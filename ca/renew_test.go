package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// renewerTestCert returns a self-signed tls.Certificate valid until the
// given notAfter. Its Leaf is populated so it can be installed in a
// TLSRenewer.
func renewerTestCert(t *testing.T, notAfter time.Time) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "renewer-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// expiredTLSRenewer builds a renewer for an already expired certificate
// without going through NewTLSRenewer (which rejects expired certificates),
// and arms its timer. With an expired certificate the timer fires
// immediately.
func expiredTLSRenewer(t *testing.T, fn RenewFunc, renewJitter time.Duration) *TLSRenewer {
	t.Helper()
	cert := renewerTestCert(t, time.Now().Add(-time.Hour))
	r := &TLSRenewer{
		RenewCertificate: fn,
		cert:             cert,
		certNotAfter:     cert.Leaf.NotAfter.Add(-time.Minute),
		renewBefore:      time.Minute,
		renewJitter:      renewJitter,
		renewTimeout:     time.Minute,
	}
	r.run(context.Background())
	t.Cleanup(func() { r.Stop() })
	return r
}

// TestTLSRenewer_Backoff verifies that the failure backoff grows
// exponentially, is capped at renewBefore and reaches a stable plateau.
func TestTLSRenewer_Backoff(t *testing.T) {
	cert := renewerTestCert(t, time.Now().Add(24*time.Hour))
	r, err := NewTLSRenewer(cert, func(context.Context) (*tls.Certificate, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// renewBefore defaults to 1/3 of the period (8h), renewJitter to 1/20
	// (72m); the first delay is therefore in [36m, 72m).
	base := r.renewJitter / 2
	delays := make([]time.Duration, 6)
	for i := range delays {
		delays[i] = r.backoff(i + 1)
	}

	expectedMin := []time.Duration{base, 2 * base, 4 * base, 8 * base, r.renewBefore, r.renewBefore}
	for i, d := range delays {
		if d <= 0 {
			t.Fatalf("backoff(%d) = %s, want a positive duration", i+1, d)
		}
		if d > r.renewBefore {
			t.Fatalf("backoff(%d) = %s exceeds cap %s", i+1, d, r.renewBefore)
		}
		if d < expectedMin[i] && d != r.renewBefore {
			t.Fatalf("backoff(%d) = %s, want at least %s", i+1, d, expectedMin[i])
		}
	}

	// Strict growth until the cap is reached, then a stable plateau.
	for i := 1; i < 4; i++ {
		if delays[i] <= delays[i-1] {
			t.Fatalf("backoff did not grow: backoff(%d)=%s backoff(%d)=%s", i, delays[i-1], i+1, delays[i])
		}
	}
	if delays[4] != r.renewBefore || delays[5] != r.renewBefore {
		t.Fatalf("backoff did not reach the cap: %s and %s, want %s", delays[4], delays[5], r.renewBefore)
	}
}

// TestTLSRenewer_RetryIntervalsEndToEnd observes a renewer whose renew
// function always fails and verifies acceptance criterion 1: consecutive
// failure intervals increase successively and are capped.
func TestTLSRenewer_RetryIntervalsEndToEnd(t *testing.T) {
	restore := setMinCertDuration(time.Second)
	defer restore()

	cert := renewerTestCert(t, time.Now().Truncate(time.Second).Add(4*time.Second))

	var mu sync.Mutex
	attempts := []time.Time{}
	fn := func(context.Context) (*tls.Certificate, error) {
		mu.Lock()
		attempts = append(attempts, time.Now())
		mu.Unlock()
		return nil, context.DeadlineExceeded
	}
	r, err := NewTLSRenewer(cert, fn)
	if err != nil {
		t.Fatal(err)
	}
	r.Run()
	defer r.Stop()

	// 1 scheduled attempt + 6 failing retries.
	deadline := time.Now().Add(20 * time.Second)
	for {
		mu.Lock()
		n := len(attempts)
		mu.Unlock()
		if n >= 7 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only got %d renewal attempts, want 7", n)
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	gaps := make([]time.Duration, 6)
	for i := range gaps {
		gaps[i] = attempts[i+1].Sub(attempts[i])
	}
	mu.Unlock()

	capWithSlack := r.renewBefore + 250*time.Millisecond
	for i, g := range gaps {
		if g > capWithSlack {
			t.Fatalf("retry interval %d = %s exceeds the cap %s", i+1, g, r.renewBefore)
		}
	}

	// Intervals grow (allow scheduling slack between adjacent stages whose
	// randomized ranges touch at the boundaries).
	for i := 1; i < 4; i++ {
		if gaps[i] < gaps[i-1]-150*time.Millisecond {
			t.Fatalf("retry intervals did not grow: gap %d = %s, gap %d = %s", i, gaps[i-1], i+1, gaps[i])
		}
	}
	if gaps[2] <= gaps[0] {
		t.Fatalf("expected exponential growth, got %s then %s", gaps[0], gaps[2])
	}

	// Once the cap is reached the interval stays on the plateau.
	if gaps[4] < r.renewBefore-250*time.Millisecond || gaps[5] < r.renewBefore-250*time.Millisecond {
		t.Fatalf("retry intervals did not reach the cap: %s and %s, want ~%s", gaps[4], gaps[5], r.renewBefore)
	}
}

// TestTLSRenewer_StopCancels verifies acceptance criterion 2 and the
// shutdown cancellation requirement: after stop (via context cancellation)
// the in-flight renewal returns promptly, its context is canceled, and no
// new renewal is started. Stop is safe to call repeatedly.
func TestTLSRenewer_StopCancels(t *testing.T) {
	restore := setMinCertDuration(time.Second)
	defer restore()

	cert := renewerTestCert(t, time.Now().Truncate(time.Second).Add(4*time.Second))

	var calls int32
	started := make(chan struct{}, 1)
	finished := make(chan struct{}, 1)
	fn := func(ctx context.Context) (*tls.Certificate, error) {
		atomic.AddInt32(&calls, 1)
		started <- struct{}{}
		<-ctx.Done()
		select {
		case finished <- struct{}{}:
		default:
		}
		return nil, ctx.Err()
	}
	r, err := NewTLSRenewer(cert, fn, WithRenewBefore(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.RunContext(ctx)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("renewal was not started")
	}

	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("in-flight renewal was not canceled when the renewer stopped")
	}

	// No new renewal attempt after the renewer is stopped.
	time.Sleep(200 * time.Millisecond)
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("got %d renewal calls after stop, want 1", n)
	}

	// Repeated stops are harmless.
	r.Stop()
	r.Stop()
}

// TestTLSRenewer_StopBeforeFire verifies that stopping before the timer is
// due prevents any renewal.
func TestTLSRenewer_StopBeforeFire(t *testing.T) {
	cert := renewerTestCert(t, time.Now().Add(2*time.Hour))

	var calls int32
	fn := func(context.Context) (*tls.Certificate, error) {
		atomic.AddInt32(&calls, 1)
		return cert, nil
	}
	r, err := NewTLSRenewer(cert, fn)
	if err != nil {
		t.Fatal(err)
	}
	r.Run()
	r.Stop()
	r.Stop()

	time.Sleep(100 * time.Millisecond)
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Fatalf("renewal was triggered after stop, got %d calls", n)
	}
}

// TestTLSRenewer_TimerAndFallbackDedup verifies acceptance criterion 3: a
// timer-triggered renewal and an expiry-fallback renewal never run
// concurrently; the fallback reuses the in-flight result instead of issuing
// a second renewal.
func TestTLSRenewer_TimerAndFallbackDedup(t *testing.T) {
	var calls int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	newCert := renewerTestCert(t, time.Now().Add(time.Hour))
	fn := func(ctx context.Context) (*tls.Certificate, error) {
		atomic.AddInt32(&calls, 1)
		started <- struct{}{}
		select {
		case <-release:
			return newCert, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// Expired certificate: the timer fires immediately.
	r := expiredTLSRenewer(t, fn, 10*time.Second)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timer renewal was not started")
	}

	// An incoming connection hits the expiry fallback while the timer
	// renewal is in flight.
	result := make(chan *tls.Certificate, 1)
	go func() {
		c, _ := r.GetCertificateForCA(nil)
		result <- c
	}()

	// Give the fallback time to join the in-flight renewal.
	time.Sleep(100 * time.Millisecond)
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("got %d renewals while timer and fallback collided, want 1", n)
	}

	close(release)

	select {
	case got := <-result:
		if got != newCert {
			t.Fatal("fallback did not reuse the in-flight renewed certificate")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fallback did not return with the in-flight result")
	}

	// The new certificate is installed and no duplicate renewal follows.
	if c, _ := r.GetCertificate(nil); c != newCert {
		t.Fatal("renewed certificate was not installed")
	}
	time.Sleep(100 * time.Millisecond)
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("got %d renewals, want 1", n)
	}
}

// TestTLSRenewer_FailureServesOldCert verifies that a failed renewal keeps
// serving the old certificate, that the backoff is honored by the fallback
// path, and that once a renewal succeeds the new certificate is served
// (acceptance criterion 4), including when the old certificate was expired.
func TestTLSRenewer_FailureServesOldCert(t *testing.T) {
	var calls int32
	newCert := renewerTestCert(t, time.Now().Add(time.Hour))
	fn := func(context.Context) (*tls.Certificate, error) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			return nil, context.DeadlineExceeded
		}
		return newCert, nil
	}
	r := expiredTLSRenewer(t, fn, 100*time.Millisecond)

	old := r.getCertificate()

	// First fallback attempt fails: the old (expired) certificate is still
	// served.
	if got := r.getCertificateForCA(); got != old {
		t.Fatal("expected the old certificate to be served after a failed renewal")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("expected the fallback to attempt a renewal, got %d calls", n)
	}

	// A second fallback before the scheduled retry must not bypass the
	// backoff (the first retry is scheduled at least 50ms out).
	if got := r.getCertificateForCA(); got != old {
		t.Fatal("expected the old certificate to be served while backing off")
	}
	time.Sleep(25 * time.Millisecond)
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("fallback bypassed the backoff: got %d renewal calls, want 1", n)
	}

	// The backoff timer keeps retrying; after the successful attempt the new
	// certificate is served to new connections.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, _ := r.GetCertificate(nil); c == newCert {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c, _ := r.GetCertificate(nil); c != newCert {
		t.Fatal("new certificate was not served after a successful renewal")
	}
	if n := atomic.LoadInt32(&calls); n != 3 {
		t.Fatalf("expected 3 renewal attempts, got %d", n)
	}
}

// TestTLSRenewer_SuccessReschedulesAndRecordsStatus verifies that after a
// successful renewal the failure counter is reset, the next attempt is
// scheduled using the new certificate's validity window, and the attempt
// state is observable.
func TestTLSRenewer_SuccessReschedulesAndRecordsStatus(t *testing.T) {
	cert := renewerTestCert(t, time.Now().Add(time.Hour))
	newCert := renewerTestCert(t, time.Now().Add(2*time.Hour))
	fn := func(context.Context) (*tls.Certificate, error) {
		return newCert, nil
	}
	r, err := NewTLSRenewer(cert, fn)
	if err != nil {
		t.Fatal(err)
	}
	r.Run()
	defer r.Stop()
	r.failures = 3

	// Simulate the timer firing.
	r.onTimer()

	if c, _ := r.GetCertificate(nil); c != newCert {
		t.Fatal("new certificate was not installed after renewal")
	}
	if r.failures != 0 {
		t.Fatalf("failure counter not reset after success: %d", r.failures)
	}
	lastAttempt, lastErr, nextRenewal := r.renewStatus()
	if lastErr != nil {
		t.Fatalf("unexpected last renewal error: %v", lastErr)
	}
	if time.Since(lastAttempt) > 5*time.Second {
		t.Fatalf("last attempt not recorded, got %s", lastAttempt)
	}
	// New cert expires in 2h, renewBefore is 40m: next renewal must be more
	// than an hour away.
	if !nextRenewal.After(time.Now().Add(time.Hour)) {
		t.Fatalf("next renewal not scheduled from the new certificate, got %s", nextRenewal)
	}
}

// TestTLSRenewer_AttemptTimeout verifies that a renewal call is bounded even
// when the renew function only reacts to context cancellation.
func TestTLSRenewer_AttemptTimeout(t *testing.T) {
	var ctxErr error
	started := make(chan struct{}, 1)
	fn := func(ctx context.Context) (*tls.Certificate, error) {
		started <- struct{}{}
		<-ctx.Done()
		ctxErr = ctx.Err()
		return nil, ctx.Err()
	}
	cert := renewerTestCert(t, time.Now().Add(-time.Hour))
	r := &TLSRenewer{
		RenewCertificate: fn,
		cert:             cert,
		certNotAfter:     cert.Leaf.NotAfter.Add(-time.Minute),
		renewBefore:      time.Hour,
		renewJitter:      time.Hour,
		renewTimeout:     50 * time.Millisecond,
	}
	r.run(context.Background())
	defer r.Stop()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("renewal was not started")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, lastErr, _ := r.renewStatus()
		if lastErr != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("renewal attempt did not finish within the timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ctxErr != context.DeadlineExceeded {
		t.Fatalf("renewal context error = %v, want %v", ctxErr, context.DeadlineExceeded)
	}
}
