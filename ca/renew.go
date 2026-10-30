package ca

import (
	"context"
	"crypto/tls"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/singleflight"
)

// RenewFunc defines the type of the functions used to get a new tls
// certificate. The context is canceled when the renewer is stopped or when
// the per-attempt timeout elapses; implementations must return once the
// context is canceled so that shutdowns are not blocked by an in-flight
// renewal.
type RenewFunc func(ctx context.Context) (*tls.Certificate, error)

var (
	minCertDuration = time.Minute

	// defaultRenewTimeout bounds a single renewal attempt. The context passed
	// to the RenewFunc is canceled when the timeout elapses or when the
	// renewer is stopped, whichever happens first.
	defaultRenewTimeout = time.Minute
)

// renewFlightKey is the singleflight key used to coalesce concurrent
// renewal attempts of the renewer's certificate.
const renewFlightKey = "tls-certificate"

// TLSRenewer automatically renews a tls certificate using a RenewFunc.
type TLSRenewer struct {
	mu               sync.RWMutex
	renewing         singleflight.Group
	RenewCertificate RenewFunc
	cert             *tls.Certificate
	timer            *time.Timer
	renewBefore      time.Duration
	renewJitter      time.Duration
	renewTimeout     time.Duration
	certNotAfter     time.Time

	// failures is the number of consecutive failed renewal attempts. It is
	// reset to zero on a successful renewal.
	failures int
	// lastAttempt is the time at which the last renewal attempt started.
	lastAttempt time.Time
	// lastError is the error of the last renewal attempt. It is nil if the
	// last attempt succeeded.
	lastError error
	// nextRenewal is the time at which the next renewal attempt is planned.
	nextRenewal time.Time

	ctx     context.Context
	cancel  context.CancelFunc
	started bool
	stopped bool
}

type tlsRenewerOptions func(r *TLSRenewer) error

// WithRenewBefore modifies a tlsRenewer by setting the renewBefore attribute.
func WithRenewBefore(b time.Duration) func(r *TLSRenewer) error {
	return func(r *TLSRenewer) error {
		r.renewBefore = b
		return nil
	}
}

// WithRenewJitter modifies a tlsRenewer by setting the renewJitter attribute.
func WithRenewJitter(j time.Duration) func(r *TLSRenewer) error {
	return func(r *TLSRenewer) error {
		r.renewJitter = j
		return nil
	}
}

// NewTLSRenewer creates a TLSRenewer for the given cert. It will use the given
// RenewFunc to get a new certificate when required.
func NewTLSRenewer(cert *tls.Certificate, fn RenewFunc, opts ...tlsRenewerOptions) (*TLSRenewer, error) {
	r := &TLSRenewer{
		RenewCertificate: fn,
		cert:             cert,
		certNotAfter:     cert.Leaf.NotAfter.Add(-1 * time.Minute),
		renewTimeout:     defaultRenewTimeout,
	}

	for _, f := range opts {
		if err := f(r); err != nil {
			return nil, errors.Wrap(err, "error applying options")
		}
	}

	// Use the current time to calculate the initial period. Using a notBefore
	// in the past might set a renewBefore too large, causing continuous
	// renewals due to the negative values in nextRenewDuration.
	period := cert.Leaf.NotAfter.Sub(time.Now().Truncate(time.Second))
	if period < minCertDuration {
		return nil, errors.Errorf("period must be greater than or equal to %s, but got %v.", minCertDuration, period)
	}
	// By default we will try to renew the cert before 2/3 of the validity
	// period have expired.
	if r.renewBefore == 0 {
		r.renewBefore = period / 3
	}
	// By default we set the jitter to 1/20th of the validity period.
	if r.renewJitter == 0 {
		r.renewJitter = period / 20
	}

	return r, nil
}

// Run starts the certificate renewer for the given certificate.
func (r *TLSRenewer) Run() {
	r.run(context.Background())
}

// RunContext starts the certificate renewer for the given certificate. The
// renewer is stopped when the given context is canceled.
func (r *TLSRenewer) RunContext(ctx context.Context) {
	r.run(ctx)
	go func() {
		<-ctx.Done()
		r.Stop()
	}()
}

// Stop prevents the renew timer from firing, cancels any in-flight renewal
// and prevents new renewal attempts from being started by this renewer. It is
// safe to call Stop multiple times.
func (r *TLSRenewer) Stop() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return false
	}
	r.stopped = true
	if r.cancel != nil {
		r.cancel()
	}
	if r.timer == nil {
		return true
	}
	return r.timer.Stop()
}

// GetCertificate returns the current server certificate.
//
// This method is set in the tls.Config GetCertificate property.
func (r *TLSRenewer) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.getCertificate(), nil
}

// GetCertificateForCA returns the current server certificate. It can only be
// used if the renew function creates the new certificate and do not uses a TLS
// request. It's intended to be use by the certificate authority server.
//
// This method is set in the tls.Config GetCertificate property.
func (r *TLSRenewer) GetCertificateForCA(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.getCertificateForCA(), nil
}

// GetClientCertificate returns the current client certificate.
//
// This method is set in the tls.Config GetClientCertificate property.
func (r *TLSRenewer) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.getCertificate(), nil
}

// getCertificate returns the certificate using a read-only lock.
//
// Known issue: It cannot renew an expired certificate because the /renew
// endpoint requires a valid client certificate. The certificate can expire
// if the timer does not fire e.g. when the CA is run from a laptop that
// enters sleep mode.
func (r *TLSRenewer) getCertificate() *tls.Certificate {
	r.mu.RLock()
	cert := r.cert
	r.mu.RUnlock()
	return cert
}

// getCertificateForCA returns the certificate using a read-only lock. It will
// automatically renew the certificate if it has expired.
func (r *TLSRenewer) getCertificateForCA() *tls.Certificate {
	r.mu.RLock()
	cert := r.cert
	started := r.started
	// Force certificate renewal if the timer didn't run.
	// This is an special case that can happen after a computer sleep.
	expired := time.Now().After(r.certNotAfter)
	// Do not trigger a new attempt before the next scheduled one; this keeps
	// the exponential backoff effective even when new connections keep
	// arriving after the certificate expired.
	due := r.nextRenewal.IsZero() || time.Now().After(r.nextRenewal)
	stopped := r.stopped
	r.mu.RUnlock()

	if started && !stopped && expired && due {
		// The timer and the expiry fallback never renew the same certificate
		// concurrently: concurrent triggers share the in-flight renewal and
		// reuse its result.
		if newCert, err := r.renewOnce(); err == nil && newCert != nil {
			return newCert
		}
		// On failure keep serving the previous certificate; it will be
		// retried either by the backoff timer or by the fallback on the next
		// connection after the scheduled attempt.
	}
	return cert
}

// run arms the renewal timer. It is a no-op if the renewer was already
// started or stopped.
func (r *TLSRenewer) run(parent context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.stopped {
		return
	}
	r.started = true
	r.ctx, r.cancel = context.WithCancel(parent)

	next := r.nextRenewDuration(r.cert.Leaf.NotAfter)
	r.timer = time.AfterFunc(next, r.onTimer)
	r.nextRenewal = time.Now().Add(next)
}

// onTimer is the timer callback.
func (r *TLSRenewer) onTimer() {
	r.mu.RLock()
	stopped := r.stopped
	r.mu.RUnlock()
	if stopped {
		return
	}
	_, _, _ = r.renewing.Do(renewFlightKey, func() (any, error) {
		return r.renew()
	})
}

// renewOnce triggers a renewal, coalescing with any in-flight renewal (timer
// or expiry fallback) and reusing its result.
func (r *TLSRenewer) renewOnce() (*tls.Certificate, error) {
	v, err, _ := r.renewing.Do(renewFlightKey, func() (any, error) {
		return r.renew()
	})
	if err != nil {
		return nil, err
	}
	cert, _ := v.(*tls.Certificate)
	return cert, nil
}

// renew performs a single renewal attempt. On failure the old certificate is
// kept and the timer is rearmed with an exponential backoff; on success the
// new certificate is installed and the timer is rearmed using the same
// schedule as before. Nothing is rescheduled if the renewer was stopped.
func (r *TLSRenewer) renew() (*tls.Certificate, error) {
	r.mu.Lock()
	if r.stopped {
		cert := r.cert
		r.mu.Unlock()
		return cert, nil
	}
	fn := r.RenewCertificate
	r.lastAttempt = time.Now()
	r.mu.Unlock()

	if fn == nil {
		err := errors.New("renew function is not configured")
		return r.finishRenewal(nil, err)
	}

	// Bound the attempt: stopping the renewer cancels r.ctx, and the timeout
	// protects against renew functions that do not honor the cancellation.
	renewCtx := r.ctx
	if renewCtx == nil {
		renewCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(renewCtx, r.renewTimeout)
	defer cancel()

	cert, err := fn(ctx)
	return r.finishRenewal(cert, err)
}

// finishRenewal records the attempt result, installs the new certificate on
// success and rearms the timer. It must not be called while the singleflight
// shared attempt is not finished.
func (r *TLSRenewer) finishRenewal(cert *tls.Certificate, err error) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// The renewer was stopped while the attempt was in flight: do not
	// install the certificate nor reschedule the timer and do not start a
	// new attempt.
	if r.stopped {
		return cert, err
	}

	if err == nil && cert == nil {
		err = errors.New("renew function returned a nil certificate")
	}
	if err != nil {
		r.failures++
		r.lastError = err
		next := r.backoff(r.failures)
		r.scheduleLocked(next)
		log.Printf("error renewing TLS certificate: %v; retry scheduled in %s", err, next)
		return nil, err
	}

	r.failures = 0
	r.lastError = nil
	r.setCertificateLocked(cert)
	next := r.nextRenewDuration(cert.Leaf.NotAfter)
	r.scheduleLocked(next)
	log.Printf("TLS certificate renewed; next renewal scheduled in %s", next)
	return cert, nil
}

// scheduleLocked rearms the timer and records the next planned attempt. The
// caller must hold r.mu.
func (r *TLSRenewer) scheduleLocked(next time.Duration) {
	if r.timer != nil {
		r.timer.Reset(next)
	}
	r.nextRenewal = time.Now().Add(next)
}

// setCertificateLocked updates the certificate and its expiry threshold. It
// also updates certNotAfter with 1m of delta; this will force the renewal of
// the certificate if it is about to expire. The caller must hold r.mu.
func (r *TLSRenewer) setCertificateLocked(cert *tls.Certificate) {
	r.cert = cert
	r.certNotAfter = cert.Leaf.NotAfter.Add(-1 * time.Minute)
}

func (r *TLSRenewer) nextRenewDuration(notAfter time.Time) time.Duration {
	d := time.Until(notAfter).Truncate(time.Second) - r.renewBefore
	n := mathRandInt63n(int64(r.renewJitter))
	d -= time.Duration(n)
	if d < 0 {
		d = 0
	}
	return d
}

// backoff returns the delay before the next renewal attempt after the given
// number of consecutive failures. The delay grows exponentially, doubling
// after every failure, and is capped at renewBefore. The first delay keeps
// the previous fixed-interval behavior, uniformly distributed in
// [renewJitter/2, renewJitter); once the cap is reached the delay stays at
// the cap. A successful renewal resets the failure counter.
func (r *TLSRenewer) backoff(failures int) time.Duration {
	base := r.renewJitter / 2
	for i := 1; i < failures; i++ {
		if base >= r.renewBefore/2 {
			base = r.renewBefore
			break
		}
		base *= 2
	}
	d := base + time.Duration(mathRandInt63n(int64(base)+1))
	if d > r.renewBefore {
		d = r.renewBefore
	}
	return d
}

// renewStatus reports the time of the last attempt, its error and the time of
// the next planned attempt. lastErr is nil if the last attempt succeeded.
func (r *TLSRenewer) renewStatus() (lastAttempt time.Time, lastErr error, nextRenewal time.Time) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastAttempt, r.lastError, r.nextRenewal
}

//nolint:gosec // not used for cryptographic security
func mathRandInt63n(n int64) int64 {
	return rand.Int63n(n)
}
