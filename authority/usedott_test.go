package authority

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"go.step.sm/crypto/jose"
)

// recyclerMockDB is a MockAuthDB that also implements db.UsedTokenRecycler.
type recyclerMockDB struct {
	*db.MockAuthDB

	mu       sync.Mutex
	calls    int
	failWith error
}

func (d *recyclerMockDB) RecycleExpiredUsedTokens(_ context.Context, _ time.Time, _ int) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.failWith != nil {
		return 0, d.failWith
	}
	return 0, nil
}

func (d *recyclerMockDB) callsCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func testSignedToken(t *testing.T, claims jose.Claims) string {
	t.Helper()
	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)
	raw, err := jose.Signed(sig).Claims(claims).CompactSerialize()
	assert.FatalError(t, err)
	return raw
}

// The expiry claim of the token is stored alongside the used token record so
// that it can be reclaimed once the token cannot be used anymore.
func TestAuthority_authorizeTokenForwardsExpiry(t *testing.T) {
	var (
		gotID   string
		gotTok  string
		gotExp  time.Time
		forward bool
	)
	a := testAuthority(t)
	a.db = &db.MockAuthDB{
		MUseToken: func(id, tok string, expiresAt time.Time) (bool, error) {
			gotID, gotTok, gotExp, forward = id, tok, expiresAt, true
			return true, nil
		},
	}

	now := time.Now().UTC()
	exp := now.Add(time.Minute)
	token := testSignedToken(t, jose.Claims{
		Subject:   "test.smallstep.com",
		Issuer:    "step-cli",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(exp),
		Audience:  []string{"https://example.com/revoke"},
		ID:        "43",
	})

	_, err := a.authorizeToken(context.Background(), token)
	assert.FatalError(t, err)
	assert.True(t, forward)
	assert.Equals(t, "43", gotID)
	assert.Equals(t, token, gotTok)
	assert.Equals(t, exp.Unix(), gotExp.Unix())
}

// A token without an expiry claim forwards the zero time; the record is then
// retained indefinitely.
func TestAuthority_authorizeTokenWithoutExpiry(t *testing.T) {
	var gotExp time.Time
	a := testAuthority(t)
	a.db = &db.MockAuthDB{
		MUseToken: func(id, tok string, expiresAt time.Time) (bool, error) {
			gotExp = expiresAt
			return true, nil
		},
	}

	now := time.Now().UTC()
	token := testSignedToken(t, jose.Claims{
		Subject:   "test.smallstep.com",
		Issuer:    "step-cli",
		NotBefore: jose.NewNumericDate(now),
		Audience:  []string{"https://example.com/revoke"},
		ID:        "43",
	})

	_, err := a.authorizeToken(context.Background(), token)
	assert.FatalError(t, err)
	assert.True(t, gotExp.IsZero())
}

// Reuse within the validity period is still rejected with the same error and
// status code, and storage errors still surface as internal server errors.
func TestAuthorityUseTokenErrorsUnchanged(t *testing.T) {
	now := time.Now().UTC()
	token := testSignedToken(t, jose.Claims{
		Subject:   "test.smallstep.com",
		Issuer:    "step-cli",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
		Audience:  []string{"https://example.com/revoke"},
		ID:        "43",
	})
	p, ok := testAuthority(t).provisioners.Load("JWK/step-cli")
	assert.Fatal(t, ok, "step-cli provisioner not found in test authority")

	t.Run("already-used", func(t *testing.T) {
		a := testAuthority(t)
		a.db = &db.MockAuthDB{
			MUseToken: func(id, tok string, expiresAt time.Time) (bool, error) {
				return false, nil
			},
		}
		err := a.UseToken(context.Background(), token, p, now.Add(time.Minute))
		assert.NotNil(t, err)
		assert.HasPrefix(t, "token already used", err.Error())
		sc := mustStatusCode(t, err)
		assert.Equals(t, 401, sc)
	})

	t.Run("storage-error", func(t *testing.T) {
		a := testAuthority(t)
		a.db = &db.MockAuthDB{
			MUseToken: func(id, tok string, expiresAt time.Time) (bool, error) {
				return false, errors.New("force")
			},
		}
		err := a.UseToken(context.Background(), token, p, now.Add(time.Minute))
		assert.NotNil(t, err)
		assert.HasPrefix(t, "failed when attempting to store token: force", err.Error())
		sc := mustStatusCode(t, err)
		assert.Equals(t, 500, sc)
	})
}

func mustStatusCode(t *testing.T, err error) int {
	t.Helper()
	var sc interface{ StatusCode() int }
	assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError")
	return sc.StatusCode()
}

func TestAuthority_startUsedOTTRecycler(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		a := testAuthority(t)
		a.startUsedOTTRecycler()
		assert.Nil(t, a.usedOTTTicker)
	})

	t.Run("db-without-recycler", func(t *testing.T) {
		a := testAuthority(t)
		a.db = &db.MockAuthDB{}
		a.config.UsedOTT = &config.UsedOTTConfig{Enabled: true}
		a.startUsedOTTRecycler()
		assert.Nil(t, a.usedOTTTicker)
	})

	t.Run("enabled", func(t *testing.T) {
		a := testAuthority(t)
		r := &recyclerMockDB{MockAuthDB: &db.MockAuthDB{}}
		a.db = r
		a.config.UsedOTT = &config.UsedOTTConfig{
			Enabled:   true,
			Interval:  &provisioner.Duration{Duration: 25 * time.Millisecond},
			BatchSize: 7,
		}

		a.startUsedOTTRecycler()
		assert.NotNil(t, a.usedOTTTicker)

		// The first run happens at startup and subsequent runs follow the
		// configured interval.
		assert.Fatal(t, waitFor(func() bool { return r.callsCount() >= 3 }, time.Second),
			"recycler did not run periodically")

		a.stopUsedOTTRecycler()
		assert.Nil(t, a.usedOTTTicker)
		// Stopping twice must be safe.
		a.stopUsedOTTRecycler()
	})
}

// A failing reclamation only affects the reclamation: it is retried and token
// issuance keeps working.
func TestAuthority_recyclerFailureDoesNotAffectIssuance(t *testing.T) {
	a := testAuthority(t)
	r := &recyclerMockDB{
		MockAuthDB: &db.MockAuthDB{
			MUseToken: func(id, tok string, expiresAt time.Time) (bool, error) {
				return true, nil
			},
		},
		failWith: errors.New("force"),
	}
	a.db = r
	a.config.UsedOTT = &config.UsedOTTConfig{
		Enabled:  true,
		Interval: &provisioner.Duration{Duration: 25 * time.Millisecond},
	}

	a.startUsedOTTRecycler()
	t.Cleanup(a.stopUsedOTTRecycler)

	// The failing run is retried instead of stopping the loop.
	assert.Fatal(t, waitFor(func() bool { return r.callsCount() >= 3 }, time.Second),
		"failing recycler was not retried")

	// Token issuance is independent from the reclamation and still succeeds.
	now := time.Now().UTC()
	token := testSignedToken(t, jose.Claims{
		Subject:   "test.smallstep.com",
		Issuer:    "step-cli",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
		Audience:  []string{"https://example.com/revoke"},
		ID:        "recycle-fail-id",
	})
	_, err := a.authorizeToken(context.Background(), token)
	assert.Nil(t, err)
}

func waitFor(cond func() bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return errors.New("condition not met before timeout")
}
