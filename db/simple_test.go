package db

import (
	"context"
	"testing"
	"time"

	"github.com/smallstep/assert"
)

func TestSimpleDB(t *testing.T) {
	db, err := newSimpleDB(nil)
	assert.FatalError(t, err)

	// Revoke
	assert.Equals(t, ErrNotImplemented, db.Revoke(nil))

	// IsRevoked -- verify noop
	isRevoked, err := db.IsRevoked("foo")
	assert.False(t, isRevoked)
	assert.Nil(t, err)

	// StoreCertificate
	assert.Equals(t, ErrNotImplemented, db.StoreCertificate(nil))

	// UseToken
	expiresAt := time.Now().Add(time.Hour)
	ok, err := db.UseToken("foo", "bar", expiresAt)
	assert.True(t, ok)
	assert.Nil(t, err)
	ok, err = db.UseToken("foo", "cat", expiresAt)
	assert.False(t, ok)
	assert.Nil(t, err)

	// Shutdown -- verify noop
	assert.FatalError(t, db.Shutdown())
	ok, err = db.UseToken("foo", "cat", expiresAt)
	assert.False(t, ok)
	assert.Nil(t, err)
}

func TestSimpleDB_RecycleExpiredUsedTokens(t *testing.T) {
	sdb, err := newSimpleDB(nil)
	assert.FatalError(t, err)

	now := time.Now()
	// One expired record, one still valid record and one without expiry.
	ok, err := sdb.UseToken("expired", "tok1", now.Add(-time.Hour))
	assert.True(t, ok)
	assert.Nil(t, err)
	ok, err = sdb.UseToken("valid", "tok2", now.Add(time.Hour))
	assert.True(t, ok)
	assert.Nil(t, err)
	ok, err = sdb.UseToken("no-expiry", "tok3", time.Time{})
	assert.True(t, ok)
	assert.Nil(t, err)

	// Only the expired record is removed.
	n, err := sdb.RecycleExpiredUsedTokens(context.Background(), now, 10)
	assert.Equals(t, 1, n)
	assert.Nil(t, err)

	// The expired record was deleted and the id can be stored again; the
	// unexpired and no-expiry records are still blocking reuse.
	ok, err = sdb.UseToken("expired", "tok1", now.Add(-time.Hour))
	assert.True(t, ok)
	assert.Nil(t, err)
	ok, err = sdb.UseToken("valid", "tok2", now.Add(time.Hour))
	assert.False(t, ok)
	assert.Nil(t, err)
	ok, err = sdb.UseToken("no-expiry", "tok3", time.Time{})
	assert.False(t, ok)
	assert.Nil(t, err)

	// The re-stored record is expired again, so it is removed on the next run;
	// records without expiry are always kept.
	n, err = sdb.RecycleExpiredUsedTokens(context.Background(), now, 10)
	assert.Equals(t, 1, n)
	assert.Nil(t, err)
	n, err = sdb.RecycleExpiredUsedTokens(context.Background(), now, 10)
	assert.Equals(t, 0, n)
	assert.Nil(t, err)
	n, err = sdb.RecycleExpiredUsedTokens(context.Background(), now, 0)
	assert.Equals(t, 0, n)
	assert.Nil(t, err)
}

func TestSimpleDB_RecycleExpiredUsedTokensBatch(t *testing.T) {
	sdb, err := newSimpleDB(nil)
	assert.FatalError(t, err)

	now := time.Now()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		ok, err := sdb.UseToken(id, "tok", now.Add(-time.Hour))
		assert.True(t, ok)
		assert.Nil(t, err)
	}

	// A single run never removes more than the batch size.
	n, err := sdb.RecycleExpiredUsedTokens(context.Background(), now, 2)
	assert.Equals(t, 2, n)
	assert.Nil(t, err)

	n, err = sdb.RecycleExpiredUsedTokens(context.Background(), now, 10)
	assert.Equals(t, 3, n)
	assert.Nil(t, err)
}
