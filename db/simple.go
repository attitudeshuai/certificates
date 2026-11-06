package db

import (
	"context"
	"crypto/x509"
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql/database"
	"golang.org/x/crypto/ssh"
)

// ErrNotImplemented is an error returned when an operation is Not Implemented.
var ErrNotImplemented = errors.Errorf("not implemented")

// SimpleDB is a barebones implementation of the DB interface. It is NOT an
// in memory implementation of the DB, but rather the bare minimum of
// functionality that the CA requires to operate securely.
type SimpleDB struct {
	usedTokens *sync.Map
}

func newSimpleDB(*Config) (*SimpleDB, error) {
	db := &SimpleDB{}
	db.usedTokens = new(sync.Map)
	return db, nil
}

// IsRevoked noop
func (s *SimpleDB) IsRevoked(string) (bool, error) {
	return false, nil
}

// IsSSHRevoked noop
func (s *SimpleDB) IsSSHRevoked(string) (bool, error) {
	return false, nil
}

// Revoke returns a "NotImplemented" error.
func (s *SimpleDB) Revoke(*RevokedCertificateInfo) error {
	return ErrNotImplemented
}

// GetRevokedCertificates returns a "NotImplemented" error.
func (s *SimpleDB) GetRevokedCertificates() (*[]RevokedCertificateInfo, error) {
	return nil, ErrNotImplemented
}

// GetCRL returns a "NotImplemented" error.
func (s *SimpleDB) GetCRL() (*CertificateRevocationListInfo, error) {
	return nil, ErrNotImplemented
}

// StoreCRL returns a "NotImplemented" error.
func (s *SimpleDB) StoreCRL(*CertificateRevocationListInfo) error {
	return ErrNotImplemented
}

// RevokeSSH returns a "NotImplemented" error.
func (s *SimpleDB) RevokeSSH(*RevokedCertificateInfo) error {
	return ErrNotImplemented
}

// GetCertificate returns a "NotImplemented" error.
func (s *SimpleDB) GetCertificate(string) (*x509.Certificate, error) {
	return nil, ErrNotImplemented
}

// StoreCertificate returns a "NotImplemented" error.
func (s *SimpleDB) StoreCertificate(*x509.Certificate) error {
	return ErrNotImplemented
}

// UseToken stores the token, along with its expiry time, the first time it is
// seen. It returns true if the token was successfully stored and false if the
// token (or another token with the same id) was already present. As the
// SimpleDB is not persisted, all the records are lost on restart and a token
// is then considered unused again.
func (s *SimpleDB) UseToken(id, tok string, expiresAt time.Time) (bool, error) {
	rec := &usedToken{
		UsedAt: time.Now().Unix(),
		Token:  tok,
	}
	if !expiresAt.IsZero() {
		rec.ExpiresAt = expiresAt.Unix()
	}
	if _, ok := s.usedTokens.LoadOrStore(id, rec); ok {
		// Token already exists in DB.
		return false, nil
	}
	// Successfully stored token.
	return true, nil
}

// RecycleExpiredUsedTokens removes at most limit used token records that
// expired before now. Records without an expiry time are never removed. As
// for the persistent backends, deletions are performed in a single bounded
// batch, oldest records first.
func (s *SimpleDB) RecycleExpiredUsedTokens(_ context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}

	cutoff := now.Unix()
	expired := make([]expiredUsedToken, 0)
	s.usedTokens.Range(func(key, value any) bool {
		rec, ok := value.(*usedToken)
		if !ok || rec.ExpiresAt == 0 || rec.ExpiresAt >= cutoff {
			// Unknown record or no known expiry or still valid: keep it.
			return true
		}
		id, _ := key.(string)
		expired = append(expired, expiredUsedToken{
			key:       []byte(id),
			expiresAt: rec.ExpiresAt,
		})
		return true
	})

	if len(expired) == 0 {
		return 0, nil
	}

	sort.SliceStable(expired, func(i, j int) bool {
		if expired[i].expiresAt != expired[j].expiresAt {
			return expired[i].expiresAt < expired[j].expiresAt
		}
		return string(expired[i].key) < string(expired[j].key)
	})
	if len(expired) > limit {
		expired = expired[:limit]
	}

	for _, e := range expired {
		// CompareAndDelete guarantees that a record replaced between the
		// listing and the deletion is not removed while still valid. Used
		// token records are never replaced in practice.
		v, ok := s.usedTokens.Load(string(e.key))
		if !ok {
			continue // already deleted
		}
		s.usedTokens.CompareAndDelete(string(e.key), v)
	}

	return len(expired), nil
}

// IsSSHHost returns a "NotImplemented" error.
func (s *SimpleDB) IsSSHHost(string) (bool, error) {
	return false, ErrNotImplemented
}

// StoreSSHCertificate returns a "NotImplemented" error.
func (s *SimpleDB) StoreSSHCertificate(*ssh.Certificate) error {
	return ErrNotImplemented
}

// GetSSHHostPrincipals returns a "NotImplemented" error.
func (s *SimpleDB) GetSSHHostPrincipals() ([]string, error) {
	return nil, ErrNotImplemented
}

// Shutdown returns nil
func (s *SimpleDB) Shutdown() error {
	return nil
}

// nosql.DB interface implementation //

// Open opens the database available with the given options.
func (s *SimpleDB) Open(string, ...database.Option) error {
	return ErrNotImplemented
}

// Close closes the current database.
func (s *SimpleDB) Close() error {
	return ErrNotImplemented
}

// Get returns the value stored in the given table/bucket and key.
func (s *SimpleDB) Get([]byte, []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Set sets the given value in the given table/bucket and key.
func (s *SimpleDB) Set([]byte, []byte, []byte) error {
	return ErrNotImplemented
}

// CmpAndSwap swaps the value at the given bucket and key if the current
// value is equivalent to the oldValue input. Returns 'true' if the
// swap was successful and 'false' otherwise.
func (s *SimpleDB) CmpAndSwap([]byte, []byte, []byte, []byte) ([]byte, bool, error) {
	return nil, false, ErrNotImplemented
}

// Del deletes the data in the given table/bucket and key.
func (s *SimpleDB) Del([]byte, []byte) error {
	return ErrNotImplemented
}

// List returns a list of all the entries in a given table/bucket.
func (s *SimpleDB) List([]byte) ([]*database.Entry, error) {
	return nil, ErrNotImplemented
}

// Update performs a transaction with multiple read-write commands.
func (s *SimpleDB) Update(*database.Tx) error {
	return ErrNotImplemented
}

// CreateTable creates a table or a bucket in the database.
func (s *SimpleDB) CreateTable([]byte) error {
	return ErrNotImplemented
}

// DeleteTable deletes a table or a bucket in the database.
func (s *SimpleDB) DeleteTable([]byte) error {
	return ErrNotImplemented
}
