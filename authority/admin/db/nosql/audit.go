package nosql

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
	nosqlDB "github.com/smallstep/nosql/database"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/admin/audit"
)

var (
	auditRecordsTable = []byte("audit_records")
	auditMetaTable    = []byte("audit_meta")

	auditSequenceKey = []byte("sequence")

	// sequenceKeyWidth is the zero padded width of a record key. A width
	// of 20 decimal digits keeps lexicographic key order identical to
	// numeric sequence order for every uint64 value.
	sequenceKeyWidth = len(fmt.Sprintf("%d", ^uint64(0)))

	// maxSequenceRetries bounds compare-and-swap retries when allocating a
	// new sequence number under contention.
	maxSequenceRetries = 100
)

// ensureAuditTables creates the audit tables on databases that predate the
// audit feature. Table creation is idempotent, so starting against an old
// database does not require a migration.
func (db *DB) ensureAuditTables() {
	db.auditTablesOnce.Do(func() {
		for _, b := range [][]byte{auditRecordsTable, auditMetaTable} {
			if err := db.db.CreateTable(b); err != nil {
				return
			}
		}
	})
}

// auditRecordKey returns the storage key for a record. Keys sort in the
// same order as the sequence numbers they encode.
func auditRecordKey(seq uint64) []byte {
	return []byte(fmt.Sprintf("%0*d", sequenceKeyWidth, seq))
}

// parseAuditRecordKey returns the sequence encoded in key. Non record keys
// (there are none in the audit_records table today, but this keeps
// ingestion resilient to future metadata entries) return ok=false.
func parseAuditRecordKey(key []byte) (uint64, bool) {
	if len(key) != sequenceKeyWidth {
		return 0, false
	}
	for _, c := range key {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	seq, err := strconv.ParseUint(string(key), 10, 64)
	if err != nil {
		return 0, false
	}
	return seq, true
}

// isRetryableConflict reports whether a database error is an optimistic
// concurrency conflict that justifies retrying the compare-and-swap.
// Badger reports "Transaction Conflict"; MySQL/Postgres can report
// deadlocks under contention. Drivers wrap these as opaque strings.
func isRetryableConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Conflict") || strings.Contains(msg, "Deadlock")
}

// retryOnConflict runs fn until it succeeds, fails with a non
// conflict error, or the attempt budget is exhausted. A true retry value
// requests another attempt.
func retryOnConflict(attempts int, fn func() (retry bool, err error)) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		retry, err := fn()
		switch {
		case err == nil && !retry:
			return nil
		case err == nil:
			// Lost a compare-and-swap race; try again.
			lastErr = errors.New("compare-and-swap lost the race")
		case retry:
			lastErr = err
		default:
			return err
		}
		// Small bounded backoff to let the competing transaction finish.
		if i < attempts-1 {
			time.Sleep(time.Duration(i+1) * 100 * time.Microsecond)
		}
	}
	return errors.Wrap(lastErr, "too many conflicts")
}

// nextSequence allocates a new monotonically increasing sequence number
// using a compare-and-swap loop. Concurrent allocators each get a unique,
// gap-free sequence number and the total order of records stays stable.
func (db *DB) nextSequence() (uint64, error) {
	var next uint64
	err := retryOnConflict(maxSequenceRetries, func() (bool, error) {
		current, err := db.db.Get(auditMetaTable, auditSequenceKey)
		if err != nil && !nosql.IsErrNotFound(err) {
			return false, errors.Wrap(err, "error reading audit sequence counter")
		}

		var seq uint64
		if len(current) > 0 {
			seq, err = strconv.ParseUint(string(current), 10, 64)
			if err != nil {
				return false, errors.Wrap(err, "error parsing audit sequence counter")
			}
		}

		candidate := strconv.AppendUint(nil, seq+1, 10)
		_, swapped, err := db.db.CmpAndSwap(auditMetaTable, auditSequenceKey, current, candidate)
		if err != nil {
			return isRetryableConflict(err), errors.Wrap(err, "error incrementing audit sequence counter")
		}
		if !swapped {
			return true, nil
		}
		next = seq + 1
		return false, nil
	})
	if err != nil {
		return 0, errors.Wrap(err, "error allocating audit sequence")
	}
	return next, nil
}

// CreateAuditRecord implements audit.Store. The record is appended with a
// freshly allocated sequence number. The compare-and-swap insert guarantees
// immutability: an existing record can never be overwritten.
func (db *DB) CreateAuditRecord(_ context.Context, rec *audit.Record) error {
	if rec == nil {
		return admin.NewError(admin.ErrorBadRequestType, "audit record cannot be nil")
	}

	db.ensureAuditTables()

	seq, err := db.nextSequence()
	if err != nil {
		return admin.WrapErrorISE(err, "error allocating audit sequence")
	}
	rec.Sequence = seq
	if rec.Time.IsZero() {
		rec.Time = clock.Now()
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return admin.WrapErrorISE(err, "error marshaling audit record")
	}

	// oldValue is nil: the insert only succeeds when the key does not
	// exist yet, so records are append-only. The transaction is retried on
	// optimistic concurrency conflicts.
	key := auditRecordKey(seq)
	return retryOnConflict(maxSequenceRetries, func() (bool, error) {
		_, swapped, err := db.db.CmpAndSwap(auditRecordsTable, key, nil, data)
		if err != nil {
			return isRetryableConflict(err), admin.WrapErrorISE(err, "error storing audit record %d", seq)
		}
		if !swapped {
			return false, admin.NewErrorISE("audit record %d already exists; refusing to overwrite", seq)
		}
		return false, nil
	})
}

// GetAuditRecords implements audit.Store. Records are returned newest
// first. Pagination is keyset based on the sequence: a cursor only returns
// records with a strictly smaller sequence, so concurrent appends at the
// head of the trail can neither skip nor duplicate an entry.
func (db *DB) GetAuditRecords(_ context.Context, cursor string, limit int) ([]*audit.Record, string, error) {
	db.ensureAuditTables()

	var cursorSeq uint64
	if cursor != "" {
		v, err := strconv.ParseUint(cursor, 10, 64)
		if err != nil {
			return nil, "", admin.NewError(admin.ErrorBadRequestType, "invalid audit cursor %q", cursor)
		}
		cursorSeq = v
	}

	switch {
	case limit <= 0:
		limit = audit.DefaultLimit
	case limit > audit.MaxLimit:
		limit = audit.MaxLimit
	}

	entries, err := db.db.List(auditRecordsTable)
	if err != nil && !nosql.IsErrNotFound(err) {
		return nil, "", errors.Wrap(err, "error listing audit records")
	}

	records := make([]*audit.Record, 0, len(entries))
	for _, entry := range entries {
		seq, ok := parseAuditRecordKey(entry.Key)
		if !ok {
			continue
		}
		if cursorSeq != 0 && seq >= cursorSeq {
			// Strictly smaller than the cursor: the record at the cursor
			// was already returned on the previous page and newly
			// appended records (larger sequences) never enter an older
			// page window.
			continue
		}
		rec, err := unmarshalAuditRecord(entry.Value, seq)
		if err != nil {
			return nil, "", err
		}
		records = append(records, rec)
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Sequence > records[j].Sequence
	})

	var nextCursor string
	if len(records) > limit {
		nextCursor = strconv.FormatUint(records[limit-1].Sequence, 10)
		records = records[:limit]
	}
	return records, nextCursor, nil
}

// unmarshalAuditRecord decodes a stored record. Records written by older
// versions may lack fields; they are normalized to "unknown" instead of
// failing the whole query. Payloads that cannot be parsed at all are
// still surfaced with their sequence and an unknown shape.
func unmarshalAuditRecord(data []byte, seq uint64) (*audit.Record, error) {
	rec := new(audit.Record)
	if err := json.Unmarshal(data, rec); err != nil {
		return &audit.Record{
			Sequence:     seq,
			Action:       audit.UnknownAction,
			ObjectType:   audit.UnknownObject,
			Result:       audit.UnknownResult,
			ActorID:      audit.Unknown,
			ActorSubject: audit.Unknown,
			ObjectID:     audit.Unknown,
		}, nil
	}
	if rec.Sequence == 0 {
		rec.Sequence = seq
	}
	rec.Normalize()
	return rec, nil
}

// PurgeAuditRecords implements audit.Store. Records older than before are
// deleted in batches; no API exists to update or delete a single record.
// It returns the number of reclaimed records.
func (db *DB) PurgeAuditRecords(_ context.Context, before time.Time) (int64, error) {
	db.ensureAuditTables()

	entries, err := db.db.List(auditRecordsTable)
	if err != nil {
		if nosql.IsErrNotFound(err) {
			return 0, nil
		}
		return 0, errors.Wrap(err, "error listing audit records for retention purge")
	}

	type expired struct {
		key  []byte
		seq  uint64
		time time.Time
	}
	var expiredRecords []expired
	for _, entry := range entries {
		seq, ok := parseAuditRecordKey(entry.Key)
		if !ok {
			continue
		}
		rec := new(audit.Record)
		if err := json.Unmarshal(entry.Value, rec); err != nil {
			// Records with a corrupted timestamp cannot be kept beyond
			// their retention window; treat them as expired.
			expiredRecords = append(expiredRecords, expired{key: entry.Key, seq: seq})
			continue
		}
		if rec.Time.IsZero() || rec.Time.Before(before) {
			expiredRecords = append(expiredRecords, expired{key: entry.Key, seq: seq, time: rec.Time})
		}
	}

	// Delete oldest first to keep reclamation deterministic.
	sort.Slice(expiredRecords, func(i, j int) bool {
		if !expiredRecords[i].time.Equal(expiredRecords[j].time) {
			return expiredRecords[i].time.Before(expiredRecords[j].time)
		}
		return expiredRecords[i].seq < expiredRecords[j].seq
	})

	var count int64
	for start := 0; start < len(expiredRecords); start += audit.PurgeBatchSize {
		end := start + audit.PurgeBatchSize
		if end > len(expiredRecords) {
			end = len(expiredRecords)
		}
		tx := new(nosqlDB.Tx)
		for _, e := range expiredRecords[start:end] {
			tx.Del(auditRecordsTable, e.key)
		}
		if err := db.db.Update(tx); err != nil {
			return count, errors.Wrapf(err, "error purging audit records %d-%d", start, end)
		}
		count += int64(end - start)
	}
	return count, nil
}
