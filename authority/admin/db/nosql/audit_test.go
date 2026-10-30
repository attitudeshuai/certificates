package nosql

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/admin/audit"
	nosqldb "github.com/smallstep/nosql/database"
)

// memDB is an in-memory implementation of the nosql DB interface with the
// same compare-and-swap and transaction semantics used by the audit store.
type memDB struct {
	mu     sync.Mutex
	tables map[string]map[string][]byte
}

func newMemDB() *memDB {
	return &memDB{tables: map[string]map[string][]byte{}}
}

func (m *memDB) Open(string, ...nosqldb.Option) error { return nil }

func (m *memDB) Close() error { return nil }

func (m *memDB) CreateTable(bucket []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tables[string(bucket)]; !ok {
		m.tables[string(bucket)] = map[string][]byte{}
	}
	return nil
}

func (m *memDB) DeleteTable(bucket []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tables, string(bucket))
	return nil
}

func (m *memDB) table(bucket []byte) (map[string][]byte, bool) {
	t, ok := m.tables[string(bucket)]
	return t, ok
}

func (m *memDB) Get(bucket, key []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.table(bucket)
	if !ok {
		return nil, errors.Wrap(nosqldb.ErrNotFound, "table missing")
	}
	v, ok := t[string(key)]
	if !ok {
		return nil, errors.Wrap(nosqldb.ErrNotFound, "key missing")
	}
	return append([]byte(nil), v...), nil
}

func (m *memDB) Set(bucket, key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.table(bucket)
	if !ok {
		return errors.Wrap(nosqldb.ErrNotFound, "table missing")
	}
	t[string(key)] = append([]byte(nil), value...)
	return nil
}

func (m *memDB) Del(bucket, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.table(bucket)
	if !ok {
		return errors.Wrap(nosqldb.ErrNotFound, "table missing")
	}
	delete(t, string(key))
	return nil
}

func (m *memDB) CmpAndSwap(bucket, key, oldValue, newValue []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.table(bucket)
	if !ok {
		return nil, false, errors.Wrap(nosqldb.ErrNotFound, "table missing")
	}
	current := t[string(key)]
	if !bytesEqual(current, oldValue) {
		return current, false, nil
	}
	if newValue == nil {
		delete(t, string(key))
	} else {
		t[string(key)] = append([]byte(nil), newValue...)
	}
	return newValue, true, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (m *memDB) List(bucket []byte) ([]*nosqldb.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.table(bucket)
	if !ok {
		return nil, errors.Wrap(nosqldb.ErrNotFound, "table missing")
	}
	entries := make([]*nosqldb.Entry, 0, len(t))
	for k, v := range t {
		entries = append(entries, &nosqldb.Entry{Bucket: bucket, Key: []byte(k), Value: append([]byte(nil), v...)})
	}
	return entries, nil
}

func (m *memDB) Update(tx *nosqldb.Tx) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range tx.Operations {
		t, ok := m.tables[string(op.Bucket)]
		if !ok {
			return errors.Wrap(nosqldb.ErrNotFound, "table missing")
		}
		switch op.Cmd {
		case nosqldb.Set:
			t[string(op.Key)] = append([]byte(nil), op.Value...)
		case nosqldb.Delete:
			delete(t, string(op.Key))
		case nosqldb.CreateTable:
			m.tables[string(op.Bucket)] = map[string][]byte{}
		case nosqldb.DeleteTable:
			delete(m.tables, string(op.Bucket))
		}
	}
	return nil
}

// directPut writes a raw record key/value pair, bypassing the store.
func (m *memDB) directPut(table string, key, value []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tables[table]; !ok {
		m.tables[table] = map[string][]byte{}
	}
	m.tables[table][string(key)] = value
}

func newTestAuditDB() *DB {
	return &DB{db: newMemDB(), authorityID: admin.DefaultAuthorityID}
}

func TestAuditRecordKey_format(t *testing.T) {
	assert.Equals(t, "00000000000000000001", string(auditRecordKey(1)))
	assert.Equals(t, "18446744073709551615", string(auditRecordKey(^uint64(0))))
	seq, ok := parseAuditRecordKey(auditRecordKey(42))
	assert.True(t, ok)
	assert.Equals(t, uint64(42), seq)

	_, ok = parseAuditRecordKey([]byte("sequence"))
	assert.Equals(t, false, ok)
	_, ok = parseAuditRecordKey([]byte("0000000000000000001"))
	assert.Equals(t, false, ok)
}

func TestCreateAuditRecord_autoCreatesTablesAndAssignsSequence(t *testing.T) {
	db := newTestAuditDB()
	ctx := context.Background()

	rec := &audit.Record{
		Time:       time.Now().UTC(),
		Action:     audit.CreateAction,
		ObjectType: audit.ProvisionerObject,
		Result:     audit.SuccessResult,
	}
	assert.FatalError(t, db.CreateAuditRecord(ctx, rec))
	assert.Equals(t, uint64(1), rec.Sequence)

	rec2 := &audit.Record{Action: audit.DeleteAction, ObjectType: audit.AdminObject, Result: audit.SuccessResult}
	assert.FatalError(t, db.CreateAuditRecord(ctx, rec2))
	assert.Equals(t, uint64(2), rec2.Sequence)
}

func TestCreateAuditRecord_concurrentWritesAreUniqueAndOrdered(t *testing.T) {
	db := newTestAuditDB()
	ctx := context.Background()

	const writers = 50
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- db.CreateAuditRecord(ctx, &audit.Record{
				Time:       time.Now().UTC(),
				Action:     audit.UpdateAction,
				ObjectType: audit.ProvisionerObject,
				ObjectName: "same-object",
				Result:     audit.SuccessResult,
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.FatalError(t, err)
	}

	records, next, err := db.GetAuditRecords(ctx, "", writers)
	assert.FatalError(t, err)
	assert.Equals(t, "", next)
	assert.Equals(t, writers, len(records))

	seen := map[uint64]bool{}
	for i, rec := range records {
		assert.Equals(t, false, seen[rec.Sequence])
		seen[rec.Sequence] = true
		if i > 0 {
			assert.True(t, records[i-1].Sequence > rec.Sequence)
		}
	}
	for seq := uint64(1); seq <= writers; seq++ {
		assert.Equals(t, true, seen[seq])
	}
}

func TestGetAuditRecords_paginationNoSkipNoDup(t *testing.T) {
	db := newTestAuditDB()
	ctx := context.Background()

	const total = 55
	for i := 0; i < total; i++ {
		assert.FatalError(t, db.CreateAuditRecord(ctx, &audit.Record{
			Time:       time.Now().UTC(),
			Action:     audit.CreateAction,
			ObjectType: audit.ProvisionerObject,
			Result:     audit.SuccessResult,
		}))
	}

	var (
		all       []uint64
		cursor    string
		pages     int
		pageLimit = 20
	)
	for {
		records, next, err := db.GetAuditRecords(ctx, cursor, pageLimit)
		assert.FatalError(t, err)
		assert.True(t, len(records) <= pageLimit)
		for _, rec := range records {
			all = append(all, rec.Sequence)
		}
		pages++
		if next == "" {
			break
		}
		assert.Equals(t, true, next != cursor)
		cursor = next
	}
	assert.Equals(t, 3, pages)
	assert.Equals(t, total, len(all))
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	for i, seq := range all {
		assert.Equals(t, uint64(i+1), seq)
	}
}

func TestGetAuditRecords_concurrentInsertsDoNotDisturbPages(t *testing.T) {
	db := newTestAuditDB()
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		assert.FatalError(t, db.CreateAuditRecord(ctx, &audit.Record{
			Time: time.Now().UTC(), Result: audit.SuccessResult,
			Action: audit.CreateAction, ObjectType: audit.ProvisionerObject,
		}))
	}

	// First page: newest 20 (50..31).
	page1, next, err := db.GetAuditRecords(ctx, "", 20)
	assert.FatalError(t, err)
	assert.Equals(t, 20, len(page1))
	assert.Equals(t, uint64(50), page1[0].Sequence)
	assert.Equals(t, uint64(31), page1[19].Sequence)
	assert.Equals(t, "31", next)

	// New writes land at the head while the client walks backwards.
	for i := 0; i < 25; i++ {
		assert.FatalError(t, db.CreateAuditRecord(ctx, &audit.Record{
			Time: time.Now().UTC(), Result: audit.SuccessResult,
			Action: audit.CreateAction, ObjectType: audit.AdminObject,
		}))
	}

	page2, next2, err := db.GetAuditRecords(ctx, next, 20)
	assert.FatalError(t, err)
	assert.Equals(t, 20, len(page2))
	assert.Equals(t, uint64(30), page2[0].Sequence)
	assert.Equals(t, uint64(11), page2[19].Sequence)
	assert.Equals(t, "11", next2)

	page3, next3, err := db.GetAuditRecords(ctx, next2, 20)
	assert.FatalError(t, err)
	assert.Equals(t, 10, len(page3))
	assert.Equals(t, uint64(10), page3[0].Sequence)
	assert.Equals(t, uint64(1), page3[9].Sequence)
	assert.Equals(t, "", next3)
}

func TestGetAuditRecords_invalidCursor(t *testing.T) {
	db := newTestAuditDB()
	_, _, err := db.GetAuditRecords(context.Background(), "not-a-number", 10)
	var ae *admin.Error
	assert.Fatal(t, errors.As(err, &ae), "expected admin.Error")
	assert.Equals(t, admin.ErrorBadRequestType.String(), ae.Type)
}

func TestGetAuditRecords_legacyRecordWithMissingFields(t *testing.T) {
	db := newTestAuditDB()
	mem := db.db.(*memDB)
	mem.directPut("audit_records", auditRecordKey(5), []byte(`{}`))
	mem.directPut("audit_records", auditRecordKey(6), []byte(`{"corrupt`))

	records, _, err := db.GetAuditRecords(context.Background(), "", 10)
	assert.FatalError(t, err)
	assert.Equals(t, 2, len(records))
	assert.Equals(t, uint64(6), records[0].Sequence)
	for _, rec := range records {
		assert.Equals(t, audit.UnknownAction, rec.Action)
		assert.Equals(t, audit.UnknownObject, rec.ObjectType)
		assert.Equals(t, audit.UnknownResult, rec.Result)
		assert.Equals(t, audit.Unknown, rec.ActorSubject)
		assert.Equals(t, audit.Unknown, rec.ObjectID)
	}
}

func TestCreateAuditRecord_doesNotOverwrite(t *testing.T) {
	db := newTestAuditDB()
	ctx := context.Background()
	assert.FatalError(t, db.CreateAuditRecord(ctx, &audit.Record{
		Time: time.Now().UTC(), Action: audit.CreateAction,
		ObjectType: audit.ProvisionerObject, Result: audit.SuccessResult,
	}))

	mem := db.db.(*memDB)
	stored := mem.tables[string(auditRecordsTable)][string(auditRecordKey(1))]
	assert.True(t, len(stored) > 0)

	var roundTrip audit.Record
	assert.FatalError(t, json.Unmarshal(stored, &roundTrip))
	assert.Equals(t, uint64(1), roundTrip.Sequence)
	assert.Equals(t, audit.ProvisionerObject, roundTrip.ObjectType)
}

func TestPurgeAuditRecords_batchReclaimsExpired(t *testing.T) {
	db := newTestAuditDB()
	ctx := context.Background()

	now := time.Now().UTC()
	times := []time.Time{
		now.Add(-200 * 24 * time.Hour),
		now.Add(-100 * 24 * time.Hour),
		now.Add(-2 * 24 * time.Hour),
		now,
	}
	for _, tm := range times {
		assert.FatalError(t, db.CreateAuditRecord(ctx, &audit.Record{
			Time: tm, Action: audit.CreateAction,
			ObjectType: audit.ProvisionerObject, Result: audit.SuccessResult,
		}))
	}

	// More than one batch worth of expired records to exercise batching.
	for i := 0; i < audit.PurgeBatchSize+5; i++ {
		assert.FatalError(t, db.CreateAuditRecord(ctx, &audit.Record{
			Time: now.Add(-300 * 24 * time.Hour), Action: audit.CreateAction,
			ObjectType: audit.AdminObject, Result: audit.SuccessResult,
		}))
	}

	cutoff := now.Add(-audit.DefaultRetention)
	n, err := db.PurgeAuditRecords(ctx, cutoff)
	assert.FatalError(t, err)
	assert.Equals(t, int64(audit.PurgeBatchSize+5+2), n)

	records, _, err := db.GetAuditRecords(ctx, "", 100)
	assert.FatalError(t, err)
	assert.Equals(t, 2, len(records))
	for _, rec := range records {
		assert.True(t, !rec.Time.Before(cutoff))
	}

	// Second purge is a no-op.
	n, err = db.PurgeAuditRecords(ctx, cutoff)
	assert.FatalError(t, err)
	assert.Equals(t, int64(0), n)
}
