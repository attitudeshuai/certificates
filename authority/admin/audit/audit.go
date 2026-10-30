// Package audit provides an append-only audit trail for administrative
// write operations. Every mutating request performed through the
// Administration API results in a single immutable Record describing the
// actor, action, object, time, outcome and a redacted before/after diff
// summary.
//
// Records can only be created (appended) and read. They cannot be modified
// or deleted individually; records older than the configured retention
// period are reclaimed in batches by PurgeAuditRecords.
package audit

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Unknown is the placeholder shown for data that is absent, for example
// when a record was written by an older version that did not populate a
// field yet.
const Unknown = "unknown"

// Action describes what kind of write operation was attempted.
type Action string

const (
	// CreateAction is the action that creates a new object.
	CreateAction Action = "create"
	// UpdateAction is the action that modifies an existing object.
	UpdateAction Action = "update"
	// DeleteAction is the action that deletes an object.
	DeleteAction Action = "delete"
	// UnknownAction is shown for records written by an older version that
	// did not record the action, or for corrupted legacy entries.
	UnknownAction Action = Unknown
)

// ObjectType identifies the kind of object a record refers to.
type ObjectType string

const (
	// ProvisionerObject is a provisioner.
	ProvisionerObject ObjectType = "provisioner"
	// AdminObject is an administrator.
	AdminObject ObjectType = "admin"
	// AuthorityPolicyObject is the authority level policy.
	AuthorityPolicyObject ObjectType = "authority_policy"
	// ProvisionerPolicyObject is a provisioner level policy.
	ProvisionerPolicyObject ObjectType = "provisioner_policy"
	// ACMEAccountPolicyObject is an ACME account level policy.
	ACMEAccountPolicyObject ObjectType = "acme_account_policy"
	// WebhookObject is a provisioner webhook (callback configuration).
	WebhookObject ObjectType = "webhook"
	// UnknownObject is shown when the object type is missing from a record.
	UnknownObject ObjectType = Unknown
)

// Result describes the outcome of a write operation.
type Result string

const (
	// SuccessResult means the business write succeeded.
	SuccessResult Result = "success"
	// FailureResult means the business write failed; the record carries an
	// error category explaining why.
	FailureResult Result = "failure"
	// UnknownResult is shown for records whose result cannot be
	// determined (e.g. corrupted legacy entries).
	UnknownResult Result = Unknown
)

// Redacted replaces the value of fields that must never end up in the
// audit trail, such as tokens, passwords and other secrets.
const Redacted = "[REDACTED]"

const (
	// DefaultRetention is the period audit records are kept for before
	// they become eligible for batch reclamation.
	DefaultRetention = 90 * 24 * time.Hour
	// PurgeBatchSize is the maximum number of expired records removed in a
	// single database transaction.
	PurgeBatchSize = 100
	// DefaultLimit is the default page size used by GetAuditRecords when
	// no limit was provided.
	DefaultLimit = 25
	// MaxLimit caps the page size used by GetAuditRecords.
	MaxLimit = 100
)

// Change describes a single field that differs between the state before
// and the state after an update operation.
type Change struct {
	// Field is the dotted path of the changed field.
	Field string `json:"field"`
	// Before is the value of the field before the change. It is nil when
	// the field was added.
	Before any `json:"before,omitempty"`
	// After is the value of the field after the change. It is nil when
	// the field was removed.
	After any `json:"after,omitempty"`
}

// Diff is a human readable summary of what changed. Create and delete
// operations carry a sanitized snapshot of the created or removed object;
// update operations carry a list of field level changes instead.
type Diff struct {
	// Summary is a short, human readable description of the change.
	Summary string `json:"summary,omitempty"`
	// Changes lists the fields that changed during an update operation.
	Changes []Change `json:"changes,omitempty"`
	// Before is the sanitized state before the operation. It is populated
	// for delete operations.
	Before map[string]any `json:"before,omitempty"`
	// After is the sanitized state after the operation. It is populated
	// for create operations.
	After map[string]any `json:"after,omitempty"`
}

// Record is a single, immutable audit entry.
type Record struct {
	// Sequence is the unique, monotonically increasing write number. It
	// defines the stable ordering of records, including under concurrent
	// writes. The record key is derived from it.
	Sequence uint64 `json:"sequence"`
	// Time is when the operation completed, in UTC.
	Time time.Time `json:"time"`
	// RequestID ties the record back to the originating HTTP request log
	// entry.
	RequestID string `json:"requestId,omitempty"`
	// ActorID is the ID of the administrator that performed the operation.
	ActorID string `json:"actorId,omitempty"`
	// ActorSubject is the subject of the administrator that performed the
	// operation.
	ActorSubject string `json:"actorSubject,omitempty"`
	// ActorType is the type of administrator (e.g. SUPER_ADMIN).
	ActorType string `json:"actorType,omitempty"`
	// RemoteAddress is the host part of the remote address of the client
	// that performed the operation.
	RemoteAddress string `json:"remoteAddress,omitempty"`
	// Action is create, update or delete.
	Action Action `json:"action"`
	// ObjectType identifies the object family.
	ObjectType ObjectType `json:"objectType"`
	// ObjectID is the stable identifier of the affected object, when
	// known.
	ObjectID string `json:"objectId,omitempty"`
	// ObjectName is the human friendly name of the affected object, when
	// known.
	ObjectName string `json:"objectName,omitempty"`
	// Result is success or failure.
	Result Result `json:"result"`
	// StatusCode is the HTTP status code returned to the caller.
	StatusCode int `json:"statusCode"`
	// ErrorCategory categorizes failed operations (e.g. badRequest,
	// notFound, conflict, internalServerError).
	ErrorCategory string `json:"errorCategory,omitempty"`
	// Diff is the before/after change summary.
	Diff *Diff `json:"diff,omitempty"`
}

// Normalize fills fields that were not recorded. Records written by older
// versions, or corrupted legacy entries, are shown with "unknown" values
// instead of failing to load.
func (r *Record) Normalize() {
	if r.Action == "" {
		r.Action = UnknownAction
	}
	if r.ObjectType == "" {
		r.ObjectType = UnknownObject
	}
	if r.Result == "" {
		r.Result = UnknownResult
	}
	if r.ActorSubject == "" {
		r.ActorSubject = Unknown
	}
	if r.ActorID == "" {
		r.ActorID = Unknown
	}
	if r.ObjectID == "" {
		r.ObjectID = Unknown
	}
	if r.ErrorCategory == "" && r.Result == FailureResult {
		r.ErrorCategory = Unknown
	}
}

// Store is the persistence backend for the audit trail. Records are
// append-only: there is no update or single-record delete operation.
type Store interface {
	// CreateAuditRecord appends a record. The store assigns the unique
	// sequence number. The operation must fail rather than overwrite an
	// existing record.
	CreateAuditRecord(ctx context.Context, rec *Record) error
	// GetAuditRecords returns one page of records in reverse chronological
	// order (newest first). cursor is the opaque cursor returned by a
	// previous call; a record with the cursor's sequence value is never
	// returned again and concurrent inserts at the head of the trail do
	// not cause skipped or duplicated entries.
	GetAuditRecords(ctx context.Context, cursor string, limit int) (records []*Record, nextCursor string, err error)
	// PurgeAuditRecords batch deletes records older than before and
	// returns the number of records that were reclaimed.
	PurgeAuditRecords(ctx context.Context, before time.Time) (int64, error)
}

// RecordView is the API representation of a record. Every identifying
// field is a string so that missing legacy data can be rendered as
// "unknown" without changing the response shape.
type RecordView struct {
	Sequence      uint64 `json:"sequence"`
	Time          string `json:"time"`
	RequestID     string `json:"requestId,omitempty"`
	ActorID       string `json:"actorId"`
	ActorSubject  string `json:"actorSubject"`
	ActorType     string `json:"actorType"`
	RemoteAddress string `json:"remoteAddress,omitempty"`
	Action        string `json:"action"`
	ObjectType    string `json:"objectType"`
	ObjectID      string `json:"objectId"`
	ObjectName    string `json:"objectName,omitempty"`
	Result        string `json:"result"`
	StatusCode    int    `json:"statusCode"`
	ErrorCategory string `json:"errorCategory,omitempty"`
	Diff          *Diff  `json:"diff,omitempty"`
}

// ViewOf converts a Record into its API representation, rendering missing
// legacy fields as "unknown".
func ViewOf(r *Record) *RecordView {
	r.Normalize()
	v := &RecordView{
		Sequence:      r.Sequence,
		RequestID:     r.RequestID,
		ActorID:       r.ActorID,
		ActorSubject:  r.ActorSubject,
		ActorType:     unknownIfEmpty(r.ActorType),
		RemoteAddress: r.RemoteAddress,
		Action:        string(r.Action),
		ObjectType:    string(r.ObjectType),
		ObjectID:      r.ObjectID,
		ObjectName:    r.ObjectName,
		Result:        string(r.Result),
		StatusCode:    r.StatusCode,
		ErrorCategory: r.ErrorCategory,
		Diff:          r.Diff,
	}
	if r.Time.IsZero() {
		v.Time = Unknown
	} else {
		v.Time = r.Time.UTC().Format(time.RFC3339)
	}
	return v
}

func unknownIfEmpty(s string) string {
	if s == "" {
		return Unknown
	}
	return s
}

// Snapshot converts a value into a generic map suitable for diffing.
// Protobuf messages are rendered with their canonical JSON representation;
// other values are rendered with encoding/json. Secret material is
// redacted. A nil value renders to a nil map without error.
func Snapshot(v any) (map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	var (
		data []byte
		err  error
	)
	if m, ok := v.(proto.Message); ok {
		data, err = protojson.Marshal(m)
	} else {
		data, err = json.Marshal(v)
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return Sanitize(m), nil
}

// JSONSnapshot parses an already encoded JSON body into a sanitized map.
// Empty or "null" bodies produce a nil map.
func JSONSnapshot(data []byte) (map[string]any, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return Sanitize(m), nil
}

// secretKeys lists (lower cased, substring matched) JSON field names that
// carry credentials or other secrets. Their values never leave the
// process in an audit record.
var secretKeys = []string{
	"secret",
	"token",
	"password",
	"passwd",
	"bearer",
	"authorization",
	"privatekey",
	"encryptedkey",
	"cookie",
}

func isSecretKey(key string) bool {
	lk := strings.ToLower(key)
	for _, sk := range secretKeys {
		if strings.Contains(lk, sk) {
			return true
		}
	}
	return false
}

// Sanitize returns a deep copy of m in which every field whose name looks
// like a secret has its value replaced by Redacted. Maps and slices are
// traversed recursively.
func Sanitize(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = sanitizeValue(k, v)
	}
	return out
}

func sanitizeValue(key string, v any) any {
	if isSecretKey(key) {
		return Redacted
	}
	switch t := v.(type) {
	case map[string]any:
		return Sanitize(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sanitizeValue(key, e)
		}
		return out
	default:
		return v
	}
}

// BuildDiff creates a redacted before/after change summary for a write
// operation. Create operations return the after snapshot, delete
// operations the before snapshot and update operations a list of changed
// fields.
func BuildDiff(action Action, before, after map[string]any, summary string) *Diff {
	d := &Diff{Summary: summary}
	switch action {
	case CreateAction:
		d.After = after
	case DeleteAction:
		d.Before = before
	case UpdateAction:
		d.Changes = FieldChanges(before, after)
		if len(d.Changes) == 0 {
			d.Summary = summary
		}
	default:
		d.Before = before
		d.After = after
	}
	return d
}

// FieldChanges compares two sanitized snapshots and returns the set of
// dotted paths whose values differ. The result is sorted by field name so
// that diffs are stable across requests and runs.
func FieldChanges(before, after map[string]any) []Change {
	changes := map[string]Change{}
	collectChanges("", before, after, changes)

	out := make([]Change, 0, len(changes))
	for _, c := range changes {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func collectChanges(prefix string, before, after any, changes map[string]Change) {
	bm, bok := before.(map[string]any)
	am, aok := after.(map[string]any)
	if bok && aok {
		keys := map[string]struct{}{}
		for k := range bm {
			keys[k] = struct{}{}
		}
		for k := range am {
			keys[k] = struct{}{}
		}
		for k := range keys {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			collectChanges(path, bm[k], am[k], changes)
		}
		return
	}
	if valuesEqual(before, after) {
		return
	}
	field := prefix
	if field == "" {
		field = "$"
	}
	changes[field] = Change{
		Field:  field,
		Before: before,
		After:  after,
	}
}

func valuesEqual(a, b any) bool {
	// Slices and nested maps reach this point only when the enclosing
	// values are not both maps; compare their JSON forms.
	ab, aok := primitiveOrJSON(a)
	bb, bok := primitiveOrJSON(b)
	if !aok || !bok {
		return a == b
	}
	return string(ab) == string(bb)
}

func primitiveOrJSON(v any) ([]byte, bool) {
	switch v.(type) {
	case nil, string, bool, float64, int, int64, uint64:
		return nil, false
	default:
		b, err := json.Marshal(v)
		return b, err == nil
	}
}
