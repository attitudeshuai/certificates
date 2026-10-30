package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/admin/audit"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
)

var errAuditDown = errors.New("audit database unavailable")

type fakeAuditStore struct {
	*admin.MockDB

	mu        sync.Mutex
	records   []*audit.Record
	createErr error

	getRecords []*audit.Record
	getNext    string
}

func (f *fakeAuditStore) CreateAuditRecord(_ context.Context, rec *audit.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, rec)
	return f.createErr
}

func (f *fakeAuditStore) GetAuditRecords(_ context.Context, _ string, _ int) ([]*audit.Record, string, error) {
	return f.getRecords, f.getNext, nil
}

func (f *fakeAuditStore) PurgeAuditRecords(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (f *fakeAuditStore) list() []*audit.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*audit.Record, len(f.records))
	copy(out, f.records)
	return out
}

// newDirectContext builds a context for invoking a handler directly,
// without a chi router.
func newDirectContext(t *testing.T, auth adminAuthority, store admin.DB) context.Context {
	t.Helper()
	mockMustAuthority(t, auth)
	ctx := admin.NewContext(context.Background(), store)
	return linkedca.NewContextWithAdmin(ctx, &linkedca.Admin{
		Id:      "adm-1",
		Subject: "step",
		Type:    linkedca.Admin_SUPER_ADMIN,
	})
}

// injectTestContext returns a middleware that enriches the incoming
// request context (it must derive from the request context so chi's
// routing context is preserved, exactly as in production) with the admin
// database and the authenticated administrator.
func injectTestContext(t *testing.T, store admin.DB) func(http.Handler) http.Handler {
	t.Helper()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := admin.NewContext(req.Context(), store)
			ctx = linkedca.NewContextWithAdmin(ctx, &linkedca.Admin{
				Id:      "adm-1",
				Subject: "step",
				Type:    linkedca.Admin_SUPER_ADMIN,
			})
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

// auditRouter builds a chi router that mounts a single audited route and
// injects the test context, matching the /admin prefix used in production.
func auditRouter(method, pattern string, inject func(http.Handler) http.Handler, h http.HandlerFunc) http.Handler {
	r := chi.NewRouter()
	r.With(inject).MethodFunc(method, pattern, auditWrites(h))
	return r
}

func serveAuditRoute(t *testing.T, method, pattern, target, body, remoteAddr string, inject func(http.Handler) http.Handler, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reqBody)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	w := httptest.NewRecorder()
	auditRouter(method, pattern, inject, h).ServeHTTP(w, req)
	return w
}

func TestAuditWrites_createProvisioner(t *testing.T) {
	store := &fakeAuditStore{MockDB: &admin.MockDB{}}
	mockMustAuthority(t, &mockAdminAuthority{})
	inject := injectTestContext(t, store)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"prov-1","name":"foo","type":"JWK"}`))
	}

	w := serveAuditRoute(t, "POST", "/admin/provisioners", "/admin/provisioners", `{"name":"foo"}`, "10.0.0.7:5555", inject, handler)
	assertStatus(t, w, http.StatusCreated)
	assertBodyContains(t, w, `"id":"prov-1"`)

	records := store.list()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	rec := records[0]
	assertAuditString(t, "create", string(rec.Action))
	assertAuditString(t, "provisioner", string(rec.ObjectType))
	assertAuditString(t, "prov-1", rec.ObjectID)
	assertAuditString(t, "foo", rec.ObjectName)
	assertAuditString(t, "success", string(rec.Result))
	assertAuditString(t, "step", rec.ActorSubject)
	assertAuditString(t, "adm-1", rec.ActorID)
	assertAuditString(t, "10.0.0.7", rec.RemoteAddress)
	if rec.Diff == nil || rec.Diff.After["name"] != "foo" {
		t.Fatalf("expected readable after-diff, got %#v", rec.Diff)
	}
	assertAuditString(t, "", w.Header().Get(AuditStatusHeader))
}

func TestAuditWrites_deleteProvisionerReadableBefore(t *testing.T) {
	auth := &mockAdminAuthority{
		MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
			assertAuditString(t, "foo", name)
			return &provisioner.JWK{ID: "prov-1", Name: "foo"}, nil
		},
	}
	store := &fakeAuditStore{
		MockDB: &admin.MockDB{
			MockGetProvisioner: func(_ context.Context, id string) (*linkedca.Provisioner, error) {
				assertAuditString(t, "prov-1", id)
				return &linkedca.Provisioner{Id: "prov-1", Name: "foo", Type: linkedca.Provisioner_JWK}, nil
			},
		},
	}
	mockMustAuthority(t, auth)
	inject := injectTestContext(t, store)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}

	w := serveAuditRoute(t, "DELETE", "/admin/provisioners/{name}", "/admin/provisioners/foo", "", "", inject, handler)
	assertStatus(t, w, http.StatusOK)

	records := store.list()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	rec := records[0]
	assertAuditString(t, "delete", string(rec.Action))
	assertAuditString(t, "provisioner", string(rec.ObjectType))
	assertAuditString(t, "foo", rec.ObjectName)
	assertAuditString(t, "success", string(rec.Result))
	if rec.Diff == nil || rec.Diff.Before["name"] != "foo" {
		t.Fatalf("expected readable before-diff, got %#v", rec.Diff)
	}
}

func TestAuditWrites_failedBusinessWriteIsRecorded(t *testing.T) {
	store := &fakeAuditStore{MockDB: &admin.MockDB{}}
	mockMustAuthority(t, &mockAdminAuthority{})
	inject := injectTestContext(t, store)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"badRequest","detail":"bad request","message":"invalid claims"}`))
	}

	w := serveAuditRoute(t, "POST", "/admin/provisioners", "/admin/provisioners", `{}`, "", inject, handler)
	assertStatus(t, w, http.StatusBadRequest)

	records := store.list()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record for failed write, got %d", len(records))
	}
	rec := records[0]
	assertAuditString(t, "failure", string(rec.Result))
	assertAuditString(t, "badRequest", rec.ErrorCategory)
	if rec.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400 in record, got %d", rec.StatusCode)
	}
}

func TestAuditWrites_auditDegradedDoesNotMaskSuccess(t *testing.T) {
	store := &fakeAuditStore{MockDB: &admin.MockDB{}, createErr: errAuditDown}
	mockMustAuthority(t, &mockAdminAuthority{})

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"prov-1","name":"foo"}`))
	}

	req := httptest.NewRequest("POST", "/admin/provisioners", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	rw := logging.NewResponseLogger(recorder)

	auditRouter("POST", "/admin/provisioners", injectTestContext(t, store), handler).ServeHTTP(rw, req)

	assertStatus(t, recorder, http.StatusCreated)
	assertBodyContains(t, recorder, `"id":"prov-1"`)
	assertAuditString(t, "degraded", recorder.Header().Get(AuditStatusHeader))
	if got := rw.Fields()["audit"]; got != "degraded" {
		t.Fatalf("expected audit=degraded log field, got %v", got)
	}
}

func TestAuditWrites_auditDegradedNotMarkedOnBusinessFailure(t *testing.T) {
	store := &fakeAuditStore{MockDB: &admin.MockDB{}, createErr: errAuditDown}
	auth := &mockAdminAuthority{
		MockLoadProvisionerByName: func(string) (provisioner.Interface, error) {
			return nil, admin.NewError(admin.ErrorNotFoundType, "provisioner not found")
		},
	}
	mockMustAuthority(t, auth)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"notFound"}`))
	}

	w := serveAuditRoute(t, "DELETE", "/admin/provisioners/{name}", "/admin/provisioners/missing", "", "", injectTestContext(t, store), handler)
	assertStatus(t, w, http.StatusNotFound)
	assertAuditString(t, "", w.Header().Get(AuditStatusHeader))
}

func TestAuditWrites_withoutStorePassesThrough(t *testing.T) {
	mockMustAuthority(t, &mockAdminAuthority{})
	called := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}
	w := serveAuditRoute(t, "POST", "/admin/provisioners", "/admin/provisioners", `{}`, "", injectTestContext(t, &admin.MockDB{}), handler)
	assertStatus(t, w, http.StatusCreated)
	if !called {
		t.Fatal("business handler was not called")
	}
}

func TestAuditWrites_secretIsRedacted(t *testing.T) {
	store := &fakeAuditStore{MockDB: &admin.MockDB{}}
	mockMustAuthority(t, &mockAdminAuthority{})

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"wh-1","name":"hook","kind":"ENRICHING","secret":"plaintext-secret"}`))
	}

	w := serveAuditRoute(t, "POST", "/admin/provisioners/{provisionerName}/webhooks", "/admin/provisioners/prov/webhooks", `{"name":"hook"}`, "", injectTestContext(t, store), handler)
	assertStatus(t, w, http.StatusCreated)

	records := store.list()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if got := records[0].Diff.After["secret"]; got != audit.Redacted {
		t.Fatalf("expected redacted secret, got %v", got)
	}
}

func TestGetAuditRecords_handler(t *testing.T) {
	store := &fakeAuditStore{
		MockDB:     &admin.MockDB{},
		getRecords: []*audit.Record{{Sequence: 9, Result: audit.SuccessResult, Action: audit.CreateAction, ObjectType: audit.ProvisionerObject}},
		getNext:    "5",
	}
	ctx := newDirectContext(t, &mockAdminAuthority{}, store)

	req := httptest.NewRequest("GET", "/admin/audit?limit=25&cursor=10", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	GetAuditRecords(w, req)
	assertStatus(t, w, http.StatusOK)

	var resp GetAuditRecordsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unexpected response body %q: %v", w.Body.String(), err)
	}
	if len(resp.Records) != 1 {
		t.Fatalf("expected 1 record view, got %d", len(resp.Records))
	}
	if resp.Records[0].Sequence != 9 {
		t.Fatalf("expected sequence 9, got %d", resp.Records[0].Sequence)
	}
	assertAuditString(t, "provisioner", resp.Records[0].ObjectType)
	assertAuditString(t, audit.Unknown, resp.Records[0].ActorSubject)
	assertAuditString(t, audit.Unknown, resp.Records[0].Time)
	assertAuditString(t, "5", resp.NextCursor)
}

func TestGetAuditRecords_notSupportedByBackend(t *testing.T) {
	ctx := newDirectContext(t, &mockAdminAuthority{}, &admin.MockDB{})
	req := httptest.NewRequest("GET", "/admin/audit", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	GetAuditRecords(w, req)
	assertStatus(t, w, http.StatusNotImplemented)
}

func assertStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("expected status %d, got %d (body=%s)", want, w.Code, w.Body.String())
	}
}

func assertBodyContains(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	if !strings.Contains(w.Body.String(), want) {
		t.Fatalf("expected body to contain %q, got %s", want, w.Body.String())
	}
}

func assertAuditString(t *testing.T, want, got string) {
	t.Helper()
	if want != got {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
