package api

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/linkedca"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/admin/audit"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/middleware/requestid"
)

// AuditStatusHeader is set on a successful business response when the
// audit record for that request could not be written. Its value is
// "degraded".
const AuditStatusHeader = "X-Step-Ca-Audit"

const auditDegradedValue = "degraded"

// GetAuditRecordsResponse is the type for GET /admin/audit responses.
type GetAuditRecordsResponse struct {
	Records    []*audit.RecordView `json:"records"`
	NextCursor string              `json:"nextCursor"`
}

// GetAuditRecords returns a page of immutable audit records, newest
// first. It uses the same authentication as the rest of the
// Administration API and is only mounted when the Administration API is
// enabled.
func GetAuditRecords(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	store, ok := admin.MustFromContext(ctx).(audit.Store)
	if !ok {
		render.Error(w, r, admin.NewError(admin.ErrorNotImplementedType, "audit log is not supported by the configured database"))
		return
	}

	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		render.Error(w, r, admin.WrapError(admin.ErrorBadRequestType, err,
			"error parsing cursor and limit from query params"))
		return
	}

	records, nextCursor, err := store.GetAuditRecords(ctx, cursor, limit)
	if err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error retrieving audit records"))
		return
	}

	views := make([]*audit.RecordView, 0, len(records))
	for _, rec := range records {
		views = append(views, audit.ViewOf(rec))
	}
	render.JSON(w, r, &GetAuditRecordsResponse{
		Records:    views,
		NextCursor: nextCursor,
	})
}

// auditWrites wraps an Administration API write handler and appends a
// single audit record for every attempt, successful or not. A failed
// business write is recorded with its error category. A failed audit
// write after a successful business write does not mask the business
// result; the response is marked as audit degraded instead.
func auditWrites(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Without an audit store (e.g. the hosted linkedca backend) audit
		// recording is a no-op. The request still flows untouched.
		store, hasStore := admin.MustFromContext(ctx).(audit.Store)

		desc := describeAuditRequest(r)

		// Buffer the request body so it can be used as a fallback for the
		// after-state and still handed to the business handler intact.
		var requestBody []byte
		if r.Body != nil {
			requestBody, _ = io.ReadAll(r.Body)
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(requestBody))
		}

		// Best-effort prefetch is guarded: audit bookkeeping must never
		// get in the way of the business request.
		before := func() (snapshot map[string]any) {
			defer func() {
				if rv := recover(); rv != nil {
					log.Printf("audit before-state load panicked for %s %s: %v", r.Method, r.URL.Path, rv)
					snapshot = nil
				}
			}()
			return loadAuditBeforeState(ctx, r, desc)
		}()

		rec := &audit.Record{
			Time:          time.Now().UTC(),
			Action:        desc.action,
			ObjectType:    desc.objectType,
			ObjectID:      desc.objectID,
			ObjectName:    desc.objectName,
			RemoteAddress: clientHost(r.RemoteAddr),
		}
		if id, ok := requestid.FromContext(ctx); ok {
			rec.RequestID = id
		}
		if adm, ok := linkedca.AdminFromContext(ctx); ok {
			rec.ActorID = adm.GetId()
			rec.ActorSubject = adm.GetSubject()
			rec.ActorType = adm.GetType().String()
		}

		recorder := newAuditResponseRecorder(w)
		next.ServeHTTP(recorder, r)

		// Audit bookkeeping runs after the business response has been
		// produced. Whatever happens here, the recorded response is always
		// replayed to the caller.
		var extra http.Header
		func() {
			defer func() {
				if rv := recover(); rv != nil {
					log.Printf("audit bookkeeping panicked for request %s (%s %s): %v",
						rec.RequestID, r.Method, r.URL.Path, rv)
				}
			}()

			body := recorder.body.Bytes()
			responseMap := decodeJSONBody(body)

			rec.StatusCode = recorder.status
			if recorder.status < http.StatusBadRequest {
				rec.Result = audit.SuccessResult
				after := responseMap
				if after == nil {
					after = decodeJSONBody(requestBody)
				}
				enrichAuditIdentity(rec, after)
				rec.Diff = audit.BuildDiff(desc.action, before, after, auditSummary(rec))
			} else {
				rec.Result = audit.FailureResult
				rec.ErrorCategory = errorCategory(recorder.status, responseMap)
				// The response body is an error document; use the
				// redacted request body to identify the intended object.
				enrichAuditIdentity(rec, decodeJSONBody(requestBody))
				rec.Diff = &audit.Diff{
					Summary: auditSummary(rec),
					Before:  before,
				}
			}

			if !hasStore {
				return
			}

			if err := store.CreateAuditRecord(ctx, rec); err != nil {
				log.Printf("audit write failed for request %s (%s %s): %v",
					rec.RequestID, r.Method, r.URL.Path, err)
				if rec.Result == audit.SuccessResult {
					// Business write succeeded; surface the degraded audit
					// state in the response and the request log entry, but
					// do not change the business response itself.
					markAuditDegraded(w, err)
					extra = http.Header{AuditStatusHeader: []string{auditDegradedValue}}
				}
			}
		}()

		recorder.flush(extra)
	}
}

// markAuditDegraded annotates the enclosing request log entry so the
// degraded audit state is visible in the logs as well.
func markAuditDegraded(w http.ResponseWriter, err error) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]any{
			"audit":       auditDegradedValue,
			"audit-error": err.Error(),
		})
	}
}

// auditResponseRecorder buffers the business response so the audit
// middleware can inspect status and body and, when needed, add the audit
// degraded header before the response is committed.
type auditResponseRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	body        bytes.Buffer
}

func newAuditResponseRecorder(w http.ResponseWriter) *auditResponseRecorder {
	return &auditResponseRecorder{ResponseWriter: w, status: http.StatusOK}
}

func (r *auditResponseRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
}

func (r *auditResponseRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(p)
}

// flush commits the buffered response to the wrapped writer. Additional
// headers (e.g. the audit degraded marker) must be supplied before the
// first flush.
func (r *auditResponseRecorder) flush(extra http.Header) {
	for key, values := range extra {
		for _, v := range values {
			r.ResponseWriter.Header().Add(key, v)
		}
	}
	r.ResponseWriter.WriteHeader(r.status)
	if r.body.Len() > 0 {
		//nolint:gosec // admin responses are small JSON documents.
		_, _ = r.ResponseWriter.Write(r.body.Bytes())
	}
}

func decodeJSONBody(data []byte) map[string]any {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	m, err := audit.JSONSnapshot(data)
	if err != nil {
		return nil
	}
	return m
}

func clientHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// auditDescriptor describes the object targeted by an admin write.
type auditDescriptor struct {
	objectType audit.ObjectType
	action     audit.Action
	objectID   string
	objectName string
}

func actionFromMethod(method string) audit.Action {
	switch method {
	case http.MethodPost:
		return audit.CreateAction
	case http.MethodPut, http.MethodPatch:
		return audit.UpdateAction
	case http.MethodDelete:
		return audit.DeleteAction
	default:
		return audit.UnknownAction
	}
}

// describeAuditRequest maps the matched chi route and HTTP method to an
// audit descriptor. Path parameters follow the routes registered in
// Route.
func describeAuditRequest(r *http.Request) auditDescriptor {
	pattern := chi.RouteContext(r.Context()).RoutePattern()
	pattern = strings.TrimPrefix(pattern, "/admin")
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		pattern = "/"
	}
	action := actionFromMethod(r.Method)

	urlParam := func(names ...string) string {
		for _, name := range names {
			if v := chi.URLParam(r, name); v != "" {
				return v
			}
		}
		return ""
	}

	d := auditDescriptor{action: action}
	switch {
	case pattern == "/provisioners":
		d.objectType = audit.ProvisionerObject
		d.objectID = r.URL.Query().Get("id")
	case pattern == "/provisioners/{name}":
		d.objectType = audit.ProvisionerObject
		d.objectID = r.URL.Query().Get("id")
		d.objectName = urlParam("name")
	case pattern == "/admins":
		d.objectType = audit.AdminObject
	case pattern == "/admins/{id}":
		d.objectType = audit.AdminObject
		d.objectID = urlParam("id")
	case pattern == "/policy":
		d.objectType = audit.AuthorityPolicyObject
		d.objectID = "authority"
		d.objectName = "authority"
	case pattern == "/provisioners/{provisionerName}/policy":
		d.objectType = audit.ProvisionerPolicyObject
		d.objectName = urlParam("provisionerName")
	case strings.HasPrefix(pattern, "/acme/policy/"):
		d.objectType = audit.ACMEAccountPolicyObject
		d.objectName = urlParam("provisionerName")
		d.objectID = urlParam("reference", "keyID")
	case pattern == "/provisioners/{provisionerName}/webhooks":
		d.objectType = audit.WebhookObject
		d.objectName = urlParam("provisionerName")
	case strings.HasSuffix(pattern, "/webhooks/{webhookName}"):
		d.objectType = audit.WebhookObject
		provName := urlParam("provisionerName")
		webhookName := urlParam("webhookName")
		d.objectName = provName + "/" + webhookName
	default:
		d.objectType = audit.UnknownObject
	}
	return d
}

// loadAuditBeforeState best-effort loads a sanitized snapshot of the
// object as it existed before an update or delete. Failures never block
// the business request.
func loadAuditBeforeState(ctx context.Context, r *http.Request, d auditDescriptor) map[string]any {
	if d.action == audit.CreateAction {
		return nil
	}

	auth := mustAuthority(ctx)
	adminDB := admin.MustFromContext(ctx)

	snapshot := func(v any) map[string]any {
		m, err := audit.Snapshot(v)
		if err != nil {
			return nil
		}
		return m
	}

	switch d.objectType {
	case audit.ProvisionerObject:
		var (
			p   provisioner.Interface
			err error
		)
		id := r.URL.Query().Get("id")
		if id != "" {
			p, err = auth.LoadProvisionerByID(id)
		} else {
			p, err = auth.LoadProvisionerByName(chi.URLParam(r, "name"))
		}
		if err != nil {
			return nil
		}
		prov, err := adminDB.GetProvisioner(ctx, p.GetID())
		if err != nil {
			return nil
		}
		return snapshot(prov)
	case audit.AdminObject:
		if d.objectID == "" {
			return nil
		}
		adm, ok := auth.LoadAdminByID(d.objectID)
		if !ok {
			return nil
		}
		return snapshot(adm)
	case audit.AuthorityPolicyObject:
		pol, err := auth.GetAuthorityPolicy(ctx)
		if err != nil || pol == nil {
			return nil
		}
		return snapshot(pol)
	case audit.ProvisionerPolicyObject:
		prov := loadLinkedProvisionerByName(ctx, r, auth, adminDB, chi.URLParam(r, "provisionerName"))
		if prov == nil {
			return nil
		}
		return snapshot(prov.GetPolicy())
	case audit.WebhookObject:
		prov := loadLinkedProvisionerByName(ctx, r, auth, adminDB, chi.URLParam(r, "provisionerName"))
		if prov == nil {
			return nil
		}
		webhookName := chi.URLParam(r, "webhookName")
		for _, wh := range prov.GetWebhooks() {
			if wh.GetName() == webhookName {
				return snapshot(wh)
			}
		}
	}
	return nil
}

// loadLinkedProvisionerByName resolves a provisioner by name through the
// cached configuration and loads its linkedca representation from the
// admin database.
func loadLinkedProvisionerByName(ctx context.Context, r *http.Request, auth adminAuthority, adminDB admin.DB, name string) *linkedca.Provisioner {
	if name == "" {
		if prov, ok := linkedca.ProvisionerFromContext(ctx); ok {
			return prov
		}
		return nil
	}
	p, err := auth.LoadProvisionerByName(name)
	if err != nil {
		return nil
	}
	prov, err := adminDB.GetProvisioner(ctx, p.GetID())
	if err != nil {
		return nil
	}
	return prov
}

// enrichAuditIdentity fills object identifiers from the response body of
// a successful create operation.
func enrichAuditIdentity(rec *audit.Record, after map[string]any) {
	if after == nil {
		return
	}
	getString := func(key string) string {
		if v, ok := after[key].(string); ok {
			return v
		}
		return ""
	}
	switch rec.ObjectType {
	case audit.ProvisionerObject:
		if rec.ObjectID == "" {
			rec.ObjectID = getString("id")
		}
		if rec.ObjectName == "" {
			rec.ObjectName = getString("name")
		}
	case audit.AdminObject:
		if rec.ObjectID == "" {
			rec.ObjectID = getString("id")
		}
		if rec.ObjectName == "" {
			rec.ObjectName = getString("subject")
		}
	case audit.WebhookObject:
		if rec.ObjectID == "" {
			rec.ObjectID = getString("id")
		}
		if name := getString("name"); name != "" {
			switch {
			case strings.HasSuffix(rec.ObjectName, "/"+name):
				// Already provisioner/webhook.
			case strings.Contains(rec.ObjectName, "/"):
				rec.ObjectName = rec.ObjectName + "/" + name
			case rec.ObjectName != "":
				rec.ObjectName = rec.ObjectName + "/" + name
			default:
				rec.ObjectName = name
			}
		}
	}
}

func auditSummary(rec *audit.Record) string {
	name := rec.ObjectName
	if name == "" {
		name = rec.ObjectID
	}
	if name == "" {
		name = audit.Unknown
	}
	return string(rec.Action) + " " + string(rec.ObjectType) + " " + name
}

// errorCategory derives the audit error category from the HTTP status and
// the "type" field rendered by admin errors.
func errorCategory(status int, body map[string]any) string {
	if body != nil {
		if t, ok := body["type"].(string); ok && t != "" {
			return t
		}
	}
	switch status {
	case http.StatusBadRequest:
		return admin.ErrorBadRequestType.String()
	case http.StatusUnauthorized:
		return admin.ErrorUnauthorizedType.String()
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return admin.ErrorNotFoundType.String()
	case http.StatusConflict:
		return admin.ErrorConflictType.String()
	case http.StatusNotImplemented:
		return admin.ErrorNotImplementedType.String()
	case http.StatusInternalServerError:
		return admin.ErrorServerInternalType.String()
	default:
		return audit.Unknown
	}
}
