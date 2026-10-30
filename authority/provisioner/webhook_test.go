package provisioner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smallstep/certificates/internal/httptransport"
	"github.com/smallstep/certificates/middleware/requestid"
	"github.com/smallstep/certificates/webhook"
	"github.com/smallstep/linkedca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

func TestWebhookController_isCertTypeOK(t *testing.T) {
	type test struct {
		wc   *WebhookController
		wh   *Webhook
		want bool
	}
	tests := map[string]test{
		"all/all": {
			wc:   &WebhookController{certType: linkedca.Webhook_ALL},
			wh:   &Webhook{CertType: linkedca.Webhook_ALL.String()},
			want: true,
		},
		"all/x509": {
			wc:   &WebhookController{certType: linkedca.Webhook_ALL},
			wh:   &Webhook{CertType: linkedca.Webhook_X509.String()},
			want: true,
		},
		"all/ssh": {
			wc:   &WebhookController{certType: linkedca.Webhook_ALL},
			wh:   &Webhook{CertType: linkedca.Webhook_SSH.String()},
			want: true,
		},
		`all/""`: {
			wc:   &WebhookController{certType: linkedca.Webhook_ALL},
			wh:   &Webhook{},
			want: true,
		},
		"x509/all": {
			wc:   &WebhookController{certType: linkedca.Webhook_X509},
			wh:   &Webhook{CertType: linkedca.Webhook_ALL.String()},
			want: true,
		},
		"x509/x509": {
			wc:   &WebhookController{certType: linkedca.Webhook_X509},
			wh:   &Webhook{CertType: linkedca.Webhook_X509.String()},
			want: true,
		},
		"x509/ssh": {
			wc:   &WebhookController{certType: linkedca.Webhook_X509},
			wh:   &Webhook{CertType: linkedca.Webhook_SSH.String()},
			want: false,
		},
		`x509/""`: {
			wc:   &WebhookController{certType: linkedca.Webhook_X509},
			wh:   &Webhook{},
			want: true,
		},
		"ssh/all": {
			wc:   &WebhookController{certType: linkedca.Webhook_SSH},
			wh:   &Webhook{CertType: linkedca.Webhook_ALL.String()},
			want: true,
		},
		"ssh/x509": {
			wc:   &WebhookController{certType: linkedca.Webhook_SSH},
			wh:   &Webhook{CertType: linkedca.Webhook_X509.String()},
			want: false,
		},
		"ssh/ssh": {
			wc:   &WebhookController{certType: linkedca.Webhook_SSH},
			wh:   &Webhook{CertType: linkedca.Webhook_SSH.String()},
			want: true,
		},
		`ssh/""`: {
			wc:   &WebhookController{certType: linkedca.Webhook_SSH},
			wh:   &Webhook{},
			want: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, test.wc.isCertTypeOK(test.wh))
		})
	}
}

// withRequestID is a helper that calls into [requestid.NewContext] and returns
// a new context with the requestID added.
func withRequestID(t *testing.T, ctx context.Context, requestID string) context.Context {
	t.Helper()
	return requestid.NewContext(ctx, requestID)
}

func TestWebhookController_Enrich(t *testing.T) {
	cert, err := pemutil.ReadCertificate("testdata/certs/x5c-leaf.crt", pemutil.WithFirstBlock())
	require.NoError(t, err)

	type test struct {
		ctl                *WebhookController
		ctx                context.Context
		req                *webhook.RequestBody
		responses          []*webhook.ResponseBody
		expectErr          bool
		expectTemplateData any
		assertRequest      func(t *testing.T, req *webhook.RequestBody)
		assertError        func(t *testing.T, err error)
	}
	tests := map[string]test{
		"ok/no enriching webhooks": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
				TemplateData: nil,
			},
			req:                &webhook.RequestBody{},
			responses:          nil,
			expectErr:          false,
			expectTemplateData: nil,
		},
		"ok/one webhook": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
			},
			ctx:                withRequestID(t, context.Background(), "reqID"),
			req:                &webhook.RequestBody{},
			responses:          []*webhook.ResponseBody{{Allow: true, Data: map[string]any{"role": "bar"}}},
			expectErr:          false,
			expectTemplateData: x509util.TemplateData{"Webhooks": map[string]any{"people": map[string]any{"role": "bar"}}},
		},
		"ok/two webhooks": {
			ctl: &WebhookController{
				client: http.DefaultClient,
				webhooks: []*Webhook{
					{Name: "people", Kind: "ENRICHING"},
					{Name: "devices", Kind: "ENRICHING"},
				},
				TemplateData: x509util.TemplateData{},
			},
			ctx: withRequestID(t, context.Background(), "reqID"),
			req: &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{
				{Allow: true, Data: map[string]any{"role": "bar"}},
				{Allow: true, Data: map[string]any{"serial": "123"}},
			},
			expectErr: false,
			expectTemplateData: x509util.TemplateData{
				"Webhooks": map[string]any{
					"devices": map[string]any{"serial": "123"},
					"people":  map[string]any{"role": "bar"},
				},
			},
		},
		"ok/x509 only": {
			ctl: &WebhookController{
				client: http.DefaultClient,
				webhooks: []*Webhook{
					{Name: "people", Kind: "ENRICHING", CertType: linkedca.Webhook_SSH.String()},
					{Name: "devices", Kind: "ENRICHING"},
				},
				TemplateData: x509util.TemplateData{},
				certType:     linkedca.Webhook_X509,
			},
			ctx: withRequestID(t, context.Background(), "reqID"),
			req: &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{
				{Allow: true, Data: map[string]any{"role": "bar"}},
				{Allow: true, Data: map[string]any{"serial": "123"}},
			},
			expectErr: false,
			expectTemplateData: x509util.TemplateData{
				"Webhooks": map[string]any{
					"devices": map[string]any{"serial": "123"},
				},
			},
		},
		"ok/with options": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
				options:      []webhook.RequestBodyOption{webhook.WithX5CCertificate(cert)},
			},
			ctx:                withRequestID(t, context.Background(), "reqID"),
			req:                &webhook.RequestBody{},
			responses:          []*webhook.ResponseBody{{Allow: true, Data: map[string]any{"role": "bar"}}},
			expectErr:          false,
			expectTemplateData: x509util.TemplateData{"Webhooks": map[string]any{"people": map[string]any{"role": "bar"}}},
			assertRequest: func(t *testing.T, req *webhook.RequestBody) {
				key, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				require.NoError(t, err)
				assert.Equal(t, &webhook.X5CCertificate{
					Raw:                cert.Raw,
					PublicKey:          key,
					PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
					NotBefore:          cert.NotBefore,
					NotAfter:           cert.NotAfter,
				}, req.X5CCertificate)
			},
		},
		"deny": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
			},
			ctx:                withRequestID(t, context.Background(), "reqID"),
			req:                &webhook.RequestBody{},
			responses:          []*webhook.ResponseBody{{Allow: false}},
			expectErr:          true,
			expectTemplateData: x509util.TemplateData{},
			assertError: func(t *testing.T, err error) {
				assert.Equal(t, ErrWebhookDenied, err)
			},
		},
		"deny/with error": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
			},
			ctx: withRequestID(t, context.Background(), "reqID"),
			req: &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: false, Error: &webhook.Error{
				Code: "theCode", Message: "Some message",
			}}},
			expectErr:          true,
			expectTemplateData: x509util.TemplateData{},
			assertError: func(t *testing.T, err error) {
				assert.Equal(t, &webhook.Error{
					Code: "theCode", Message: "Some message",
				}, err)
			},
		},
		"fail/with options": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
				options: []webhook.RequestBodyOption{webhook.WithX5CCertificate(&x509.Certificate{
					PublicKey: []byte("bad"),
				})},
			},
			ctx:                withRequestID(t, context.Background(), "reqID"),
			req:                &webhook.RequestBody{},
			responses:          []*webhook.ResponseBody{{Allow: false}},
			expectErr:          true,
			expectTemplateData: x509util.TemplateData{},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for i, wh := range test.ctl.webhooks {
				var j = i
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "reqID", r.Header.Get("X-Request-ID"))

					err := json.NewEncoder(w).Encode(test.responses[j])
					require.NoError(t, err)
				}))
				// nolint: gocritic // defer in loop isn't a memory leak
				defer ts.Close()
				wh.URL = ts.URL
			}

			err := test.ctl.Enrich(test.ctx, test.req)
			if (err != nil) != test.expectErr {
				t.Fatalf("Got err %v, want %v", err, test.expectErr)
			}
			assert.Equal(t, test.expectTemplateData, test.ctl.TemplateData)
			if test.assertRequest != nil {
				test.assertRequest(t, test.req)
			}
			if test.assertError != nil {
				test.assertError(t, err)
			}
		})
	}
}

func TestWebhookController_Authorize(t *testing.T) {
	cert, err := pemutil.ReadCertificate("testdata/certs/x5c-leaf.crt", pemutil.WithFirstBlock())
	require.NoError(t, err)

	type test struct {
		ctl           *WebhookController
		ctx           context.Context
		req           *webhook.RequestBody
		responses     []*webhook.ResponseBody
		expectErr     bool
		assertRequest func(t *testing.T, req *webhook.RequestBody)
		assertError   func(t *testing.T, err error)
	}
	tests := map[string]test{
		"ok/no enriching webhooks": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "ENRICHING"}},
			},
			req:       &webhook.RequestBody{},
			responses: nil,
			expectErr: false,
		},
		"ok": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
			},
			ctx:       withRequestID(t, context.Background(), "reqID"),
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: true}},
			expectErr: false,
		},
		"ok/ssh only": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING", CertType: linkedca.Webhook_X509.String()}},
				certType: linkedca.Webhook_SSH,
			},
			ctx:       withRequestID(t, context.Background(), "reqID"),
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: false}},
			expectErr: false,
		},
		"ok/with options": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
				options:  []webhook.RequestBodyOption{webhook.WithX5CCertificate(cert)},
			},
			ctx:       withRequestID(t, context.Background(), "reqID"),
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: true}},
			expectErr: false,
			assertRequest: func(t *testing.T, req *webhook.RequestBody) {
				key, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				require.NoError(t, err)
				assert.Equal(t, &webhook.X5CCertificate{
					Raw:                cert.Raw,
					PublicKey:          key,
					PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
					NotBefore:          cert.NotBefore,
					NotAfter:           cert.NotAfter,
				}, req.X5CCertificate)
			},
		},
		"deny": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
			},
			ctx:       withRequestID(t, context.Background(), "reqID"),
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: false}},
			expectErr: true,
			assertError: func(t *testing.T, err error) {
				assert.Equal(t, ErrWebhookDenied, err)
			},
		},
		"deny/withError": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
			},
			ctx: withRequestID(t, context.Background(), "reqID"),
			req: &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: false, Error: &webhook.Error{
				Code: "theCode", Message: "Some message",
			}}},
			expectErr: true,
			assertError: func(t *testing.T, err error) {
				assert.Equal(t, &webhook.Error{
					Code: "theCode", Message: "Some message",
				}, err)
			},
		},
		"fail/with options": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
				options: []webhook.RequestBodyOption{webhook.WithX5CCertificate(&x509.Certificate{
					PublicKey: []byte("bad"),
				})},
			},
			ctx:       withRequestID(t, context.Background(), "reqID"),
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: false}},
			expectErr: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for i, wh := range test.ctl.webhooks {
				var j = i
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "reqID", r.Header.Get("X-Request-ID"))

					err := json.NewEncoder(w).Encode(test.responses[j])
					require.NoError(t, err)
				}))
				// nolint: gocritic // defer in loop isn't a memory leak
				defer ts.Close()
				wh.URL = ts.URL
			}

			err := test.ctl.Authorize(test.ctx, test.req)
			if (err != nil) != test.expectErr {
				t.Fatalf("Got err %v, want %v", err, test.expectErr)
			}
			if test.assertRequest != nil {
				test.assertRequest(t, test.req)
			}
			if test.assertError != nil {
				test.assertError(t, err)
			}
		})
	}
}

func TestWebhook_Do(t *testing.T) {
	csr := parseCertificateRequest(t, "testdata/certs/ecdsa.csr")
	type test struct {
		webhook         Webhook
		dataArg         any
		requestID       string
		webhookResponse webhook.ResponseBody
		expectPath      string
		errStatusCode   int
		serverErrMsg    string
		expectErr       error
		// expectToken     any
	}
	tests := map[string]test{
		"ok": {
			webhook: Webhook{
				ID:     "abc123",
				Secret: "c2VjcmV0Cg==",
			},
			requestID: "reqID",
			webhookResponse: webhook.ResponseBody{
				Data: map[string]any{"role": "dba"},
			},
		},
		"ok/no-request-id": {
			webhook: Webhook{
				ID:     "abc123",
				Secret: "c2VjcmV0Cg==",
			},
			webhookResponse: webhook.ResponseBody{
				Data: map[string]any{"role": "dba"},
			},
		},
		"ok/bearer": {
			webhook: Webhook{
				ID:          "abc123",
				Secret:      "c2VjcmV0Cg==",
				BearerToken: "mytoken",
			},
			requestID: "reqID",
			webhookResponse: webhook.ResponseBody{
				Data: map[string]any{"role": "dba"},
			},
		},
		"ok/basic": {
			webhook: Webhook{
				ID:     "abc123",
				Secret: "c2VjcmV0Cg==",
				BasicAuth: struct {
					Username string
					Password string
				}{
					Username: "myuser",
					Password: "mypass",
				},
			},
			requestID: "reqID",
			webhookResponse: webhook.ResponseBody{
				Data: map[string]any{"role": "dba"},
			},
		},
		"ok/templated-url": {
			webhook: Webhook{
				ID: "abc123",
				// scheme, host, port will come from test server
				URL:    "/users/{{ .username }}?region={{ .region }}",
				Secret: "c2VjcmV0Cg==",
			},
			requestID: "reqID",
			dataArg:   map[string]any{"username": "areed", "region": "central"},
			webhookResponse: webhook.ResponseBody{
				Data: map[string]any{"role": "dba"},
			},
			expectPath: "/users/areed?region=central",
		},
		/*
			"ok/token from ssh template": {
				webhook: Webhook{
					ID:     "abc123",
					Secret: "c2VjcmV0Cg==",
				},
				webhookResponse: webhook.ResponseBody{
					Data: map[string]interface{}{"role": "dba"},
				},
				dataArg:     sshutil.TemplateData{sshutil.TokenKey: "token"},
				expectToken: "token",
			},
			"ok/token from x509 template": {
				webhook: Webhook{
					ID:     "abc123",
					Secret: "c2VjcmV0Cg==",
				},
				webhookResponse: webhook.ResponseBody{
					Data: map[string]interface{}{"role": "dba"},
				},
				dataArg:     x509util.TemplateData{sshutil.TokenKey: "token"},
				expectToken: "token",
			},
		*/
		"ok/allow": {
			webhook: Webhook{
				ID:     "abc123",
				Secret: "c2VjcmV0Cg==",
			},
			requestID: "reqID",
			webhookResponse: webhook.ResponseBody{
				Allow: true,
			},
		},
		"fail/404": {
			webhook: Webhook{
				ID:     "abc123",
				Secret: "c2VjcmV0Cg==",
			},
			webhookResponse: webhook.ResponseBody{
				Data: map[string]any{"role": "dba"},
			},
			requestID:     "reqID",
			errStatusCode: 404,
			serverErrMsg:  "item not found",
			expectErr:     errors.New(`webhook "abc123" failed after 1 attempt: Webhook server responded with 404`),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.requestID != "" {
					assert.Equal(t, tc.requestID, r.Header.Get("X-Request-ID"))
				}

				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				assert.Equal(t, tc.webhook.ID, r.Header.Get("X-Smallstep-Webhook-ID"))

				sig, err := hex.DecodeString(r.Header.Get("X-Smallstep-Signature"))
				assert.NoError(t, err)

				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)

				secret, err := base64.StdEncoding.DecodeString(tc.webhook.Secret)
				assert.NoError(t, err)
				h := hmac.New(sha256.New, secret)
				h.Write(body)
				mac := h.Sum(nil)
				assert.True(t, hmac.Equal(sig, mac))

				switch {
				case tc.webhook.BearerToken != "":
					ah := fmt.Sprintf("Bearer %s", tc.webhook.BearerToken)
					assert.Equal(t, ah, r.Header.Get("Authorization"))
				case tc.webhook.BasicAuth.Username != "" || tc.webhook.BasicAuth.Password != "":
					whReq, err := http.NewRequest("", "", http.NoBody)
					require.NoError(t, err)
					whReq.SetBasicAuth(tc.webhook.BasicAuth.Username, tc.webhook.BasicAuth.Password)
					ah := whReq.Header.Get("Authorization")
					assert.Equal(t, ah, whReq.Header.Get("Authorization"))
				default:
					assert.Equal(t, "", r.Header.Get("Authorization"))
				}

				if tc.expectPath != "" {
					assert.Equal(t, tc.expectPath, r.URL.Path+"?"+r.URL.RawQuery)
				}

				if tc.errStatusCode != 0 {
					http.Error(w, tc.serverErrMsg, tc.errStatusCode)
					return
				}

				reqBody := new(webhook.RequestBody)
				err = json.Unmarshal(body, reqBody)
				require.NoError(t, err)

				err = json.NewEncoder(w).Encode(tc.webhookResponse)
				require.NoError(t, err)
			}))
			defer ts.Close()

			tc.webhook.URL = ts.URL + tc.webhook.URL

			reqBody, err := webhook.NewRequestBody(webhook.WithX509CertificateRequest(csr))
			require.NoError(t, err)

			ctx := context.Background()
			if tc.requestID != "" {
				ctx = withRequestID(t, ctx, tc.requestID)
			}
			ctx, cancel := context.WithTimeout(ctx, time.Second*10)
			defer cancel()

			got, err := tc.webhook.DoWithContext(ctx, http.DefaultClient, httptransport.NoopWrapper(), reqBody, tc.dataArg)
			if tc.expectErr != nil {
				assert.Equal(t, tc.expectErr.Error(), err.Error())
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, &tc.webhookResponse, got)
		})
	}

	t.Run("disableTLSClientAuth", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("{}"))
		}))
		ts.TLS.ClientAuth = tls.RequireAnyClientCert
		wh := Webhook{
			URL: ts.URL,
		}
		cert, err := tls.LoadX509KeyPair("testdata/certs/foo.crt", "testdata/secrets/foo.key")
		require.NoError(t, err)

		transport := httptransport.New()
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		}
		client := &http.Client{
			Transport: transport,
		}
		reqBody, err := webhook.NewRequestBody(webhook.WithX509CertificateRequest(csr))
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		_, err = wh.DoWithContext(ctx, client, httptransport.NoopWrapper(), reqBody, nil)
		require.NoError(t, err)

		ctx, cancel = context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		wh.DisableTLSClientAuth = true
		_, err = wh.DoWithContext(ctx, client, httptransport.NoopWrapper(), reqBody, nil)
		require.Error(t, err)
	})
}

func TestWebhook_Validate(t *testing.T) {
	tests := []struct {
		name      string
		webhook   *Webhook
		assertion assert.ErrorAssertionFunc
	}{
		{"ok enriching", &Webhook{Name: "devices", URL: "https://localhost:3000", Kind: "ENRICHING"}, assert.NoError},
		{"ok authorizing", &Webhook{Name: "devices", URL: "https://localhost:3000/devices", Kind: "AUTHORIZING"}, assert.NoError},
		{"fail name", &Webhook{Name: "", URL: "https://localhost:3000", Kind: "ENRICHING"}, assert.Error},
		{"fail url", &Webhook{Name: "devices", URL: "", Kind: "ENRICHING"}, assert.Error},
		{"fail bad url", &Webhook{Name: "devices", URL: "https://{{.Templated.Host}}", Kind: "ENRICHING"}, assert.Error},
		{"fail host", &Webhook{Name: "devices", URL: "https:opaque", Kind: "ENRICHING"}, assert.Error},
		{"fail scheme", &Webhook{Name: "devices", URL: "http://localhost", Kind: "ENRICHING"}, assert.Error},
		{"fail user", &Webhook{Name: "devices", URL: "https://user:pass@localhost", Kind: "ENRICHING"}, assert.Error},
		{"fail kind", &Webhook{Name: "devices", URL: "https://localhost:3000", Kind: ""}, assert.Error},
		{"fail bad kind", &Webhook{Name: "devices", URL: "https://localhost:3000", Kind: "SOMETHING"}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.webhook.Validate())
		})
	}
}

func TestWebhook_Validate_retryConfig(t *testing.T) {
	base := func() *Webhook {
		return &Webhook{Name: "devices", URL: "https://localhost:3000", Kind: "ENRICHING"}
	}
	tests := []struct {
		name      string
		mutate    func(w *Webhook)
		assertion assert.ErrorAssertionFunc
	}{
		{"ok zero defaults", func(w *Webhook) {}, assert.NoError},
		{"ok max retries", func(w *Webhook) { w.MaxRetries = maxMaxRetries }, assert.NoError},
		{"ok backoff", func(w *Webhook) { w.RetryBackoff = &Duration{Duration: 250 * time.Millisecond} }, assert.NoError},
		{"ok max backoff", func(w *Webhook) { w.RetryBackoff = &Duration{Duration: maxRetryBackoff} }, assert.NoError},
		{"fail negative retries", func(w *Webhook) { w.MaxRetries = -1 }, assert.Error},
		{"fail retries over cap", func(w *Webhook) { w.MaxRetries = maxMaxRetries + 1 }, assert.Error},
		{"fail negative backoff", func(w *Webhook) { w.RetryBackoff = &Duration{Duration: -time.Second} }, assert.Error},
		{"fail backoff over cap", func(w *Webhook) { w.RetryBackoff = &Duration{Duration: maxRetryBackoff + time.Second} }, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := base()
			tt.mutate(w)
			tt.assertion(t, w.Validate())
		})
	}
}

func TestWebhook_retryConfigNormalization(t *testing.T) {
	tests := []struct {
		name        string
		maxRetries  int
		backoff     *Duration
		wantRetries int
		wantBackoff time.Duration
	}{
		{"defaults", 0, nil, defaultMaxRetries, defaultRetryBackoff},
		{"configured", 3, &Duration{Duration: 250 * time.Millisecond}, 3, 250 * time.Millisecond},
		{"retries capped", maxMaxRetries + 50, nil, maxMaxRetries, defaultRetryBackoff},
		{"negative retries defaults", -5, nil, defaultMaxRetries, defaultRetryBackoff},
		{"backoff capped", 0, &Duration{Duration: maxRetryBackoff + time.Hour}, defaultMaxRetries, maxRetryBackoff},
		{"zero/negative backoff defaults", 0, &Duration{Duration: 0}, defaultMaxRetries, defaultRetryBackoff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &Webhook{MaxRetries: tt.maxRetries, RetryBackoff: tt.backoff}
			assert.Equal(t, tt.wantRetries, w.retries())
			assert.Equal(t, tt.wantBackoff, w.backoff())
		})
	}
}

func TestWebhook_JSONConfig(t *testing.T) {
	// Old configuration fields (address template, kind, cert type) keep
	// working and the new retry fields are picked up from the same document.
	var w Webhook
	err := json.Unmarshal([]byte(`{
		"id": "abc123",
		"name": "people",
		"url": "https://localhost:3000/users/{{ .username }}",
		"kind": "ENRICHING",
		"certType": "ALL",
		"maxRetries": 3,
		"retryBackoff": "250ms"
	}`), &w)
	require.NoError(t, err)
	assert.Equal(t, "people", w.Name)
	assert.Equal(t, 3, w.MaxRetries)
	require.NotNil(t, w.RetryBackoff)
	assert.Equal(t, 250*time.Millisecond, w.RetryBackoff.Duration)
	assert.NoError(t, w.Validate())

	// A document without the new fields stays valid and gets the defaults.
	var old Webhook
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "people",
		"url": "https://localhost:3000",
		"kind": "AUTHORIZING"
	}`), &old))
	assert.NoError(t, old.Validate())
	assert.Equal(t, defaultMaxRetries, old.retries())
	assert.Equal(t, defaultRetryBackoff, old.backoff())
}

func TestWebhookError(t *testing.T) {
	err := &WebhookError{Name: "people", Attempts: 2, Err: io.EOF}
	assert.Equal(t, `webhook "people" failed after 2 attempts: EOF`, err.Error())
	assert.True(t, errors.Is(err, io.EOF))

	// The webhook ID is reported when the name is empty.
	err = &WebhookError{ID: "abc123", Attempts: 1, Err: http.ErrServerClosed}
	assert.Equal(t, `webhook "abc123" failed after 1 attempt: http: Server closed`, err.Error())

	var target *WebhookError
	assert.True(t, errors.As(fmt.Errorf("outer: %w", err), &target))
	assert.Equal(t, "abc123", target.ID)
}

// newRetryTestWebhook returns a webhook pointing at the given test server with
// a short backoff so retry tests don't have to wait for the default delay.
func newRetryTestWebhook(t *testing.T, name, url string, wh *Webhook) *Webhook {
	t.Helper()
	if wh == nil {
		wh = &Webhook{}
	}
	wh.ID = "webhook-id-" + name
	wh.Name = name
	wh.URL = url
	wh.Secret = "c2VjcmV0Cg=="
	if wh.RetryBackoff == nil {
		wh.RetryBackoff = &Duration{Duration: 10 * time.Millisecond}
	}
	return wh
}

func doTestRequest(t *testing.T, wh *Webhook, ctx context.Context) (*webhook.ResponseBody, error) {
	t.Helper()
	reqBody, err := webhook.NewRequestBody(webhook.WithX509CertificateRequest(parseCertificateRequest(t, "testdata/certs/ecdsa.csr")))
	require.NoError(t, err)
	if ctx == nil {
		ctx = context.Background()
	}
	return wh.DoWithContext(ctx, http.DefaultClient, httptransport.NoopWrapper(), reqBody, nil)
}

func assertWebhookError(t *testing.T, err error, name string, attempts int, causeContains string) *WebhookError {
	t.Helper()
	var whErr *WebhookError
	require.True(t, errors.As(err, &whErr), "expected *WebhookError, got %T: %v", err, err)
	assert.Equal(t, name, whErr.Name)
	assert.Equal(t, attempts, whErr.Attempts)
	if causeContains != "" {
		require.Error(t, whErr.Err)
		assert.Contains(t, whErr.Err.Error(), causeContains)
	}
	return whErr
}

func TestWebhook_DoWithContext_serverFailures(t *testing.T) {
	t.Run("5xx retries once by default then stops with webhook identity", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer ts.Close()

		// MaxRetries left at zero: defaults to one retry, i.e. two attempts.
		wh := newRetryTestWebhook(t, "people", ts.URL, nil)
		start := time.Now()
		_, err := doTestRequest(t, wh, nil)
		assert.Less(t, time.Since(start), time.Second, "should use the configured short backoff")
		assert.Equal(t, int64(2), hits.Load())
		assertWebhookError(t, err, "people", 2, "Webhook server responded with 500")
	})

	t.Run("5xx stops after the configured number of attempts", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "boom", http.StatusBadGateway)
		}))
		defer ts.Close()

		wh := newRetryTestWebhook(t, "devices", ts.URL, &Webhook{MaxRetries: 2})
		_, err := doTestRequest(t, wh, nil)
		assert.Equal(t, int64(3), hits.Load())
		assertWebhookError(t, err, "devices", 3, "Webhook server responded with 502")
	})

	t.Run("429 is retried and a later success wins", func(t *testing.T) {
		var (
			hits       atomic.Int64
			signatures []string
			mu         sync.Mutex
		)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			mu.Lock()
			signatures = append(signatures, r.Header.Get("X-Smallstep-Signature"))
			mu.Unlock()
			if hits.Load() == 1 {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":{"role":"dba"},"allow":true}`)
		}))
		defer ts.Close()

		wh := newRetryTestWebhook(t, "people", ts.URL, nil)
		resp, err := doTestRequest(t, wh, nil)
		require.NoError(t, err)
		assert.Equal(t, int64(2), hits.Load())
		assert.Equal(t, map[string]any{"role": "dba"}, resp.Data)

		// The signed request is sent verbatim on every attempt.
		mu.Lock()
		require.Len(t, signatures, 2)
		assert.Equal(t, signatures[0], signatures[1])
		mu.Unlock()
	})

	t.Run("4xx request error is not retried", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer ts.Close()

		wh := newRetryTestWebhook(t, "people", ts.URL, &Webhook{MaxRetries: 5})
		_, err := doTestRequest(t, wh, nil)
		assert.Equal(t, int64(1), hits.Load())
		assertWebhookError(t, err, "people", 1, "Webhook server responded with 404")
	})

	t.Run("connection error is retried", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ts.Close() // nothing is listening anymore

		wh := newRetryTestWebhook(t, "people", ts.URL, nil)
		_, err := doTestRequest(t, wh, nil)
		assertWebhookError(t, err, "people", 2, "")
	})
}

func TestWebhook_DoWithContext_responseSizeLimit(t *testing.T) {
	t.Run("response larger than the limit fails and is not retried", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(bytes.Repeat([]byte("a"), int(maxResponseBodySize)+1))
			assert.NoError(t, err)
		}))
		defer ts.Close()

		wh := newRetryTestWebhook(t, "people", ts.URL, &Webhook{MaxRetries: 5})
		_, err := doTestRequest(t, wh, nil)
		assert.Equal(t, int64(1), hits.Load(), "oversized responses must not be retried")
		assertWebhookError(t, err, "people", 1, "exceeds the maximum size")
	})

	t.Run("response exactly at the limit is accepted", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			prefix := []byte(`{"data":{"role":"dba"}`)
			suffix := []byte("}")
			padding := int(maxResponseBodySize) - len(prefix) - len(suffix)
			require.Greater(t, padding, 0)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(prefix)
			assert.NoError(t, err)
			_, err = w.Write(bytes.Repeat([]byte(" "), padding))
			assert.NoError(t, err)
			_, err = w.Write(suffix)
			assert.NoError(t, err)
		}))
		defer ts.Close()

		wh := newRetryTestWebhook(t, "people", ts.URL, nil)
		resp, err := doTestRequest(t, wh, nil)
		require.NoError(t, err)
		assert.Equal(t, int64(1), hits.Load())
		assert.Equal(t, map[string]any{"role": "dba"}, resp.Data)
	})

	t.Run("malformed json is not retried", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			fmt.Fprint(w, "not-json")
		}))
		defer ts.Close()

		wh := newRetryTestWebhook(t, "people", ts.URL, &Webhook{MaxRetries: 3})
		_, err := doTestRequest(t, wh, nil)
		assert.Equal(t, int64(1), hits.Load())
		assertWebhookError(t, err, "people", 1, "")
	})
}

func TestWebhook_DoWithContext_cancellation(t *testing.T) {
	t.Run("canceled in-flight request is not attempted again", func(t *testing.T) {
		var hits atomic.Int64
		release := make(chan struct{})
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			// Block until the test releases the handler. The client cancels
			// while the response is still in flight.
			<-release
			http.Error(w, "boom", http.StatusInternalServerError)
		}))

		wh := newRetryTestWebhook(t, "people", ts.URL, &Webhook{MaxRetries: 5})
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		_, err := doTestRequest(t, wh, ctx)
		assert.Less(t, time.Since(start), 2*time.Second, "must return immediately on cancellation")
		assert.Equal(t, int64(1), hits.Load(), "no second attempt after cancellation")
		whErr := assertWebhookError(t, err, "people", 1, "")
		assert.True(t, errors.Is(whErr, context.Canceled), "expected context.Canceled in error chain, got %v", err)

		// Let the blocked handler finish so the test server can shut down.
		close(release)
		ts.Close()
	})

	t.Run("cancellation interrupts the backoff without another attempt", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer ts.Close()

		// Configure a long backoff so sleeping through it would blow the test
		// timeout if it weren't interruptible.
		wh := newRetryTestWebhook(t, "people", ts.URL, &Webhook{MaxRetries: 5, RetryBackoff: &Duration{Duration: 10 * time.Second}})
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		_, err := doTestRequest(t, wh, ctx)
		assert.Less(t, time.Since(start), 2*time.Second, "backoff wait must be interrupted")
		assert.Equal(t, int64(1), hits.Load(), "must not retry after cancellation during backoff")
		whErr := assertWebhookError(t, err, "people", 1, "")
		assert.True(t, errors.Is(whErr, context.Canceled), "expected context.Canceled in error chain, got %v", err)
	})

	t.Run("already canceled context performs no attempt", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
		}))
		defer ts.Close()

		wh := newRetryTestWebhook(t, "people", ts.URL, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := doTestRequest(t, wh, ctx)
		assert.Equal(t, int64(0), hits.Load())
		assertWebhookError(t, err, "people", 0, "")
	})
}

func TestWebhookController_chain(t *testing.T) {
	csrReq, err := webhook.NewRequestBody(webhook.WithX509CertificateRequest(parseCertificateRequest(t, "testdata/certs/ecdsa.csr")))
	require.NoError(t, err)

	t.Run("enrich attributes the failing webhook and keeps earlier data", func(t *testing.T) {
		var firstHits, secondHits atomic.Int64
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			firstHits.Add(1)
			fmt.Fprint(w, `{"data":{"role":"bar"},"allow":true}`)
		}))
		defer first.Close()
		second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secondHits.Add(1)
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer second.Close()

		data := x509util.TemplateData{}
		wc := &WebhookController{
			client:        http.DefaultClient,
			wrapTransport: httptransport.NoopWrapper(),
			TemplateData:  data,
			webhooks: []*Webhook{
				newRetryTestWebhook(t, "first", first.URL, nil),
				newRetryTestWebhook(t, "second", second.URL, nil),
			},
		}
		for _, wh := range wc.webhooks {
			wh.Kind = linkedca.Webhook_ENRICHING.String()
		}

		err := wc.Enrich(context.Background(), csrReq)
		assertWebhookError(t, err, "second", 2, "500")
		assert.Equal(t, int64(1), firstHits.Load())
		assert.Equal(t, int64(2), secondHits.Load())
		// Earlier successful enrichment is still written back by name.
		assert.Equal(t, x509util.TemplateData{"Webhooks": map[string]any{
			"first": map[string]any{"role": "bar"},
		}}, data)
	})

	t.Run("authorize passes only when every webhook allows", func(t *testing.T) {
		var firstHits, secondHits atomic.Int64
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			firstHits.Add(1)
			fmt.Fprint(w, `{"allow":true}`)
		}))
		defer first.Close()
		second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secondHits.Add(1)
			fmt.Fprint(w, `{"allow":true}`)
		}))
		defer second.Close()

		wc := &WebhookController{
			client:        http.DefaultClient,
			wrapTransport: httptransport.NoopWrapper(),
			webhooks: []*Webhook{
				newRetryTestWebhook(t, "first", first.URL, nil),
				newRetryTestWebhook(t, "second", second.URL, nil),
			},
		}
		for _, wh := range wc.webhooks {
			wh.Kind = linkedca.Webhook_AUTHORIZING.String()
		}
		assert.NoError(t, wc.Authorize(context.Background(), csrReq))
		assert.Equal(t, int64(1), firstHits.Load())
		assert.Equal(t, int64(1), secondHits.Load())
	})

	t.Run("authorize returns immediately on the first denial", func(t *testing.T) {
		var firstHits, secondHits atomic.Int64
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			firstHits.Add(1)
			fmt.Fprint(w, `{"allow":false}`)
		}))
		defer first.Close()
		second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secondHits.Add(1)
			fmt.Fprint(w, `{"allow":true}`)
		}))
		defer second.Close()

		wc := &WebhookController{
			client:        http.DefaultClient,
			wrapTransport: httptransport.NoopWrapper(),
			webhooks: []*Webhook{
				newRetryTestWebhook(t, "first", first.URL, nil),
				newRetryTestWebhook(t, "second", second.URL, nil),
			},
		}
		for _, wh := range wc.webhooks {
			wh.Kind = linkedca.Webhook_AUTHORIZING.String()
		}
		err := wc.Authorize(context.Background(), csrReq)
		assert.Equal(t, ErrWebhookDenied, err)
		assert.Equal(t, int64(1), firstHits.Load())
		assert.Equal(t, int64(0), secondHits.Load(), "later webhooks must not be called after a denial")
	})
}
