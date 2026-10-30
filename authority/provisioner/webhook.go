package provisioner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/pkg/errors"

	"github.com/smallstep/linkedca"

	"github.com/smallstep/certificates/authority/poolhttp"
	"github.com/smallstep/certificates/internal/httptransport"
	"github.com/smallstep/certificates/middleware/requestid"
	"github.com/smallstep/certificates/templates"
	"github.com/smallstep/certificates/webhook"
)

var ErrWebhookDenied = errors.New("webhook server did not allow request")

// Retry and timeout limits for webhook requests.
const (
	// webhookTimeout is the maximum duration of a single call to a webhook,
	// including all of its retries.
	webhookTimeout = 10 * time.Second

	// defaultMaxRetries is the number of retries performed for a webhook when
	// MaxRetries is not configured. It preserves the historical behavior of a
	// single retry.
	defaultMaxRetries = 1
	// maxMaxRetries is the upper bound on the number of retries that can be
	// configured for a webhook.
	maxMaxRetries = 5

	// defaultRetryBackoff is the duration waited between webhook attempts when
	// RetryBackoff is not configured. It preserves the historical behavior of
	// sleeping one second between attempts.
	defaultRetryBackoff = time.Second
	// maxRetryBackoff is the upper bound on the backoff duration that can be
	// configured for a webhook.
	maxRetryBackoff = 30 * time.Second

	// maxResponseBodySize is the maximum number of bytes read from a webhook
	// response body (1 MiB). Responses larger than this are treated as a
	// failure instead of being silently truncated.
	maxResponseBodySize int64 = 1 << 20
)

type WebhookSetter interface {
	SetWebhook(string, any)
}

// WebhookError is returned when a request to a webhook fails. It carries the
// webhook identifier, the number of attempts performed and the last error
// encountered, so that failures of different webhooks in a chain can be
// attributed. The last error can be unwrapped, keeping errors.Is and
// errors.As working (e.g. for context.Canceled).
type WebhookError struct {
	// Name is the configured name of the webhook.
	Name string
	// ID is the configured identifier of the webhook.
	ID string
	// Attempts is the number of HTTP attempts performed. It is zero when the
	// request could not be prepared (e.g. an invalid secret).
	Attempts int
	// Err is the error of the last attempt.
	Err error
}

func (e *WebhookError) Error() string {
	id := e.Name
	if id == "" {
		id = e.ID
	}
	if id == "" {
		id = "(unnamed)"
	}
	return fmt.Sprintf("webhook %q failed after %s: %s", id, attemptWord(e.Attempts), e.Err)
}

func (e *WebhookError) Unwrap() error {
	return e.Err
}

func attemptWord(attempts int) string {
	if attempts == 1 {
		return "1 attempt"
	}
	return fmt.Sprintf("%d attempts", attempts)
}

type WebhookController struct {
	client        HTTPClient
	wrapTransport httptransport.Wrapper
	webhooks      []*Webhook
	certType      linkedca.Webhook_CertType
	options       []webhook.RequestBodyOption
	TemplateData  WebhookSetter
}

// Enrich fetches data from remote servers and adds returned data to the
// templateData
func (wc *WebhookController) Enrich(ctx context.Context, req *webhook.RequestBody) error {
	if wc == nil {
		return nil
	}

	// Apply extra options in the webhook controller
	for _, fn := range wc.options {
		if err := fn(req); err != nil {
			return err
		}
	}

	for _, wh := range wc.webhooks {
		if wh.Kind != linkedca.Webhook_ENRICHING.String() {
			continue
		}
		if !wc.isCertTypeOK(wh) {
			continue
		}

		whCtx, cancel := context.WithTimeout(ctx, webhookTimeout)
		resp, err := wh.DoWithContext(whCtx, wc.client, wc.wrapTransport, req, wc.TemplateData)
		cancel()
		if err != nil {
			return err
		}
		if !resp.Allow {
			if resp.Error != nil {
				return resp.Error
			}
			return ErrWebhookDenied
		}
		wc.TemplateData.SetWebhook(wh.Name, resp.Data)
	}
	return nil
}

// Authorize checks that all remote servers allow the request
func (wc *WebhookController) Authorize(ctx context.Context, req *webhook.RequestBody) error {
	if wc == nil {
		return nil
	}

	// Apply extra options in the webhook controller
	for _, fn := range wc.options {
		if err := fn(req); err != nil {
			return err
		}
	}

	for _, wh := range wc.webhooks {
		if wh.Kind != linkedca.Webhook_AUTHORIZING.String() {
			continue
		}
		if !wc.isCertTypeOK(wh) {
			continue
		}

		whCtx, cancel := context.WithTimeout(ctx, webhookTimeout)
		resp, err := wh.DoWithContext(whCtx, wc.client, wc.wrapTransport, req, wc.TemplateData)
		cancel()
		if err != nil {
			return err
		}
		if !resp.Allow {
			if resp.Error != nil {
				return resp.Error
			}
			return ErrWebhookDenied
		}
	}
	return nil
}

func (wc *WebhookController) isCertTypeOK(wh *Webhook) bool {
	if wc.certType == linkedca.Webhook_ALL {
		return true
	}
	if wh.CertType == linkedca.Webhook_ALL.String() || wh.CertType == "" {
		return true
	}
	return wc.certType.String() == wh.CertType
}

type Webhook struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	URL                  string `json:"url"`
	Kind                 string `json:"kind"`
	DisableTLSClientAuth bool   `json:"disableTLSClientAuth,omitempty"`
	CertType             string `json:"certType"`
	Secret               string `json:"-"`
	BearerToken          string `json:"-"`
	BasicAuth            struct {
		Username string
		Password string
	} `json:"-"`

	// MaxRetries is the maximum number of additional requests performed after
	// the first one when a retryable failure (connection error, 5xx response
	// or 429 response) occurs. When zero it defaults to defaultMaxRetries.
	// Values above maxMaxRetries are rejected by Validate and capped at
	// execution time. Each webhook in a chain keeps its own counter.
	MaxRetries int `json:"maxRetries,omitempty"`

	// RetryBackoff is the fixed duration waited between attempts. When nil it
	// defaults to defaultRetryBackoff. Values above maxRetryBackoff are
	// rejected by Validate and capped at execution time. The wait is
	// interrupted when the request context is canceled.
	RetryBackoff *Duration `json:"retryBackoff,omitempty"`
}

// retries returns the normalized number of retries for the webhook.
func (w *Webhook) retries() int {
	switch {
	case w.MaxRetries <= 0:
		return defaultMaxRetries
	case w.MaxRetries > maxMaxRetries:
		return maxMaxRetries
	default:
		return w.MaxRetries
	}
}

// backoff returns the normalized backoff duration for the webhook.
func (w *Webhook) backoff() time.Duration {
	d := defaultRetryBackoff
	if w.RetryBackoff != nil && w.RetryBackoff.Duration > 0 {
		d = w.RetryBackoff.Duration
	}
	if d > maxRetryBackoff {
		return maxRetryBackoff
	}
	return d
}

// errorf wraps err in a WebhookError attributed to the webhook.
func (w *Webhook) errorf(attempts int, err error) error {
	if err == nil {
		return nil
	}
	return &WebhookError{
		Name:     w.Name,
		ID:       w.ID,
		Attempts: attempts,
		Err:      err,
	}
}

// Validate validates a webhook, only name, url and kind are required.
func (w *Webhook) Validate() error {
	if w == nil {
		return nil
	}

	// name
	if w.Name == "" {
		return errors.New("webhook name is required")
	}

	// url
	parsedURL, err := url.Parse(w.URL)
	if err != nil {
		return errors.New("webhook url is invalid")
	}
	if parsedURL.Host == "" {
		return errors.New("webhook url is invalid")
	}
	if parsedURL.Scheme != "https" {
		return errors.New("webhook url must use https")
	}
	if parsedURL.User != nil {
		return errors.New("webhook url may not contain username or password")
	}

	// kind
	if w.Kind == "" {
		return errors.New("webhook kind is required")
	}
	w.Kind = strings.ToUpper(w.Kind)
	kind, ok := linkedca.Webhook_Kind_value[w.Kind]
	if !ok || kind == 0 {
		return errors.New("webhook kind is invalid")
	}

	// retries
	if w.MaxRetries < 0 {
		return errors.New("webhook maxRetries cannot be negative")
	}
	if w.MaxRetries > maxMaxRetries {
		return errors.Errorf("webhook maxRetries must be at most %d", maxMaxRetries)
	}
	if w.RetryBackoff != nil {
		if w.RetryBackoff.Duration < 0 {
			return errors.New("webhook retryBackoff cannot be negative")
		}
		if w.RetryBackoff.Duration > maxRetryBackoff {
			return errors.Errorf("webhook retryBackoff must be at most %s", maxRetryBackoff)
		}
	}

	return nil
}

// TransportWrapper wraps the set of functions mapping [http.Transport] references to
// [http.RoundTripper].
type TransportWrapper = httptransport.Wrapper

func (w *Webhook) DoWithContext(ctx context.Context, client HTTPClient, tw TransportWrapper, reqBody *webhook.RequestBody, data any) (*webhook.ResponseBody, error) {
	tmpl, err := template.New("url").Funcs(templates.StepFuncMap()).Parse(w.URL)
	if err != nil {
		return nil, w.errorf(0, err)
	}
	buf := &bytes.Buffer{}
	if err := tmpl.Execute(buf, data); err != nil {
		return nil, w.errorf(0, err)
	}
	webhookURL := buf.String()

	/*
		Sending the token to the webhook server is a security risk. A K8sSA
		token can be reused multiple times. The webhook can misuse it to get
		fake certificates. A webhook can misuse any other token to get its own
		certificate before responding.
		switch tmpl := data.(type) {
		case x509util.TemplateData:
			reqBody.Token = tmpl[x509util.TokenKey]
		case sshutil.TemplateData:
			reqBody.Token = tmpl[sshutil.TokenKey]
		}
	*/

	reqBody.Timestamp = time.Now()

	// The request body and its signature are computed once and sent verbatim
	// on every attempt.
	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, w.errorf(0, err)
	}

	// An invalid signature secret is a configuration error; retrying will
	// not fix it, so fail before any attempt is made.
	secret, err := base64.StdEncoding.DecodeString(w.Secret)
	if err != nil {
		return nil, w.errorf(0, err)
	}
	sig := hmac.New(sha256.New, secret)
	sig.Write(reqBytes)
	signature := hex.EncodeToString(sig.Sum(nil))

	if w.DisableTLSClientAuth {
		var transport *http.Transport
		if ct, ok := client.(poolhttp.Transporter); ok {
			transport = ct.Transport()
		} else {
			transport = httptransport.New()
		}

		if transport.TLSClientConfig != nil {
			transport.TLSClientConfig.GetClientCertificate = nil
			transport.TLSClientConfig.Certificates = nil
		}

		client = &http.Client{
			Transport: tw(transport),
		}
	}

	maxAttempts := w.retries() + 1
	backoff := w.backoff()

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Do not start a new attempt when the caller already canceled the
		// request or its deadline passed.
		if err := ctx.Err(); err != nil {
			return nil, w.errorf(attempt-1, err)
		}

		respBody, retryable, err := w.doRequest(ctx, client, webhookURL, reqBytes, signature)
		if err == nil {
			return respBody, nil
		}
		lastErr = err

		// A request error (4xx), a context cancellation, an oversized or
		// invalid response, or an exhausted retry budget is not retried.
		if !retryable || attempt == maxAttempts {
			return nil, w.errorf(attempt, err)
		}

		// Wait for the fixed backoff, but return as soon as the context is
		// canceled instead of sleeping through the whole delay.
		select {
		case <-ctx.Done():
			return nil, w.errorf(attempt, ctx.Err())
		case <-time.After(backoff):
		}
	}

	return nil, w.errorf(maxAttempts, lastErr)
}

// doRequest performs a single POST to the webhook. It returns the parsed
// response and, on failure, whether performing another attempt makes sense.
// Only connection/transport errors, 5xx responses and 429 responses are
// retryable; request errors, signature failures, context cancellations,
// oversized and invalid responses are not.
func (w *Webhook) doRequest(ctx context.Context, client HTTPClient, webhookURL string, reqBytes []byte, signature string) (*webhook.ResponseBody, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, false, err
	}

	req.Header.Set("Content-Type", "application/json")

	if requestID, ok := requestid.FromContext(ctx); ok {
		req.Header.Set("X-Request-Id", requestID)
	}

	req.Header.Set("X-Smallstep-Signature", signature)
	req.Header.Set("X-Smallstep-Webhook-ID", w.ID)

	if w.BearerToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.BearerToken))
	} else if w.BasicAuth.Username != "" || w.BasicAuth.Password != "" {
		req.SetBasicAuth(w.BasicAuth.Username, w.BasicAuth.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Caller cancellation or an expired context must return immediately
		// and never trigger another attempt.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, false, err
		}
		// Any other transport failure is a connection class error, which is
		// worth retrying.
		return nil, true, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close body of response from %s", w.URL)
		}
	}()

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		// Rate limited; the request may succeed after backing off.
		return nil, true, fmt.Errorf("Webhook server responded with %d", resp.StatusCode)
	case resp.StatusCode >= 500:
		// Server error; retrying may help.
		return nil, true, fmt.Errorf("Webhook server responded with %d", resp.StatusCode)
	case resp.StatusCode >= 400:
		// Client/request error (e.g. 400, 401 after signature verification
		// failure, 403, 404); retrying will not change the outcome.
		return nil, false, fmt.Errorf("Webhook server responded with %d", resp.StatusCode)
	}

	// Read at most one byte more than the allowed size so that an oversized
	// body can be detected instead of being silently truncated into a valid
	// response.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		// A failure while reading the body is a connection class error.
		return nil, true, err
	}
	if int64(len(body)) > maxResponseBodySize {
		return nil, false, fmt.Errorf("webhook response body exceeds the maximum size of %d bytes", maxResponseBodySize)
	}

	respBody := &webhook.ResponseBody{}
	if err := json.Unmarshal(body, respBody); err != nil {
		return nil, false, err
	}

	return respBody, false, nil
}
