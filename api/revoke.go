package api

import (
	"math/big"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
)

// RevokeResponse is the response object that returns the health of the server.
//
// RevokedAt, ReasonCode and Source are only included when the certificate was
// already revoked by an earlier request. They report the information stored
// by the first revocation, allowing clients to tell a repeated revocation of
// their own apart from a certificate that was revoked through another entry.
// A first revocation keeps returning just {"status":"ok"}.
type RevokeResponse struct {
	Status string `json:"status"`

	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	ReasonCode *int       `json:"reasonCode,omitempty"`
	Source     string     `json:"source,omitempty"`
}

// RevokeRequest is the request body for a revocation request.
type RevokeRequest struct {
	Serial     string `json:"serial"`
	OTT        string `json:"ott"`
	ReasonCode int    `json:"reasonCode"`
	Reason     string `json:"reason"`
	Passive    bool   `json:"passive"`
}

// Validate checks the fields of the RevokeRequest and returns nil if they are ok
// or an error if something is wrong.
func (r *RevokeRequest) Validate() (err error) {
	if r.Serial == "" {
		return errs.BadRequest("missing serial")
	}
	sn, ok := new(big.Int).SetString(r.Serial, 0)
	if !ok {
		return errs.BadRequest("'%s' is not a valid serial number - use a base 10 representation or a base 16 representation with '0x' prefix", r.Serial)
	}
	r.Serial = sn.String()
	if r.ReasonCode < ocsp.Unspecified || r.ReasonCode > ocsp.AACompromise {
		return errs.BadRequest("reasonCode out of bounds")
	}
	if !r.Passive {
		return errs.NotImplemented("non-passive revocation not implemented")
	}

	return
}

// Revoke supports handful of different methods that revoke a Certificate.
//
// NOTE: currently only Passive revocation is supported.
//
// TODO: Add CRL and OCSP support.
func Revoke(w http.ResponseWriter, r *http.Request) {
	var body RevokeRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, r, errs.BadRequestErr(err, "error reading request body"))
		return
	}

	if err := body.Validate(); err != nil {
		render.Error(w, r, err)
		return
	}

	opts := &authority.RevokeOptions{
		Serial:      body.Serial,
		Reason:      body.Reason,
		ReasonCode:  body.ReasonCode,
		PassiveOnly: body.Passive,
	}

	ctx := provisioner.NewContextWithMethod(r.Context(), provisioner.RevokeMethod)
	a := mustAuthority(ctx)

	// A token indicates that we are using the api via a provisioner token,
	// otherwise it is assumed that the certificate is revoking itself over mTLS.
	if body.OTT != "" {
		logOtt(w, body.OTT)
		if _, err := a.Authorize(ctx, body.OTT); err != nil {
			render.Error(w, r, errs.UnauthorizedErr(err))
			return
		}
		opts.OTT = body.OTT
		opts.Source = authority.RevocationSourceToken
	} else {
		// If no token is present, then the request must be made over mTLS and
		// the client certificate Serial Number must match the serial number
		// being revoked.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			render.Error(w, r, errs.BadRequest("missing ott or client certificate"))
			return
		}
		opts.Crt = r.TLS.PeerCertificates[0]
		if serialNumber := opts.Crt.SerialNumber.String(); opts.Serial != serialNumber {
			render.Error(w, r, errs.Forbidden(
				"request serial number %q and certificate serial number %q do not match", opts.Serial, serialNumber))
			return
		}
		// TODO: should probably be checking if the certificate was revoked here.
		// Will need to thread that request down to the authority, so will need
		// to add API for that.
		LogCertificate(w, opts.Crt)
		opts.MTLS = true
		opts.Source = authority.RevocationSourceMTLS
	}

	rci, alreadyRevoked, err := a.Revoke(ctx, opts)
	if err != nil {
		render.Error(w, r, errs.ForbiddenErr(err, "error revoking certificate"))
		return
	}

	logRevoke(w, opts)

	// A first revocation returns the same body as before. A repeated
	// revocation succeeds too, but reports the information stored by the
	// first revocation so the client can see who revoked the certificate
	// first and with which reason code.
	resp := &RevokeResponse{Status: "ok"}
	if alreadyRevoked && rci != nil {
		revokedAt := rci.RevokedAt
		reasonCode := rci.ReasonCode
		resp.RevokedAt = &revokedAt
		resp.ReasonCode = &reasonCode
		resp.Source = rci.Source
	}
	render.JSON(w, r, resp)
}

func logRevoke(w http.ResponseWriter, ri *authority.RevokeOptions) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]any{
			"serial":      ri.Serial,
			"reasonCode":  ri.ReasonCode,
			"reason":      ri.Reason,
			"passiveOnly": ri.PassiveOnly,
			"mTLS":        ri.MTLS,
		})
	}
}
