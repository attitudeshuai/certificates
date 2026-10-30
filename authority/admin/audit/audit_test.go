package audit

import (
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/linkedca"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSnapshot_redactsSecrets(t *testing.T) {
	wh := &linkedca.Webhook{
		Id:     "wh-id",
		Name:   "my-webhook",
		Url:    "https://example.com/hook",
		Kind:   linkedca.Webhook_ENRICHING,
		Secret: "super-secret-value",
		Auth: &linkedca.Webhook_BearerToken{
			BearerToken: &linkedca.BearerToken{BearerToken: "tok-plaintext"},
		},
	}
	m, err := Snapshot(wh)
	assert.FatalError(t, err)
	assert.Equals(t, "my-webhook", m["name"])
	assert.Equals(t, Redacted, m["secret"])
	// "bearerToken" matches the secret denylist, so its entire subtree is
	// replaced with the redaction marker instead of being traversed.
	assert.Equals(t, Redacted, m["bearerToken"])

	// A regular map with nested and array credentials.
	in := map[string]any{
		"name": "p",
		"basicAuth": map[string]any{
			"username": "u",
			"password": "p@ss",
		},
		"webhooks": []any{
			map[string]any{"kind": "ENRICHING", "token": "abc"},
		},
	}
	out := Sanitize(in)
	assert.Equals(t, Redacted, out["basicAuth"].(map[string]any)["password"])
	assert.Equals(t, "u", out["basicAuth"].(map[string]any)["username"])
	assert.Equals(t, Redacted, out["webhooks"].([]any)[0].(map[string]any)["token"])
}

func TestJSONSnapshot_empty(t *testing.T) {
	m, err := JSONSnapshot(nil)
	assert.FatalError(t, err)
	assert.Nil(t, m)
	m, err = JSONSnapshot([]byte("  null "))
	assert.FatalError(t, err)
	assert.Nil(t, m)

	_, err = JSONSnapshot([]byte("{not-json"))
	assert.NotNil(t, err)
}

func TestBuildDiff(t *testing.T) {
	t.Run("create carries after snapshot", func(t *testing.T) {
		after := map[string]any{"id": "p1", "name": "foo"}
		d := BuildDiff(CreateAction, nil, after, "created provisioner foo")
		assert.Equals(t, "created provisioner foo", d.Summary)
		assert.Nil(t, d.Before)
		assert.Equals(t, "foo", d.After["name"])
	})

	t.Run("delete carries before snapshot", func(t *testing.T) {
		before := map[string]any{"id": "p1", "name": "foo"}
		d := BuildDiff(DeleteAction, before, nil, "deleted provisioner foo")
		assert.Equals(t, "foo", d.Before["name"])
		assert.Nil(t, d.After)
	})

	t.Run("update lists changed fields", func(t *testing.T) {
		before := map[string]any{
			"name": "foo",
			"claims": map[string]any{
				"x509": map[string]any{"maxTLSCertDuration": "1h"},
			},
			"tags": []any{"a"},
		}
		after := map[string]any{
			"name": "foo",
			"claims": map[string]any{
				"x509": map[string]any{"maxTLSCertDuration": "2h"},
			},
			"tags": []any{"a", "b"},
		}
		d := BuildDiff(UpdateAction, before, after, "")
		changes := map[string]Change{}
		for _, c := range d.Changes {
			changes[c.Field] = c
		}
		c, ok := changes["claims.x509.maxTLSCertDuration"]
		assert.Fatal(t, ok, "expected nested claims change")
		assert.Equals(t, "1h", c.Before)
		assert.Equals(t, "2h", c.After)

		c, ok = changes["tags"]
		assert.Fatal(t, ok, "expected tags slice change")
		assert.NotNil(t, c.After)

		_, ok = changes["name"]
		assert.Equals(t, false, ok)
		assert.Nil(t, d.Before)
		assert.Nil(t, d.After)
	})
}

func TestViewOf_unknownForLegacyRecords(t *testing.T) {
	rec := &Record{Sequence: 7, Result: FailureResult}
	v := ViewOf(rec)
	assert.Equals(t, uint64(7), v.Sequence)
	assert.Equals(t, Unknown, v.Action)
	assert.Equals(t, Unknown, v.ObjectType)
	assert.Equals(t, Unknown, v.ActorSubject)
	assert.Equals(t, Unknown, v.ActorID)
	assert.Equals(t, Unknown, v.ObjectID)
	assert.Equals(t, "failure", v.Result)
	assert.Equals(t, Unknown, v.ErrorCategory)
	assert.Equals(t, Unknown, v.Time)
	assert.Equals(t, Unknown, v.ActorType)

	rec.Time = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	rec.Action = CreateAction
	rec.ObjectType = ProvisionerObject
	rec.ActorSubject = "step"
	v = ViewOf(rec)
	assert.Equals(t, "2026-01-02T03:04:05Z", v.Time)
	assert.Equals(t, "create", v.Action)
	assert.Equals(t, "provisioner", v.ObjectType)
	assert.Equals(t, "step", v.ActorSubject)
}

func TestRecordNormalize_setsUnknowns(t *testing.T) {
	rec := &Record{}
	rec.Normalize()
	assert.Equals(t, UnknownAction, rec.Action)
	assert.Equals(t, UnknownObject, rec.ObjectType)
	assert.Equals(t, UnknownResult, rec.Result)
	assert.Equals(t, Unknown, rec.ActorSubject)
}

func TestSnapshot_protobuf(t *testing.T) {
	adm := &linkedca.Admin{
		Id:        "adm-id",
		Subject:   "alice",
		Type:      linkedca.Admin_SUPER_ADMIN,
		CreatedAt: timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
	}
	m, err := Snapshot(adm)
	assert.FatalError(t, err)
	assert.Equals(t, "adm-id", m["id"])
	assert.Equals(t, "alice", m["subject"])
	assert.Equals(t, "SUPER_ADMIN", m["type"])
}
