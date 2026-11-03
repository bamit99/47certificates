package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookSignsBody(t *testing.T) {
	var gotSig, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-47C-Signature")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer srv.Close()

	wh := Webhook{URL: srv.URL, Secret: "s3cret", Client: srv.Client()}
	if err := wh.Send(context.Background(), 7, []byte(`{"report":7}`)); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte(gotBody))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(gotSig), []byte(want)) {
		t.Fatalf("sig %q, want %q", gotSig, want)
	}
	if gotBody != `{"report":7}` {
		t.Fatalf("body %q", gotBody)
	}
}

func TestWebhookRejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	wh := Webhook{URL: srv.URL, Secret: "x", Client: srv.Client()}
	if err := wh.Send(context.Background(), 1, []byte("{}")); err == nil {
		t.Fatal("expected error for non-2xx")
	}
}
