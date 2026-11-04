package mailservice

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testConfig(endpoint string) Config {
	return Config{APIKey: "test-secret", FromEmail: "mail@example.com", Endpoint: endpoint, Timeout: time.Second}
}
func testMessage() Message {
	return Message{To: []string{"person@example.com"}, Subject: "Hello", TextBody: "Hello"}
}

func TestSend(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		response string
		want     error
	}{
		{"success", 200, `{"id":"abc"}`, nil},
		{"bad key", 401, `{"message":"private"}`, ErrAuthentication},
		{"rate limit", 429, `{"message":"private"}`, ErrRateLimited},
		{"server error", 503, `{"message":"private"}`, ErrProvider},
		{"malformed success", 200, `{`, ErrProvider},
		{"unexpected status", 418, `no`, ErrProvider},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-secret" {
					t.Errorf("missing auth header")
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.response))
			}))
			defer server.Close()
			s, err := New(testConfig(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			err = s.Send(context.Background(), testMessage())
			if tt.want == nil && err != nil {
				t.Fatal(err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "private") {
				t.Fatal("provider response leaked")
			}
		})
	}
}

func TestValidation(t *testing.T) {
	s, err := New(testConfig("https://example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []Message{{To: []string{"bad"}, Subject: "s", TextBody: "b"}, {To: []string{"a@b.com"}, TextBody: "b"}, {To: []string{"a@b.com"}, Subject: "s"}} {
		if err := s.Send(context.Background(), m); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("got %v", err)
		}
	}
}

func TestInvalidConfig(t *testing.T) {
	for _, c := range []Config{{}, {APIKey: "x", FromEmail: "bad"}, {APIKey: "x", FromEmail: "a@b.com", Timeout: -1}, {APIKey: "x", FromEmail: "a@b.com", Endpoint: "file:///secret"}} {
		if _, err := New(c); err == nil {
			t.Fatalf("expected invalid config: %+v", c)
		}
	}
}

func TestNetworkAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(20 * time.Millisecond) }))
	defer server.Close()
	s, err := New(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Send(ctx, testMessage()); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	server.CloseClientConnections()
	server.Close()
	if err := s.Send(context.Background(), testMessage()); !errors.Is(err, ErrNetwork) {
		t.Fatalf("got %v", err)
	}
}

func TestContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(20 * time.Millisecond) }))
	defer server.Close()
	s, err := New(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := s.Send(ctx, testMessage()); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadConfigInvalidTimeout(t *testing.T) {
	t.Setenv("RESEND_API_KEY", "x")
	t.Setenv("MAIL_FROM_EMAIL", "mail@example.com")
	t.Setenv("MAIL_API_TIMEOUT", "not-duration")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected invalid timeout")
	}
}
