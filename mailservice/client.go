package mailservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

type resendClient struct {
	apiKey, fromEmail, fromName, endpoint string
	http                                  *http.Client
}

func validateEndpoint(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" {
		return errors.New("mailservice: endpoint must be an absolute HTTP(S) URL without user info or fragment")
	}
	return nil
}

type resendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	CC      []string `json:"cc,omitempty"`
	BCC     []string `json:"bcc,omitempty"`
	ReplyTo string   `json:"reply_to,omitempty"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html,omitempty"`
	Text    string   `json:"text,omitempty"`
}

func (c *resendClient) send(ctx context.Context, m Message) error {
	from := c.fromEmail
	if c.fromName != "" {
		from = c.fromName + " <" + c.fromEmail + ">"
	}
	body, err := json.Marshal(resendRequest{From: from, To: m.To, CC: m.CC, BCC: m.BCC, ReplyTo: m.ReplyTo, Subject: m.Subject, HTML: m.HTMLBody, Text: m.TextBody})
	if err != nil {
		return fmt.Errorf("%w: could not encode request", ErrProvider)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: could not create request", ErrProvider)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return fmt.Errorf("%w: %w", ErrNetwork, context.Canceled)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%w: %w", ErrTimeout, context.DeadlineExceeded)
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("%w: %w", ErrTimeout, context.DeadlineExceeded)
		}
		return fmt.Errorf("%w: request could not be completed", ErrNetwork)
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if readErr != nil || len(responseBody) > maxResponseBytes {
		return fmt.Errorf("%w: invalid provider response", ErrProvider)
	}
	log.Printf("Resend status: %d, response: %s", resp.StatusCode, responseBody)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		var result struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(responseBody, &result); err != nil || strings.TrimSpace(result.ID) == "" {
			return fmt.Errorf("%w: malformed provider response", ErrProvider)
		}
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w (HTTP %d)", ErrAuthentication, resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("%w", ErrRateLimited)
	default:
		return fmt.Errorf("%w (HTTP %d)", ErrProvider, resp.StatusCode)
	}
}

func defaultHTTPClient(timeout time.Duration) *http.Client { return &http.Client{Timeout: timeout} }
