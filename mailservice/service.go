package mailservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// New constructs the Resend-backed mail service from validated configuration.
func New(config Config) (Service, error) {
	c, err := config.withDefaults()
	if err != nil {
		return nil, err
	}
	return &service{client: &resendClient{apiKey: c.APIKey, fromEmail: c.FromEmail, fromName: c.FromName, endpoint: c.Endpoint, http: defaultHTTPClient(c.Timeout)}}, nil
}

type service struct{ client *resendClient }

func (s *service) Send(ctx context.Context, m Message) error {
	if err := validateMessage(m); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidMessage, err)
	}
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidMessage)
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %w", ErrTimeout, err)
		}
		return fmt.Errorf("%w: %w", ErrNetwork, err)
	}
	return s.client.send(ctx, m)
}

func validateMessage(m Message) error {
	if len(m.To) == 0 {
		return errors.New("at least one recipient is required")
	}
	if strings.TrimSpace(m.Subject) == "" || strings.ContainsAny(m.Subject, "\r\n") {
		return errors.New("subject is required and must not contain line breaks")
	}
	if strings.TrimSpace(m.HTMLBody) == "" && strings.TrimSpace(m.TextBody) == "" {
		return errors.New("HTML or text body is required")
	}
	for _, list := range [][]string{m.To, m.CC, m.BCC} {
		for _, address := range list {
			if !validEmail(strings.TrimSpace(address)) {
				return errors.New("recipient address is invalid")
			}
		}
	}
	if m.ReplyTo != "" && !validEmail(strings.TrimSpace(m.ReplyTo)) {
		return errors.New("reply-to address is invalid")
	}
	return nil
}
