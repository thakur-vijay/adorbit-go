package mailservice

import (
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"time"
)

const defaultEndpoint = "https://api.resend.com/emails"

// Config contains the credentials and transport settings for a Resend client.
type Config struct {
	APIKey    string
	FromEmail string
	FromName  string
	Endpoint  string
	Timeout   time.Duration
}

// LoadConfig reads configuration from the environment and validates it.
func LoadConfig() (Config, error) {
	c := Config{APIKey: os.Getenv("RESEND_API_KEY"), FromEmail: os.Getenv("MAIL_FROM_EMAIL"), FromName: os.Getenv("MAIL_FROM_NAME"), Endpoint: os.Getenv("MAIL_API_ENDPOINT")}
	if raw := strings.TrimSpace(os.Getenv("MAIL_API_TIMEOUT")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("mailservice: invalid MAIL_API_TIMEOUT: %w", err)
		}
		c.Timeout = d
	}
	return c.withDefaults()
}

func (c Config) withDefaults() (Config, error) {
	c.APIKey = strings.TrimSpace(c.APIKey)
	c.FromEmail = strings.TrimSpace(c.FromEmail)
	c.FromName = strings.TrimSpace(c.FromName)
	if c.APIKey == "" {
		return Config{}, errors.New("mailservice: RESEND_API_KEY is required")
	}
	if !validEmail(c.FromEmail) {
		return Config{}, errors.New("mailservice: MAIL_FROM_EMAIL must be a valid email address")
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Timeout < 0 {
		return Config{}, errors.New("mailservice: timeout must be positive")
	}
	if c.Endpoint == "" {
		c.Endpoint = defaultEndpoint
	}
	if err := validateEndpoint(c.Endpoint); err != nil {
		return Config{}, err
	}
	return c, nil
}

func validEmail(s string) bool {
	if strings.ContainsAny(s, "\r\n") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && strings.Count(s, "@") == 1
}
