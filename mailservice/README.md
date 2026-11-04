# Mail Service

`mailservice` is a reusable Go email abstraction. Consumers depend on the `Service` interface and `Message`; the initial implementation sends through Resend using only the standard library.

## Design

`Config` handles environment and settings validation, `Service` validates messages, and the private HTTP client handles Resend authentication, encoding, and status classification. Sends are never automatically retried: a timeout may occur after Resend accepted the message, and retrying could duplicate delivery. Successful provider responses must contain a message ID. Provider response bodies and request content are never included in errors.

## Configuration

| Environment variable | Required | Description |
| --- | --- | --- |
| `RESEND_API_KEY` | Yes | Resend API key |
| `MAIL_FROM_EMAIL` | Yes | Verified sender email address |
| `MAIL_FROM_NAME` | No | Display name shown as the sender |
| `MAIL_API_TIMEOUT` | No | Go duration, such as `10s` (defaults to 10 seconds) |
| `MAIL_API_ENDPOINT` | No | HTTP(S) endpoint override, primarily useful for tests |

`LoadConfig` reads and validates these values. `New` validates supplied configuration as well. Production deployments should use HTTPS and keep credentials in a secret manager or protected environment variables.

## Authentication Service example

```go
package auth

import (
    "context"
    "github.com/thakur-vijay/adorbit-go/mailservice"
)

func NewMailer() (mailservice.Service, error) {
    cfg, err := mailservice.LoadConfig()
    if err != nil { return nil, err }
    return mailservice.New(cfg)
}

func SendVerification(ctx context.Context, mailer mailservice.Service, address, otp string) error {
    return mailer.Send(ctx, mailservice.Message{
        To: []string{address}, Subject: "Verify your email",
        HTMLBody: "<h1>Your OTP is " + otp + "</h1>",
        TextBody: "Your OTP is " + otp,
    })
}
```

In real applications, escape values inserted into HTML templates. Do not log message content or OTPs.

## Errors

Errors can be checked with `errors.Is` against `ErrInvalidMessage`, `ErrAuthentication`, `ErrRateLimited`, `ErrProvider`, `ErrNetwork`, and `ErrTimeout`. Underlying context cancellation and deadlines are preserved where applicable. Network errors intentionally omit low-level URL and request details to avoid exposing configuration or content.

## Resend setup

Create a Resend account, verify a sending domain, and configure the sender address with that verified domain before sending from production. Resend may reject unverified senders or API keys. API keys must not be committed or included in logs.

## Tests

Run `go test ./mailservice`. The tests use `httptest.Server` and never contact Resend.
