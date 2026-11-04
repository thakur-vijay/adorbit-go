package mailservice

import "errors"

var (
	ErrInvalidMessage = errors.New("mailservice: invalid message")
	ErrAuthentication = errors.New("mailservice: provider authentication failed")
	ErrRateLimited    = errors.New("mailservice: provider rate limit exceeded")
	ErrProvider       = errors.New("mailservice: provider request failed")
	ErrNetwork        = errors.New("mailservice: network request failed")
	ErrTimeout        = errors.New("mailservice: request timed out")
)
