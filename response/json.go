package response

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

var (
	ErrFailedToReadBody   = errors.New("failed to read request body")
	ErrRequestBodyEmpty   = errors.New("request body must not be empty")
	ErrInvalidJSON        = errors.New("request body must be a valid JSON object")
	ErrInvalidFieldValues = errors.New("request body contains invalid field values")
)

func DecodeJSON[T any](r *http.Request, destination *T) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return ErrFailedToReadBody
	}

	if len(strings.TrimSpace(string(body))) == 0 {
		return ErrRequestBodyEmpty
	}

	var raw map[string]json.RawMessage

	if err := json.Unmarshal(body, &raw); err != nil {
		return ErrInvalidJSON
	}

	if len(raw) == 0 {
		return ErrRequestBodyEmpty
	}

	if err := json.Unmarshal(body, destination); err != nil {
		return ErrInvalidFieldValues
	}

	return nil
}
