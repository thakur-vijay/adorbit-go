package apperrors

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/thakur-vijay/adorbit-go/validation"
)

var ErrAlreadyProcessing = errors.New("request with this Idempotency-Key is already being processed")

const (
	CodeBadRequest         = "BAD_REQUEST"
	CodeUnauthorized       = "UNAUTHORIZED"
	CodeForbidden          = "FORBIDDEN"
	CodeNotFound           = "NOT_FOUND"
	CodeConflict           = "CONFLICT"
	CodeRateLimited        = "RATE_LIMITED"
	CodePayloadTooLarge    = "PAYLOAD_TOO_LARGE"
	CodeRequestTimeout     = "REQUEST_TIMEOUT"
	CodeInternal           = "INTERNAL_ERROR"
	CodeServiceUnavailable = "SERVICE_UNAVAILABLE"
	CodeConfig             = "CONFIG_ERROR"
	CodeValidation         = "VALIDATION_ERROR"
)

type AppError struct {
	Code       string
	Message    string
	StatusCode int
	Err        error
}

func (e *AppError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func New(code, message string, statusCode int, err error) *AppError {
	if err == nil && message == "" {
		message = code
	}
	return &AppError{Code: code, Message: message, StatusCode: statusCode, Err: err}
}

func NewBadRequest(message string, err error) *AppError {
	return New(CodeBadRequest, message, http.StatusBadRequest, err)
}

func NewUnauthorized(message string, err error) *AppError {
	return New(CodeUnauthorized, message, http.StatusUnauthorized, err)
}

func NewForbidden(message string, err error) *AppError {
	return New(CodeForbidden, message, http.StatusForbidden, err)
}

func NewNotFound(message string, err error) *AppError {
	return New(CodeNotFound, message, http.StatusNotFound, err)
}

func NewConflict(message string, err error) *AppError {
	return New(CodeConflict, message, http.StatusConflict, err)
}

func NewRateLimited(message string, err error) *AppError {
	return New(CodeRateLimited, message, http.StatusTooManyRequests, err)
}

func NewPayloadTooLarge(message string, err error) *AppError {
	return New(CodePayloadTooLarge, message, http.StatusRequestEntityTooLarge, err)
}

func NewRequestTimeout(message string, err error) *AppError {
	return New(CodeRequestTimeout, message, http.StatusRequestTimeout, err)
}

func NewInternal(message string, err error) *AppError {
	return New(CodeInternal, message, http.StatusInternalServerError, err)
}

func NewServiceUnavailable(message string, err error) *AppError {
	return New(CodeServiceUnavailable, message, http.StatusServiceUnavailable, err)
}

func NewConfigError(message string, err error) *AppError {
	return New(CodeConfig, message, http.StatusInternalServerError, err)
}

func NewValidationError(message string, err error) *AppError {
	return New(CodeValidation, message, http.StatusBadRequest, err)
}

func Classify(err error) *AppError {
	if err == nil {
		return nil
	}

	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}

	var validationErr *validation.ValidationError
	if errors.As(err, &validationErr) {
		return NewValidationError(validationErr.Message, err)
	}

	if errors.Is(err, context.Canceled) {
		return NewRequestTimeout("request was cancelled", err)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return NewRequestTimeout("request timed out", err)
	}

	if errors.Is(err, ErrAlreadyProcessing) {
		return NewConflict(ErrAlreadyProcessing.Error(), err)
	}

	if errors.Is(err, sql.ErrNoRows) {
		return NewNotFound("resource was not found", err)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return NewConflict("resource already exists", err)
		case "23503":
			return NewConflict("resource is still in use", err)
		case "22001":
			return NewBadRequest("request payload is too large", err)
		case "22P02":
			return NewBadRequest("request contains invalid values", err)
		default:
			return NewServiceUnavailable("database operation failed", err)
		}
	}

	return NewInternal("internal server error", err)
}
