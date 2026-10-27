package validation

import (
	"reflect"
	"strings"

	"github.com/google/uuid"

	"github.com/go-playground/validator/v10"
)

type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	if e == nil {
		return "validation failed"
	}
	return e.Message
}

var validate = validator.New()

func init() {
	validate.RegisterValidation("notblank", func(fl validator.FieldLevel) bool {
		if fl.Field().Kind() == reflect.Pointer {
			if fl.Field().IsNil() {
				return true
			}

			return strings.TrimSpace(fl.Field().Elem().String()) != ""
		}

		return strings.TrimSpace(fl.Field().String()) != ""
	})

	validate.RegisterValidation("valid_uuid4", func(fl validator.FieldLevel) bool {
		id, err := uuid.Parse(fl.Field().String())
		if err != nil {
			return false
		}

		return id.Version() == 4
	})

	validate.RegisterValidation("valid_password", func(fl validator.FieldLevel) bool {
		password := fl.Field().String()

		if len(password) < 6 || len(password) > 128 {
			return false
		}

		var hasLower, hasUpper, hasNumber, hasSymbol bool

		for _, char := range password {
			switch {
			case char >= 'a' && char <= 'z':
				hasLower = true
			case char >= 'A' && char <= 'Z':
				hasUpper = true
			case char >= '0' && char <= '9':
				hasNumber = true
			default:
				hasSymbol = true
			}
		}

		return hasLower && hasUpper && hasNumber && hasSymbol
	})
}

func Validator(dto any) error {
	err := validate.Struct(dto)
	if err == nil {
		return nil
	}

	return buildMessage(dto, err)
}
