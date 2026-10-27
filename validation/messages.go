package validation

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

func buildMessage(dto any, err error) error {
	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		return &ValidationError{Message: "validation failed"}
	}

	fieldError := validationErrors[0]

	t := reflect.TypeOf(dto)

	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	field, ok := t.FieldByName(fieldError.StructField())
	if !ok {
		return &ValidationError{Message: "validation failed"}
	}

	jsonName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	fieldType := field.Type

	if fieldType.Kind() == reflect.Pointer {
		fieldType = fieldType.Elem()
	}

	if jsonName == "" {
		jsonName = fieldError.Field()
	}

	switch fieldError.Tag() {
	case "required":
		return &ValidationError{Message: fmt.Sprintf("%s of type %s is required", jsonName, fieldType.String())}
	case "notblank":
		return &ValidationError{Message: fmt.Sprintf("%s of type %s must not be blank", jsonName, fieldType.String())}

	case "min":
		return &ValidationError{Message: fmt.Sprintf("%s of type %s must be at least %s", jsonName, fieldType.String(), fieldError.Param())}
	case "max":
		return &ValidationError{Message: fmt.Sprintf("%s of type %s must be at most %s", jsonName, fieldType.String(), fieldError.Param())}
	case "oneof":
		return &ValidationError{Message: fmt.Sprintf("%s must be one of: %s", jsonName, strings.ReplaceAll(fieldError.Param(), " ", ", "))}
	case "gte":
		return &ValidationError{Message: fmt.Sprintf("%s of type %s must be greater than or equal to %s", jsonName, fieldType.String(), fieldError.Param())}
	case "gt":
		return &ValidationError{Message: fmt.Sprintf("%s of type %s must be greater than %s", jsonName, fieldType.String(), fieldError.Param())}
	case "lte":
		return &ValidationError{Message: fmt.Sprintf("%s of type %s must be less than or equal to %s", jsonName, fieldType.String(), fieldError.Param())}
	case "lt":
		return &ValidationError{Message: fmt.Sprintf("%s of type %s must be less than %s", jsonName, fieldType.String(), fieldError.Param())}
	case "valid_password":
		return &ValidationError{
			Message: fmt.Sprintf(
				"%s must be 6-16 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character",
				jsonName,
			),
		}
	default:
		return &ValidationError{Message: fmt.Sprintf("%s is invalid", jsonName)}
	}
}
