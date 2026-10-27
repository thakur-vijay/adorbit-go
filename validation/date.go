package validation

import "time"

func IsISODate(value string) bool {
	_, err := time.Parse("2006-01-02", value)
	return err == nil
}
