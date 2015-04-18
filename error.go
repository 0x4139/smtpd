package smtpd

import (
	"fmt"
)

// Error represents an Error reported in the SMTP session.
type Error struct {
	Code    StatusCode // The integer error (status) code
	Message string     // The error message
}

func NewError(code StatusCode, message string) Error {
	return Error{
		Code:    code,
		Message: message,
	}
}

// Error returns a string representation of the SMTP error
func (e Error) Error() string {
	return fmt.Sprintf("%d %s", e.Code, e.Message)
}
