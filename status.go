package smtpd

// StatusCode represents SMTP status code
type StatusCode int

// SMTP Status codes
const (
	StatusSuccess              StatusCode = 200
	StatusSystem               StatusCode = 211
	StatusHelpMessage          StatusCode = 214
	StatusServiceReady         StatusCode = 220
	StatusServiceClosing       StatusCode = 221
	StatusAuthenticated        StatusCode = 235
	StatusOK                   StatusCode = 250
	StatusNotLocalWillForward  StatusCode = 251
	StatusCantVerifyWillAccept StatusCode = 252

	StatusProvideCredentials StatusCode = 334
	StatusStartMailInput     StatusCode = 354

	StatusServiceNotAvailable           StatusCode = 421
	StatusMailboxTemporarilyUnavailable StatusCode = 450
	StatusLocalError                    StatusCode = 451
	StatusInsufficientStorage           StatusCode = 452

	StatusCommandUnrecognized           StatusCode = 500
	StatusSyntaxError                   StatusCode = 501
	StatusCommandNotImplemented         StatusCode = 502
	StatusBadSequence                   StatusCode = 503
	StatusParameterNotImplemented       StatusCode = 504
	StatusDoesNotAcceptMail             StatusCode = 521
	StatusAccessDenied                  StatusCode = 530
	StatusMailboxPermanentlyUnavailable StatusCode = 550
	StatusUserNotLocal                  StatusCode = 551
	StatusExceededStorageAllocation     StatusCode = 552
	StatusMailboxNameNotAllowed         StatusCode = 553
	StatusTransactionFailed             StatusCode = 554
)
