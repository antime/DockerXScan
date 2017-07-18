package commonerr

import "errors"

var (
	// ErrFilesystem occurs when a filesystem interaction fails.
	ErrFilesystem = errors.New("something went wrong when interacting with the fs")

	// ErrCouldNotDownload occurs when a download fails.
	ErrCouldNotDownload = errors.New("could not download requested resource")

	// ErrNotFound occurs when a resource could not be found.
	ErrNotFound = errors.New("the resource cannot be found")

	// ErrCouldNotParse is returned when a fetcher fails to parse the update data.
	ErrCouldNotParse = errors.New("updater/fetchers: could not parse")

	ErrBackendException = errors.New("database: an error occured when querying the backend")

	ErrInconsistent = errors.New("database: inconsistent database")
)

// ErrBadRequest occurs when a method has been passed an inappropriate argument.
type ErrBadRequest struct {
	s string
}

// NewBadRequestError instantiates a ErrBadRequest with the specified message.
func NewBadRequestError(message string) error {
	return &ErrBadRequest{s: message}
}

func (e *ErrBadRequest) Error() string {
	return e.s
}