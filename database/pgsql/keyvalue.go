package pgsql

import (
	"database/sql"
	"log"
	"github.com/MXi4oyu/DockerXScan/common/commonerr"
	"time"
)

// InsertKeyValue stores (or updates) a single key / value tuple.
func (pgSQL *pgSQL) InsertKeyValue(key, value string) (err error) {
	if key == "" || value == "" {
		log.Println("could not insert a flag which has an empty name or value")
		return commonerr.NewBadRequestError("could not insert a flag which has an empty name or value")
	}

	defer observeQueryTime("InsertKeyValue", "all", time.Now())

	for {
		// First, try to update.
		r, err := pgSQL.Exec(updateKeyValue, value, key)
		if err != nil {
			return handleError("updateKeyValue", err)
		}
		if n, _ := r.RowsAffected(); n > 0 {
			// Updated successfully.
			return nil
		}

		// Try to insert the key.
		// If someone else inserts the same key concurrently, we could get a unique-key violation error.
		_, err = pgSQL.Exec(insertKeyValue, key, value)
		if err != nil {
			if isErrUniqueViolation(err) {
				// Got unique constraint violation, retry.
				continue
			}
			return handleError("insertKeyValue", err)
		}

		return nil
	}
}

// GetValue reads a single key / value tuple and returns an empty string if the key doesn't exist.
func (pgSQL *pgSQL) GetKeyValue(key string) (string, error) {
	defer observeQueryTime("GetKeyValue", "all", time.Now())
	var value string
	err := pgSQL.QueryRow(searchKeyValue, key).Scan(&value)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", handleError("searchKeyValue", err)
	}

	return value, nil
}