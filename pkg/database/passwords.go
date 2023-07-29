package database

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

func Open(filePath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", filePath+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(migrations); err != nil {
		return nil, fmt.Errorf("migrations failed: %w", err)
	}

	return db, nil
}
