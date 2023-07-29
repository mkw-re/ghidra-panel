package database

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"go.mkw.re/ghidra-panel/pkg/common"
)

type DB struct {
	*sql.DB
}

func Open(filePath string) (*DB, error) {
	db, err := sql.Open("sqlite3", filePath+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(migrations); err != nil {
		return nil, fmt.Errorf("migrations failed: %w", err)
	}

	return &DB{db}, nil
}

func (d *DB) GetUserState(ctx context.Context, id uint64) (*common.UserState, error) {
	hasPass, err := d.HasPassword(ctx, id)
	if err != nil {
		return nil, err
	}
	return &common.UserState{
		HasPassword: hasPass,
	}, nil
}

func (d *DB) HasPassword(ctx context.Context, id uint64) (exist bool, err error) {
	err = d.
		QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM passwords WHERE id = ?)", id).
		Scan(&exist)
	return
}
