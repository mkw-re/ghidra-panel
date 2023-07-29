package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"

	"go.mkw.re/ghidra-panel/common"
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

func (d *DB) SetPassword(ctx context.Context, id uint64, username, password string) error {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}

	// Hash password with Argon2id
	hash := argon2.IDKey([]byte(password), salt[:], 1, 19456, 2, 32)

	_, err := d.ExecContext(
		ctx,
		`INSERT INTO passwords (id, username, hash, salt, format) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hash = excluded.hash,
			salt = excluded.salt,
			format = excluded.format,
			updated_at = CURRENT_TIMESTAMP`,
		id, username, hash, salt[:], 1,
	)
	return err
}
