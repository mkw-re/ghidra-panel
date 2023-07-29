package database

const migrations = `
CREATE TABLE IF NOT EXISTS passwords (
	id UNSIGNED BIG INT PRIMARY KEY,
	hash BLOB NOT NULL,
	salt BLOB NOT NULL,
	format SHORT INT NOT NULL,
	updated_at INTEGER DEFAULT CURRENT_TIMESTAMP NOT NULL
);
`
