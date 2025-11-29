package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"

	"github.com/jackc/tern/v2/migrate"
)

const versionTable = "db_version"

type Migrator struct {
	migrator *migrate.Migrator
}

//go:embed migration/*.sql
var migrationFiles embed.FS

func NewMigrator(dbDNS string) (Migrator, error) {
	conn, err := pgx.Connect(context.Background(), dbDNS)
	if err != nil {
		return Migrator{}, fmt.Errorf("failed to connect to DB: %w", err)
	}

	migrator, err := migrate.NewMigratorEx(
		context.Background(), conn, versionTable,
		&migrate.MigratorOptions{
			DisableTx: false,
		},
	)
	if err != nil {
		return Migrator{}, fmt.Errorf("failed to initialize migrator: %w", err)
	}

	migrationRoot, err := fs.Sub(migrationFiles, "migration")
	if err != nil {
		return Migrator{}, fmt.Errorf("failed to access migrations: %w", err)
	}

	if err = migrator.LoadMigrations(migrationRoot); err != nil {
		return Migrator{}, fmt.Errorf("failed to load migrations: %w", err)
	}

	return Migrator{migrator: migrator}, nil
}

func (m Migrator) Info() (int32, int32, string, error) {
	version, err := m.migrator.GetCurrentVersion(context.Background())
	if err != nil {
		return 0, 0, "", err
	}

	info := ""
	var last int32
	for _, thisMigration := range m.migrator.Migrations {
		last = thisMigration.Sequence
		cur := version == thisMigration.Sequence
		indicator := "  "
		if cur {
			indicator = "->"
		}
		info += fmt.Sprintf("%2s %3d %s\n", indicator, thisMigration.Sequence, thisMigration.Name)
	}

	return version, last, info, nil
}

func (m Migrator) Migrate() error {
	return m.migrator.Migrate(context.Background())
}

func (m Migrator) MigrateTo(version int32) error {
	return m.migrator.MigrateTo(context.Background(), version)
}
