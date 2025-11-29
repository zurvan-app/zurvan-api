package database

import (
	"context"
	"log"
	"time"
	"zurvan-api/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

var dbPool *pgxpool.Pool

func InitPostgresClient(dbCfg config.DatabaseConfig) {
	if dbPool != nil {
		return
	}

	pgxCfg, err := pgxpool.ParseConfig(dbCfg.ConnectionURL)
	if err != nil {
		log.Fatalf("Unable to parse Postgres connection URL: %v", err)
	}

	pgxCfg.MaxConns = 20
	pgxCfg.MinConns = 10
	pgxCfg.MaxConnLifetime = 30 * time.Minute
	pgxCfg.MaxConnIdleTime = 10 * time.Minute
	pgxCfg.HealthCheckPeriod = 30 * time.Second
	pgxCfg.ConnConfig.ConnectTimeout = 10 * time.Second

	dbPool, err = pgxpool.NewWithConfig(context.Background(), pgxCfg)
	if err != nil {
		log.Fatalf("Unable to connect to Postgres: %v", err)
	}
}

func PostgresClient() *pgxpool.Pool {
	return dbPool
}
