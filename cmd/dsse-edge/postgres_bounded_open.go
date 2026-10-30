package main

import (
	"database/sql"
	"time"

	"github.com/lib/pq"
)

// database/sql may open pool connections without a request context. A bounded
// TCP dial alone also does not bound PostgreSQL's initial SSL/startup reads.
// Keep an explicit driver handshake deadline on every runtime pool, including
// the dedicated advisory-lock pool. TLS and all other DSN settings are retained.
const postgresConnectTimeout = 2 * time.Second

func boundedPostgresConfig(dsn string) (pq.Config, error) {
	cfg, err := pq.NewConfig(dsn)
	if err != nil {
		return cfg, err
	}
	if cfg.ConnectTimeout <= 0 || cfg.ConnectTimeout > postgresConnectTimeout {
		cfg.ConnectTimeout = postgresConnectTimeout
	}
	return cfg, nil
}

func openPostgresBounded(dsn string) (*sql.DB, error) {
	cfg, err := boundedPostgresConfig(dsn)
	if err != nil {
		return nil, err
	}
	c, err := pq.NewConnectorConfig(cfg)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(c), nil
}
