package main

import (
	"context"
	"strings"
	"testing"
)

func TestRunPostgresExportWorkerRequiresDSN(t *testing.T) {
	err := runPostgresExportWorker(context.Background(), postgresExportWorkerConfig{})
	if err == nil || !strings.Contains(err.Error(), "postgres-dsn is required") {
		t.Fatalf("error = %v, want postgres-dsn requirement", err)
	}
}

func TestPostgresExportWorkerHotStoreRejectsUnsupportedMode(t *testing.T) {
	_, err := postgresExportWorkerHotStore("memory", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported worker hot store") {
		t.Fatalf("error = %v, want unsupported hot store mode", err)
	}
}
