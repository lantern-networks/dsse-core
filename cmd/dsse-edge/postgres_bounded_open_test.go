package main

import (
	"context"
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestPostgresRuntimeHandshakeDeadlinePreservesTLS(t *testing.T) {
	t.Setenv("PGCONNECT_TIMEOUT", "0")
	for _, tt := range []struct {
		timeout string
		want    time.Duration
	}{{"", 2 * time.Second}, {"0", 2 * time.Second}, {"-1", 2 * time.Second}, {"30", 2 * time.Second}, {"1", time.Second}} {
		dsn := "host=db.example user=fixture dbname=fixture sslmode=verify-full sslrootcert=/fixture/root.pem"
		if tt.timeout != "" {
			dsn += " connect_timeout=" + tt.timeout
		}
		cfg, err := boundedPostgresConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ConnectTimeout != tt.want {
			t.Errorf("timeout %q: got %s, want %s", tt.timeout, cfg.ConnectTimeout, tt.want)
		}
		if cfg.SSLMode != pq.SSLModeVerifyFull || cfg.SSLRootCert != "/fixture/root.pem" {
			t.Fatal("TLS identity verification settings changed")
		}
	}
}

func TestPostgresRuntimeInitialReadCannotWaitForever(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		close(accepted)
		<-release
	}()
	defer func() { close(release); listener.Close(); <-done }()
	db, err := openPostgresBounded("postgres://fixture@" + listener.Addr().String() + "/fixture?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	begin := time.Now()
	err = db.PingContext(ctx)
	if err == nil {
		t.Fatal("silent PostgreSQL peer accepted")
	}
	if elapsed := time.Since(begin); elapsed > 1500*time.Millisecond {
		t.Fatalf("initial read exceeded driver deadline: %s", elapsed)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("test did not exercise an accepted connection")
	}
}

func TestReplicaHealthProbeDoesNotQueueBehindBlockedRefresh(t *testing.T) {
	before := cpDatabaseShapeCache
	c := &cpDatabaseShape{}
	cpDatabaseShapeCache = c
	defer func() { cpDatabaseShapeCache = before }()
	c.mu.Lock()
	defer c.mu.Unlock()
	answer := make(chan bool, 1)
	go func() { _, known := streamingReplicas(new(sql.DB)); answer <- known }()
	select {
	case known := <-answer:
		if known {
			t.Fatal("blocked probe must be reported as unknown")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("health request queued behind the refresh lock")
	}
}
