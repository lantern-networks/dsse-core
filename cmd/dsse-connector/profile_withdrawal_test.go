package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthoritativeEmptyProfileWithdrawsDataButRetainsOnlyProfileGET(t *testing.T) {
	var mode atomic.Int32 // 0=empty, 1=unavailable, 2=restored
	var profileGets atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/connectors/conn-1/profile" {
			t.Errorf("data request reached profile-only address: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		profileGets.Add(1)
		if mode.Load() == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		answer := connectorProfileAnswer{SchemaVersion: "connector_profile.v1", TenantID: "tenant-a", EdgeEndpoints: []string{}}
		if mode.Load() == 2 {
			answer.EdgeEndpoints = []string{"region-a=" + server.URL}
		}
		_ = json.NewEncoder(w).Encode(answer)
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := saveConnectorState(filepath.Join(dir, "connector-state.json"), connectorState{
		EdgeURL: server.URL, EdgeEndpoints: "region-a=" + server.URL, TenantID: "tenant-a", ConnectorID: "conn-1",
	}); err != nil {
		t.Fatal(err)
	}
	doors := parseConnectorEndpoints("region-a=" + server.URL)
	_, dataCtx := doors.selectionForData()
	closed := 0
	doors.SetOnMove(func() { closed++ })
	refresh := func(target *connectorEndpoints) error {
		return refreshConnectorProfile(context.Background(), server.Client(), target, dir, "conn-1", "runtime-secret", "tenant-a", false)
	}
	if err := refresh(doors); err != nil {
		t.Fatal(err)
	}
	if closed != 1 || doors.count() != 0 || doors.current() != "" || doors.selection().url != "" || doors.profileDoor() != server.URL {
		t.Fatalf("withdrawal left a data door: count=%d current=%q control=%q callbacks=%d", doors.count(), doors.current(), doors.profileDoor(), closed)
	}
	select {
	case <-dataCtx.Done():
	default:
		t.Fatal("withdrawal did not cancel an in-flight data dial")
	}
	st, ok, err := loadConnectorState(filepath.Join(dir, "connector-state.json"))
	if err != nil || !ok || !st.DoorListWithdrawn || st.EdgeEndpoints != "" || st.ProfileDoorURL != server.URL {
		t.Fatalf("withdrawal state not durable: %+v ok=%t err=%v", st, ok, err)
	}
	mode.Store(1)
	if err := refresh(doors); err == nil || doors.count() != 0 || closed != 1 {
		t.Fatalf("503 must retain the withdrawn data state: err=%v count=%d callbacks=%d", err, doors.count(), closed)
	}
	restarted, err := initialConnectorDoors("", server.URL, dir, false)
	if err != nil || restarted.count() != 0 || restarted.current() != "" || restarted.profileDoor() != server.URL {
		t.Fatalf("restart reused old data URL: count=%d err=%v", restarted.count(), err)
	}
	mode.Store(2)
	if err := refresh(restarted); err != nil {
		t.Fatal(err)
	}
	if restarted.current() != server.URL || restarted.count() != 1 || profileGets.Load() != 3 {
		t.Fatalf("new authorized profile did not restore data doors: count=%d gets=%d", restarted.count(), profileGets.Load())
	}
	st, _, err = loadConnectorState(filepath.Join(dir, "connector-state.json"))
	if err != nil || st.DoorListWithdrawn || st.ProfileDoorURL != "" {
		t.Fatalf("restored profile kept withdrawal marker: %+v err=%v", st, err)
	}
}

func TestMalformedOrOtherTenantProfileCannotWithdrawDoors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(connectorProfileAnswer{
			SchemaVersion: "connector_profile.v1", TenantID: "tenant-b", EdgeEndpoints: []string{},
		})
	}))
	defer server.Close()
	doors := parseConnectorEndpoints(server.URL)
	if err := refreshConnectorProfile(context.Background(), server.Client(), doors, "", "conn-1", "secret", "tenant-a", false); err == nil || doors.current() != server.URL {
		t.Fatalf("another tenant's empty list changed current door: err=%v current=%q", err, doors.current())
	}
}

func TestWithdrawnProfileDoesNotFollowRedirect(t *testing.T) {
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected++ }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/connectors/conn-1/profile", http.StatusFound)
	}))
	defer source.Close()
	doors := &connectorEndpoints{profileURL: source.URL}
	if err := refreshConnectorProfile(context.Background(), source.Client(), doors, "", "conn-1", "secret", "tenant-a", false); err == nil {
		t.Fatal("redirected profile was accepted")
	}
	if redirected != 0 || doors.count() != 0 || doors.profileDoor() != source.URL {
		t.Fatal("profile-only address followed a redirect or changed data state")
	}
}

func TestEmptyProfileClosesDataEvenWhenStateCannotBePersisted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(connectorProfileAnswer{
			SchemaVersion: "connector_profile.v1", TenantID: "tenant-a", EdgeEndpoints: []string{},
		})
	}))
	defer server.Close()
	doors := parseConnectorEndpoints(server.URL)
	if err := refreshConnectorProfile(context.Background(), server.Client(), doors, t.TempDir(), "conn-1", "secret", "tenant-a", false); err == nil {
		t.Fatal("missing durable state was hidden")
	}
	if doors.count() != 0 {
		t.Fatal("state persistence failure left an unauthorized live data door")
	}
}

func TestRemovingCurrentDoorCancelsItsInFlightDataDial(t *testing.T) {
	doors := parseConnectorEndpoints("region-a=https://a.example;region-b=https://b.example")
	_, dataCtx := doors.selectionForData()
	closed := 0
	doors.SetOnMove(func() { closed++ })
	if !doors.replace(parseConnectorEndpoints("region-b=https://b.example")) {
		t.Fatal("new valid door list not applied")
	}
	select {
	case <-dataCtx.Done():
	default:
		t.Fatal("removed current door left an in-flight data dial live")
	}
	if closed != 1 || doors.current() != "https://b.example" {
		t.Fatalf("removed current door retained old attachments: callbacks=%d current=%q", closed, doors.current())
	}
}

func TestHeartbeatDoesNotUseProfileOnlyDoor(t *testing.T) {
	doors := &connectorEndpoints{profileURL: "https://control.example"}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	sends := 0
	runConnectorHeartbeats(ctx, doors, func(string) error { sends++; return nil }, func() { t.Error("register called") }, 5*time.Millisecond)
	if sends != 0 {
		t.Fatalf("sent %d data heartbeats through profile-only address", sends)
	}
}
