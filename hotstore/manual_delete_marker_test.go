package hotstore

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManualDeleteMutationLookupCannotMatchAnotherJobPrefix(t *testing.T) {
	job := "hot_delete_test"
	otherCommand := "DELETE WHERE cityHash64('hot_delete_test_other') != 0"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marker := r.URL.Query().Get("param_marker")
		if marker == "" {
			t.Error("missing bound marker")
			return
		}
		if strings.Contains(otherCommand, marker) {
			fmt.Fprintln(w, `{"mutation_id":"wrong-job","is_done":1,"parts_to_do":0,"failed":0}`)
		}
	}))
	defer server.Close()
	store := NewClickHouseStore(server.URL, "", "", "dsse", "events")
	state, found, err := store.ManualDeleteMutationState(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatalf("another job selected by prefix: %+v", state)
	}
}

func TestManualDeleteMutationLookupFindsItsOwnQuotedMarker(t *testing.T) {
	job := "hot_delete_test"
	command := "DELETE WHERE cityHash64('hot_delete_test') != 0"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marker := r.URL.Query().Get("param_marker")
		if marker != "" && strings.Contains(command, marker) {
			fmt.Fprintln(w, `{"mutation_id":"own-job","is_done":0,"parts_to_do":2,"failed":0}`)
		}
	}))
	defer server.Close()
	store := NewClickHouseStore(server.URL, "", "", "dsse", "events")
	state, found, err := store.ManualDeleteMutationState(context.Background(), job)
	if err != nil || !found || state.ID != "own-job" {
		t.Fatalf("own mutation not selected: state=%+v found=%v err=%v", state, found, err)
	}
}
