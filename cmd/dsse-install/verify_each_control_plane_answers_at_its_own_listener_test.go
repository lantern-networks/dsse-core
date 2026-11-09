package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestADirectControlPlanePeerThatAnswersPasses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/leader" {
			t.Errorf("asked %s, want /leader", r.URL.Path)
		}
		w.WriteHeader(http.StatusServiceUnavailable) // a standby answers too
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	env := map[string]string{controlPlanePeersKey: "https://example.com@" + srv.Listener.Addr().String()}
	got := verifyControlPlanesAnswerAtPort(srv.Client(), env, port)
	if len(got) != 1 || !got[0].ok {
		t.Fatalf("a control plane that answered /leader with 503 over a verified connection was not counted: %+v", got)
	}
}

func TestADirectControlPlanePeerThatDoesNotAnswerFailsAndSaysWhatToOpen(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close() // nothing listens here now
	_, port, _ := net.SplitHostPort(address)
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	env := map[string]string{controlPlanePeersKey: "https://example.com@" + address}
	got := verifyControlPlanesAnswerAtPort(srv.Client(), env, port)
	if len(got) != 1 || got[0].ok {
		t.Fatalf("an unreachable direct peer passed: %+v", got)
	}
	if !strings.Contains(got[0].note, "Allow TCP 19543 and 19545") {
		t.Errorf("the failure does not say which ports to open: %s", got[0].note)
	}
}

func TestDoorwayOnlyPeersAreNotAskedAboutDirectListeners(t *testing.T) {
	env := map[string]string{controlPlanePeersKey: "https://admin.region-b.example.test@10.0.0.2:443"}
	if got := verifyEachControlPlaneAnswersAtItsOwnListener(http.DefaultClient, env); len(got) != 0 {
		t.Fatalf("a deployment whose peers are doorways was asked about direct listeners: %+v", got)
	}
}

func TestADirectDataListenerThatAnswersHealthzPasses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("asked %s, want /healthz", r.URL.Path)
		}
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	env := map[string]string{controlPlaneDataPeersKey: "https://example.com@" + srv.Listener.Addr().String()}
	if got := verifyDataListenersAnswer(srv.Client(), env, port); len(got) != 1 || !got[0].ok {
		t.Fatalf("a data listener answering /healthz was not counted: %+v", got)
	}
}

// The admin listener answering is not evidence about the data listener (measured: a closed 19545
// with a healthy 19543).
func TestAClosedDataListenerFailsEvenWhenItsAdminListenerAnswers(t *testing.T) {
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer admin.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().String()
	_ = l.Close()
	_, adminPort, _ := net.SplitHostPort(admin.Listener.Addr().String())
	_, dataPort, _ := net.SplitHostPort(closed)
	env := map[string]string{
		controlPlanePeersKey:     "https://example.com@" + admin.Listener.Addr().String(),
		controlPlaneDataPeersKey: "https://example.com@" + closed,
	}
	if got := verifyControlPlanesAnswerAtPort(admin.Client(), env, adminPort); len(got) != 1 || !got[0].ok {
		t.Fatalf("setup: the admin listener should answer: %+v", got)
	}
	got := verifyDataListenersAnswer(admin.Client(), env, dataPort)
	if len(got) != 1 || got[0].ok || !strings.Contains(got[0].note, "Allow TCP 19545") {
		t.Fatalf("a closed data listener behind a healthy admin listener passed or said nothing useful: %+v", got)
	}
}
