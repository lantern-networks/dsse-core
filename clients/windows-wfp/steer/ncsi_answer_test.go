package main

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func buildDNSQuery(name string, typ dnsmessage.Type) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	out, _ := b.Finish()
	return out
}

func TestNCSIDNSReplyA(t *testing.T) {
	reply, ok := ncsiDNSReply(buildDNSQuery("dns.msftncsi.com.", dnsmessage.TypeA))
	if !ok {
		t.Fatal("expected an NCSI A reply")
	}
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil || !h.Response {
		t.Fatalf("reply is not a response: %v", err)
	}
	if h.ID != 0x1234 {
		t.Fatalf("reply ID = %x, want 1234 (must echo the query)", h.ID)
	}
	_ = p.SkipAllQuestions()
	ah, err := p.AnswerHeader()
	if err != nil || ah.Type != dnsmessage.TypeA {
		t.Fatalf("answer header: %v type=%v", err, ah.Type)
	}
	a, err := p.AResource()
	if err != nil {
		t.Fatalf("no A answer: %v", err)
	}
	if net.IP(a.A[:]).String() != "131.107.255.255" {
		t.Fatalf("A = %v, want 131.107.255.255", net.IP(a.A[:]))
	}
}

func TestNCSIDNSReplyAAAA(t *testing.T) {
	reply, ok := ncsiDNSReply(buildDNSQuery("dns.msftncsi.com.", dnsmessage.TypeAAAA))
	if !ok {
		t.Fatal("expected an NCSI AAAA reply")
	}
	var p dnsmessage.Parser
	if _, err := p.Start(reply); err != nil {
		t.Fatal(err)
	}
	_ = p.SkipAllQuestions()
	ah, err := p.AnswerHeader()
	if err != nil || ah.Type != dnsmessage.TypeAAAA {
		t.Fatalf("answer header: %v type=%v", err, ah.Type)
	}
	aaaa, err := p.AAAAResource()
	if err != nil {
		t.Fatalf("no AAAA answer: %v", err)
	}
	if net.IP(aaaa.AAAA[:]).String() != "fd3e:4f5a:5b81::1" {
		t.Fatalf("AAAA = %v, want fd3e:4f5a:5b81::1", net.IP(aaaa.AAAA[:]))
	}
}

func TestNCSIDNSReplyIgnoresOtherNames(t *testing.T) {
	if _, ok := ncsiDNSReply(buildDNSQuery("www.example.com.", dnsmessage.TypeA)); ok {
		t.Fatal("must not answer non-NCSI names locally")
	}
}

func TestIsNCSIWebProbe(t *testing.T) {
	probe := []byte("GET /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\nConnection: Close\r\n\r\n")
	if !isNCSIWebProbe(probe) {
		t.Fatal("expected the connecttest GET to be recognized")
	}
	ncsi := []byte("GET /ncsi.txt HTTP/1.1\r\nHost: www.msftncsi.com\r\n\r\n")
	if !isNCSIWebProbe(ncsi) {
		t.Fatal("expected the ncsi.txt GET to be recognized")
	}
	notProbe := []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
	if isNCSIWebProbe(notProbe) {
		t.Fatal("a normal site must NOT be treated as an NCSI probe")
	}
	post := []byte("POST /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\n\r\n")
	if isNCSIWebProbe(post) {
		t.Fatal("only GET is an NCSI probe")
	}
}

func TestAnswerNCSIWebProbeOverPipe(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_, _ = c1.Write([]byte("GET /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\n\r\n"))
	}()
	done := make(chan struct{})
	go func() {
		handled, _ := answerNCSIWebProbe(c2)
		if !handled {
			t.Errorf("expected the probe to be answered")
		}
		close(done)
	}()
	resp := make([]byte, 512)
	n, err := c1.Read(resp)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.Contains(resp[:n], []byte("Microsoft Connect Test")) || !bytes.Contains(resp[:n], []byte("200 OK")) {
		t.Fatalf("response missing expected NCSI body/status: %q", resp[:n])
	}
	<-done
}
