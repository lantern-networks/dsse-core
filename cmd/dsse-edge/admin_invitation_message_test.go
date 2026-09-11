package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

// The invitation is text a person can paste into whatever channel they actually use. It must carry the link,
// say that the link works once, and say when it stops working — because the reader is the administrator
// being invited, not an operator reading an API.
func TestInvitationCarriesTheLinkAndItsLimits(t *testing.T) {
	now := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	msg := buildAdminInvitation("alice@corp.example", "https://console.example/?activate=TOKEN123", now)

	if msg.To != "alice@corp.example" {
		t.Fatalf("to = %q", msg.To)
	}
	if strings.TrimSpace(msg.Subject) == "" {
		t.Fatal("an invitation with no subject cannot be pasted into mail")
	}
	if !strings.Contains(msg.Body, "https://console.example/?activate=TOKEN123") {
		t.Fatalf("the body must contain the link a person will click:\n%s", msg.Body)
	}
	if !msg.SingleUse || msg.TTLHours != int(activationTTL.Hours()) {
		t.Fatalf("single_use=%v ttl=%d, want true and %d", msg.SingleUse, msg.TTLHours, int(activationTTL.Hours()))
	}
	if msg.ExpiresAt != now.Add(activationTTL).Format(time.RFC3339) {
		t.Fatalf("expires_at = %q, want the store's own window from now", msg.ExpiresAt)
	}
	// The body says the limits too. A screen can show the fields; the pasted text has to stand alone, because
	// the person receiving it never sees the screen.
	if !strings.Contains(msg.Body, "once") || !strings.Contains(msg.Body, msg.ExpiresAt) {
		t.Fatalf("the body must state that the link is single-use and when it expires:\n%s", msg.Body)
	}

	// ★ AND IT SAYS IT IN BOTH LANGUAGES (2026-08-17). This was the one piece of operator-facing text left in
	// English only, on a product whose every screen is written in the reader's language — pasted as it stands
	// into a Japanese organization's chat. The reader is the person being invited, who has no account and so no
	// stated language, so the message says the same thing twice rather than guessing. Asserted here because
	// the checks above are all satisfied by the English half alone: the Japanese could be deleted and nothing
	// would fail.
	for _, phrase := range []string{"管理者に招待されました", "パスワードを設定", "1回だけ"} {
		if !strings.Contains(msg.Body, phrase) {
			t.Fatalf("the Japanese half no longer says %q — half the readers are being addressed in a "+
				"language they may not read:\n%s", phrase, msg.Body)
		}
	}
	if !strings.Contains(msg.Subject, "有効化") || !strings.Contains(msg.Subject, "Activate") {
		t.Fatalf("the subject line is what a person sees first, in both languages: %q", msg.Subject)
	}
	// The link appears in each half, so neither half is a fragment that has to be read alongside the other.
	if strings.Count(msg.Body, "https://console.example/?activate=TOKEN123") != 2 {
		t.Fatalf("each half must carry the link a person will click:\n%s", msg.Body)
	}
}

// ★ The regression this exists for: the activation token is a single-use credential that sets an
// administrator's first password, and the default path (no sink configured) printed it into the process log
// in plain text, where it outlives its 24-hour window in whatever collects stdout.
func TestActivationLinkIsNotWrittenToTheProcessLog(t *testing.T) {
	var logged bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&logged)
	log.SetFlags(0)
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()

	link := "https://console.example/?activate=SUPERSECRETTOKEN"
	if err := sendActivationEmail("", "alice@corp.example", link, time.Now()); err != nil {
		t.Fatalf("sendActivationEmail: %v", err)
	}

	out := logged.String()
	if strings.Contains(out, "SUPERSECRETTOKEN") || strings.Contains(out, link) {
		t.Fatalf("the activation link reached the log:\n%s", out)
	}
	// It should still say an invitation happened — the absence of a record is its own problem.
	if !strings.Contains(out, "alice@corp.example") {
		t.Fatalf("the log should record that an invite was created, without the credential:\n%s", out)
	}
}

// The file sink is a deliberate lab convenience and keeps the link: it is a file an operator chose to
// configure, not the process log. Kept as a test so removing the sink is a decision, not a slip.
func TestConfiguredSinkStillReceivesTheLink(t *testing.T) {
	dir := t.TempDir()
	sink := dir + "/invites.log"
	link := "https://console.example/?activate=TOKENINSINK"
	if err := sendActivationEmail(sink, "bob@corp.example", link, time.Now()); err != nil {
		t.Fatalf("sendActivationEmail: %v", err)
	}
	raw, err := os.ReadFile(sink)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	if !strings.Contains(string(raw), link) {
		t.Fatalf("a configured sink must still receive the link, got:\n%s", raw)
	}
}
