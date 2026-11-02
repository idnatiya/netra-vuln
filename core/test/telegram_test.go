package test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/entity"
)

type sentMessage struct {
	ChatID int64  `json:"chat_id"`
	Text   string `json:"text"`
}

// fakeTelegram records sendMessage calls; it returns a function that drains them.
func fakeTelegram(t *testing.T) func() []sentMessage {
	t.Helper()
	var mu sync.Mutex
	var sent []sentMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/botTEST/sendMessage", r.URL.Path)
		var m sentMessage
		require.NoError(t, json.NewDecoder(r.Body).Decode(&m))
		mu.Lock()
		sent = append(sent, m)
		mu.Unlock()
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	t.Cleanup(srv.Close)
	uc.Telegram.Token, uc.Telegram.APIURL, uc.Telegram.DigestAt = "TEST", srv.URL, ""
	uc.Telegram.PublicURL = "https://vuln.example"
	t.Cleanup(func() { uc.Telegram.Token, uc.Telegram.PublicURL = "", "" })
	return func() []sentMessage {
		mu.Lock()
		defer mu.Unlock()
		out := sent
		sent = nil
		return out
	}
}

func byChat(msgs []sentMessage) map[int64][]string {
	out := map[int64][]string{}
	for _, m := range msgs {
		out[m.ChatID] = append(out[m.ChatID], m.Text)
	}
	return out
}

func TestTelegramNotifier(t *testing.T) {
	ClearAll(t)
	drain := fakeTelegram(t)
	ctx := context.Background()
	a := enrollHost(t, "acme", "web-01")
	b := enrollHost(t, "globex", "api-01")
	require.NoError(t, uc.Telegram.AddChat(ctx, 1, ""))
	require.NoError(t, uc.Telegram.AddChat(ctx, 2, "acme"))
	require.NoError(t, uc.Telegram.AddChat(ctx, 3, "globex"))
	ingest(t, a, "ok", vuln("CVE-1", "HIGH", "openssl"))
	ingest(t, b, "ok")
	require.NoError(t, db.Exec("UPDATE hosts SET last_heartbeat_at = ?", time.Now().UTC()).Error)

	// The first tick records the state only.
	require.NoError(t, uc.Telegram.Tick(ctx))
	assert.Empty(t, drain())

	ingest(t, a, "ok", vuln("CVE-1", "HIGH", "openssl"), vuln("CVE-2", "CRITICAL", "openssl"), vuln("CVE-3", "LOW", "zlib"))
	require.NoError(t, uc.Telegram.Tick(ctx))
	got := byChat(drain())
	require.Len(t, got[1], 1, "admin chat")
	require.Len(t, got[2], 1, "acme chat")
	assert.Empty(t, got[3], "globex must not see acme")
	assert.Contains(t, got[2][0], "1 critical new — web-01")
	assert.Contains(t, got[2][0], "https://vuln.example/hosts/")
	assert.NotContains(t, got[2][0], "high", "CVE-1 is not new")

	require.NoError(t, uc.Telegram.Tick(ctx))
	assert.Empty(t, drain(), "same scan is not sent twice")

	// Repeated scan errors alert once.
	for range entity.ErrorStreak {
		ingest(t, b, "error")
	}
	require.NoError(t, uc.Telegram.Tick(ctx))
	got = byChat(drain())
	require.Len(t, got[3], 1)
	assert.Contains(t, got[3][0], "Scan failed 3x in a row — api-01")
	assert.Empty(t, got[2])
	ingest(t, b, "error")
	require.NoError(t, uc.Telegram.Tick(ctx))
	assert.Empty(t, drain())

	// Not reporting, then recovered.
	old := time.Now().UTC().Add(-3 * time.Hour)
	require.NoError(t, db.Exec("UPDATE hosts SET last_heartbeat_at = ? WHERE id = ?", old, a.ID).Error)
	require.NoError(t, uc.Telegram.Tick(ctx))
	got = byChat(drain())
	require.Len(t, got[2], 1)
	assert.Contains(t, got[2][0], "Not reporting — web-01")
	require.NoError(t, uc.Telegram.Tick(ctx))
	assert.Empty(t, drain())
	require.NoError(t, db.Exec("UPDATE hosts SET last_heartbeat_at = ? WHERE id = ?", time.Now().UTC(), a.ID).Error)
	require.NoError(t, uc.Telegram.Tick(ctx))
	got = byChat(drain())
	require.Len(t, got[2], 1)
	assert.Contains(t, got[2][0], "Recovered — web-01")

	// Daily digest once per day, per chat.
	uc.Telegram.DigestAt = "00:00"
	require.NoError(t, uc.Telegram.Tick(ctx))
	got = byChat(drain())
	require.Len(t, got[1], 1)
	assert.Contains(t, got[1][0], "Open: 1 critical · 1 high")
	assert.Contains(t, got[1][0], "globex")
	assert.NotContains(t, got[2][0], "api-01")
	require.NoError(t, uc.Telegram.Tick(ctx))
	assert.Empty(t, drain())
}

func TestTelegramEOLOncePerLabel(t *testing.T) {
	ClearAll(t)
	drain := fakeTelegram(t)
	fakeEOL(t)
	ctx := context.Background()
	_ = uc.EOL.Refresh(ctx) // products without fake data fail; php/vue are enough
	h := enrollHost(t, "acme", "web-01")
	require.NoError(t, uc.Telegram.AddChat(ctx, 1, ""))
	require.NoError(t, uc.Telegram.Tick(ctx)) // first tick: state only

	rep := report(h, "ok")
	rep.Software = []wire.Software{
		{Name: "vue", Version: "2.7.16", Path: "/srv/frontend"},
		{Name: "vue", Version: "2.7.16", Path: "/srv/frontend-stage"},
	}
	require.Equal(t, http.StatusNoContent, agentStatus(t, "POST", "/api/v1/report", h.Token, mustJSON(rep), true))
	require.NoError(t, uc.Telegram.Tick(ctx))
	var eol []string
	for _, m := range drain() {
		if strings.Contains(m.Text, "End of life") {
			eol = append(eol, m.Text)
		}
	}
	require.Len(t, eol, 1)
	assert.Equal(t, 1, strings.Count(eol[0], "vue 2"), eol[0])
	require.NoError(t, uc.Telegram.Tick(ctx))
	assert.Empty(t, drain(), "an alert raised from two paths is not resent")
}

func TestTelegramCommands(t *testing.T) {
	ClearAll(t)
	fakeTelegram(t)
	ctx := context.Background()
	a := enrollHost(t, "acme", "web-01")
	b := enrollHost(t, "globex", "api-01")
	ingest(t, a, "ok", vuln("CVE-2024-6387", "CRITICAL", "openssh-server"))
	ingest(t, b, "ok", vuln("CVE-2024-6387", "CRITICAL", "openssh-server"))
	require.NoError(t, uc.Telegram.AddChat(ctx, 2, "acme"))

	reply, err := uc.Telegram.Handle(ctx, 99, "/status")
	require.NoError(t, err)
	assert.Contains(t, reply, "Not authorized. Chat id: <code>99</code>")

	reply, err = uc.Telegram.Handle(ctx, 2, "/cve@netra_bot cve-2024-6387")
	require.NoError(t, err)
	assert.Contains(t, reply, "1 host(s)")
	assert.Contains(t, reply, "web-01")
	assert.NotContains(t, reply, "api-01", "other client's host")

	reply, err = uc.Telegram.Handle(ctx, 2, "/host api-01")
	require.NoError(t, err)
	assert.Equal(t, "Host not found.", reply)

	reply, err = uc.Telegram.Handle(ctx, 2, "/host WEB-01")
	require.NoError(t, err)
	assert.Contains(t, reply, "Open: 1 critical · 0 high")
	assert.Contains(t, reply, "1.0 — 1 critical")

	reply, err = uc.Telegram.Handle(ctx, 2, "/status")
	require.NoError(t, err)
	assert.Contains(t, reply, "Open: 1 critical")

	require.NoError(t, uc.Telegram.AddChat(ctx, 1, ""))
	require.NoError(t, db.Exec("UPDATE hosts SET last_heartbeat_at = ?", time.Now().UTC()).Error)
	reply, err = uc.Telegram.Handle(ctx, 1, "/hosts")
	require.NoError(t, err)
	assert.Contains(t, reply, "<b>acme</b> — 1 host(s)")
	assert.Contains(t, reply, "🔴 api-01 — 1 critical")
	reply, err = uc.Telegram.Handle(ctx, 1, "/hosts ACME")
	require.NoError(t, err)
	assert.Equal(t, "🔴 web-01 — 1 critical", reply)
	reply, err = uc.Telegram.Handle(ctx, 2, "/hosts globex")
	require.NoError(t, err)
	assert.Equal(t, "Client not found.", reply, "client chat cannot list another client")

	reply, _ = uc.Telegram.Handle(ctx, 2, "/nope")
	assert.True(t, strings.HasPrefix(reply, "Commands:"))
}

func TestTelegramEscapesHTML(t *testing.T) {
	h := entity.HostSummary{Host: entity.Host{ID: 1, Hostname: "<b>x</b>"}, ClientName: "a&b"}
	msg := entity.MsgStale(h, "")
	assert.Contains(t, msg, "&lt;b&gt;x&lt;/b&gt;")
	assert.Contains(t, msg, "a&amp;b")
}
