package entity

import (
	"fmt"
	"html"
	"strings"
	"time"
)

// TelegramChat may use the bot; ClientID nil = admin chat (every client).
type TelegramChat struct {
	ChatID    int64     `gorm:"column:chat_id;primaryKey;autoIncrement:false"`
	ClientID  *int64    `gorm:"column:client_id"`
	CreatedAt time.Time `gorm:"column:created_at"`
	Client    *Client   `gorm:"foreignKey:ClientID;references:ID"`
}

func (TelegramChat) TableName() string { return "telegram_chats" }

// Sees reports whether the chat may see data of clientID.
func (c TelegramChat) Sees(clientID int64) bool { return c.ClientID == nil || *c.ClientID == clientID }

// NotifyAlert is an alert already sent for a host, kept until it clears.
type NotifyAlert struct {
	HostID int64  `gorm:"column:host_id;primaryKey"`
	Kind   string `gorm:"column:kind;primaryKey"`
	Label  string `gorm:"column:label;primaryKey"`
}

func (NotifyAlert) TableName() string { return "notify_alerts" }

const (
	AlertStale = "stale"
	AlertError = "error"
	AlertEOL   = "eol"
	AlertSoon  = "eol_soon"
)

// ErrorStreak is how many failed scans in a row raise an alert.
const ErrorStreak = 3

// NewFindingGroup is one component's new open critical/high findings in a scan.
type NewFindingGroup struct {
	Kind     ComponentKind `gorm:"column:component_kind"`
	Key      string        `gorm:"column:component"`
	Critical int           `gorm:"column:critical"`
	High     int           `gorm:"column:high"`
}

// CVEHost is one host affected by a CVE.
type CVEHost struct {
	ClientID   int64  `gorm:"column:client_id"`
	ClientName string `gorm:"column:client_name"`
	Hostname   string `gorm:"column:hostname"`
	Pkg        string `gorm:"column:pkg"`
	Severity   string `gorm:"column:severity"`
	Installed  string `gorm:"column:installed_version"`
	Fixed      string `gorm:"column:fixed_version"`
	Status     string `gorm:"column:status"`
	Note       string `gorm:"column:note"`
}

// Message formatting (Telegram HTML parse mode): every dynamic value is escaped.

var esc = html.EscapeString

func tgTime(t time.Time) string { return t.UTC().Format("02 Jan 15:04 UTC") }

func link(publicURL string, hostID int64) string {
	if publicURL == "" {
		return ""
	}
	return fmt.Sprintf("\n🔗 %s/hosts/%d", esc(strings.TrimRight(publicURL, "/")), hostID)
}

func componentName(g NewFindingGroup) string {
	if g.Kind == ComponentOS && strings.HasPrefix(g.Key, "linux") {
		return "Linux kernel " + g.Key + " (reboot needed)"
	}
	return g.Key
}

func sevCounts(crit, high int) string {
	var parts []string
	if crit > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", crit))
	}
	if high > 0 {
		parts = append(parts, fmt.Sprintf("%d high", high))
	}
	return strings.Join(parts, ", ")
}

// MsgNewFindings announces the new critical/high findings of one scan.
func MsgNewFindings(h HostSummary, groups []NewFindingGroup, publicURL string) string {
	crit, high := 0, 0
	for _, g := range groups {
		crit += g.Critical
		high += g.High
	}
	icon := "🟠"
	if crit > 0 {
		icon = "🔴"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s <b>%s new — %s</b>\nClient: %s", icon, sevCounts(crit, high), esc(h.Hostname), esc(h.ClientName))
	if h.LastScanAt != nil {
		fmt.Fprintf(&b, " · scan %s", tgTime(*h.LastScanAt))
	}
	b.WriteString("\n\nTop:")
	for i, g := range groups {
		if i == 5 {
			fmt.Fprintf(&b, "\n• … %d more", len(groups)-5)
			break
		}
		fmt.Fprintf(&b, "\n• %s — %s", esc(componentName(g)), sevCounts(g.Critical, g.High))
	}
	if h.ResolvedInLastScan > 0 {
		fmt.Fprintf(&b, "\n\nResolved in this scan: %d", h.ResolvedInLastScan)
	}
	b.WriteString(link(publicURL, h.ID))
	return b.String()
}

// MsgStale announces a host that stopped reporting.
func MsgStale(h HostSummary, publicURL string) string {
	last := "never"
	if h.LastHeartbeatAt != nil {
		last = tgTime(*h.LastHeartbeatAt)
	}
	return fmt.Sprintf("⚠️ <b>Not reporting — %s</b> (%s)\nLast heartbeat: %s%s", esc(h.Hostname), esc(h.ClientName), last, link(publicURL, h.ID))
}

// MsgRecovered announces a host that reports again.
func MsgRecovered(h HostSummary) string {
	return fmt.Sprintf("✅ <b>Recovered — %s</b> (%s) is reporting again", esc(h.Hostname), esc(h.ClientName))
}

// MsgScanError announces repeated failed scans.
func MsgScanError(h HostSummary, lastError, publicURL string) string {
	return fmt.Sprintf("❌ <b>Scan failed %dx in a row — %s</b> (%s)\nError: <code>%s</code>%s",
		ErrorStreak, esc(h.Hostname), esc(h.ClientName), esc(truncate(lastError, 300)), link(publicURL, h.ID))
}

// EOLItem is one newly end-of-life (or soon) software on a host.
type EOLItem struct {
	Host  HostSummary
	Label string
	Soon  bool
}

// MsgEOL lists software that newly reached (or nears) end of life.
func MsgEOL(items []EOLItem) string {
	var b strings.Builder
	fmt.Fprintf(&b, "⏳ <b>End of life — %d item(s)</b>", len(items))
	for _, it := range items {
		state := "end of life"
		if it.Soon {
			state = fmt.Sprintf("ends within %d days", int(EOLSoonWithin.Hours()/24))
		}
		fmt.Fprintf(&b, "\n• %s (%s): %s — %s", esc(it.Host.Hostname), esc(it.Host.ClientName), esc(it.Label), state)
	}
	return b.String()
}

// NeedsAttention orders hosts for the digest; 0 = fine.
func attentionScore(h HostSummary) int {
	s := h.OpenCritical*10 + h.OpenHigh
	if h.StaleScan || h.StaleHeartbeat || h.LastScanStatus == StatusError {
		s += 1000
	}
	return s
}

func attentionReason(h HostSummary) string {
	switch {
	case h.StaleScan || h.StaleHeartbeat:
		return "not reporting"
	case h.LastScanStatus == StatusError:
		return "scan error"
	}
	return sevCounts(h.OpenCritical, h.OpenHigh)
}

// MsgDigest summarises the active hosts the chat may see.
func MsgDigest(day time.Time, hosts []HostSummary, resolved24h int, agentVersion string) string {
	type agg struct{ hosts, crit, high int }
	byClient := map[string]*agg{}
	var clients []string
	total := agg{}
	outdated := 0
	var active []HostSummary
	for _, h := range hosts {
		if !h.Active() {
			continue
		}
		active = append(active, h)
		a := byClient[h.ClientName]
		if a == nil {
			a = &agg{}
			byClient[h.ClientName] = a
			clients = append(clients, h.ClientName)
		}
		a.hosts++
		a.crit += h.OpenCritical
		a.high += h.OpenHigh
		total.crit += h.OpenCritical
		total.high += h.OpenHigh
		if agentVersion != "" && strings.TrimPrefix(h.Meta.AgentVersion, "v") != strings.TrimPrefix(agentVersion, "v") {
			outdated++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "📊 <b>Summary %s</b>\nOpen: %d critical · %d high\n", day.UTC().Format("02 Jan 2006"), total.crit, total.high)
	if len(clients) > 1 {
		b.WriteString("\nPer client:")
		for _, c := range clients {
			a := byClient[c]
			fmt.Fprintf(&b, "\n• %s — %d crit / %d high · %d host(s)", esc(c), a.crit, a.high, a.hosts)
		}
		b.WriteString("\n")
	}
	sortByAttention(active)
	n := 0
	for _, h := range active {
		if n == 5 || attentionScore(h) == 0 {
			break
		}
		if n == 0 {
			b.WriteString("\nNeeds attention:")
		}
		n++
		fmt.Fprintf(&b, "\n%d. %s — %s", n, esc(h.Hostname), esc(attentionReason(h)))
	}
	if n == 0 {
		b.WriteString("\nNothing needs attention.")
	}
	fmt.Fprintf(&b, "\n\nResolved in 24h: %d", resolved24h)
	if outdated > 0 {
		fmt.Fprintf(&b, " · Agent outdated: %d host(s)", outdated)
	}
	return b.String()
}

func sortByAttention(hosts []HostSummary) {
	for i := 1; i < len(hosts); i++ { // insertion sort: a few dozen hosts, stable
		for j := i; j > 0 && attentionScore(hosts[j]) > attentionScore(hosts[j-1]); j-- {
			hosts[j], hosts[j-1] = hosts[j-1], hosts[j]
		}
	}
}

// MsgHost answers /host.
func MsgHost(h HostSummary, groups []NewFindingGroup, publicURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b> (%s)\n%s %s · agent %s", esc(h.Hostname), esc(h.ClientName), esc(h.Meta.OSName), esc(h.Meta.OSVersion), esc(h.Meta.AgentVersion))
	if !h.Active() {
		b.WriteString("\nRevoked")
	}
	fmt.Fprintf(&b, "\nOpen: %d critical · %d high", h.OpenCritical, h.OpenHigh)
	if h.LastScanAt != nil {
		fmt.Fprintf(&b, "\nLast scan: %s (%s)", tgTime(*h.LastScanAt), esc(string(h.LastScanStatus)))
	}
	if reason := attentionReason(h); h.StaleScan || h.StaleHeartbeat || h.LastScanStatus == StatusError {
		fmt.Fprintf(&b, "\n⚠️ %s", reason)
	}
	if h.Meta.RebootRequired {
		b.WriteString("\nReboot required")
	}
	for _, l := range h.EOL {
		fmt.Fprintf(&b, "\nEnd of life: %s", esc(l))
	}
	if len(groups) > 0 {
		b.WriteString("\n\nWhat to fix:")
		for i, g := range groups {
			if i == 5 {
				fmt.Fprintf(&b, "\n• … %d more", len(groups)-5)
				break
			}
			fmt.Fprintf(&b, "\n• %s — %s", esc(componentName(g)), sevCounts(g.Critical, g.High))
		}
	}
	b.WriteString(link(publicURL, h.ID))
	return b.String()
}

// MsgCVE answers /cve.
func MsgCVE(cve string, rows []CVEHost) string {
	if len(rows) == 0 {
		return fmt.Sprintf("%s: no unresolved findings.", esc(cve))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b> (%s, %s) — %d host(s)", esc(cve), esc(rows[0].Pkg), strings.ToLower(esc(rows[0].Severity)), len(rows))
	for _, r := range rows {
		fmt.Fprintf(&b, "\n• %s (%s) — ", esc(r.Hostname), esc(r.ClientName))
		if r.Status != string(TriageOpen) {
			fmt.Fprintf(&b, "%s", esc(strings.ReplaceAll(r.Status, "_", " ")))
			if r.Note != "" {
				fmt.Fprintf(&b, ": \"%s\"", esc(truncate(r.Note, 100)))
			}
			continue
		}
		fmt.Fprintf(&b, "%s %s", esc(r.Pkg), esc(r.Installed))
		if r.Fixed != "" {
			fmt.Fprintf(&b, " → %s", esc(r.Fixed))
		}
	}
	return b.String()
}

// MsgHosts answers /hosts: active hosts per client, worst first.
func MsgHosts(hosts []HostSummary) string {
	byClient := map[string][]HostSummary{}
	var clients []string
	for _, h := range hosts {
		if !h.Active() {
			continue
		}
		if _, ok := byClient[h.ClientName]; !ok {
			clients = append(clients, h.ClientName)
		}
		byClient[h.ClientName] = append(byClient[h.ClientName], h)
	}
	if len(clients) == 0 {
		return "No hosts."
	}
	const maxLines = 80 // Telegram messages hold 4096 characters
	var b strings.Builder
	lines, total := 0, 0
	for _, c := range clients {
		list := byClient[c]
		total += len(list)
		sortByAttention(list)
		if lines >= maxLines {
			continue
		}
		if len(clients) > 1 {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "<b>%s</b> — %d host(s)\n", esc(c), len(list))
		}
		for _, h := range list {
			if lines == maxLines {
				break
			}
			lines++
			icon := "🟢"
			switch {
			case h.StaleScan || h.StaleHeartbeat || h.LastScanStatus == StatusError:
				icon = "⚠️"
			case h.OpenCritical > 0:
				icon = "🔴"
			case h.OpenHigh > 0:
				icon = "🟠"
			}
			state := attentionReason(h)
			if state == "" {
				state = "no open critical/high"
			}
			fmt.Fprintf(&b, "%s %s — %s\n", icon, esc(h.Hostname), esc(state))
		}
	}
	if total > lines {
		fmt.Fprintf(&b, "… %d more", total-lines)
	}
	return strings.TrimRight(b.String(), "\n")
}
