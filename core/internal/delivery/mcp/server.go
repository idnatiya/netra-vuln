// Package mcp exposes read-only vulnerability data to AI clients (Claude,
// Codex, OpenCode, Antigravity, Cursor, ...) over MCP Streamable HTTP. Tools call
// the same use cases as the admin API and return the admin API's models.
package mcp

import (
	"context"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"

	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/usecase"
)

const (
	defaultPageSize = 25
	maxPageSize     = 100
)

type UseCases struct {
	Client  *usecase.ClientUseCase
	Host    *usecase.HostUseCase
	Finding *usecase.FindingUseCase
}

type ClientsOut struct {
	Clients []model.ClientResponse `json:"clients"`
}

type HostsIn struct {
	Client string `json:"client,omitempty" jsonschema:"client name; empty = every client"`
}

type HostsOut struct {
	Hosts []model.HostResponse `json:"hosts"`
}

type FindingsIn struct {
	Client          string `json:"client,omitempty" jsonschema:"client name"`
	HostID          int64  `json:"host_id,omitempty" jsonschema:"host id from list_hosts"`
	Severity        string `json:"severity,omitempty" jsonschema:"UNKNOWN, LOW, MEDIUM, HIGH or CRITICAL"`
	Status          string `json:"status,omitempty" jsonschema:"triage status: open, accepted or false_positive; empty = any"`
	Query           string `json:"query,omitempty" jsonschema:"substring of a CVE id or package name"`
	IncludeResolved bool   `json:"include_resolved,omitempty" jsonschema:"also return findings no longer seen by the last scan"`
	Page            int    `json:"page,omitempty" jsonschema:"1-based page"`
	PageSize        int    `json:"page_size,omitempty" jsonschema:"findings per page, 1-100 (default 25); use 100 to page through a large host"`
}

type FindingsOut struct {
	Findings []model.FindingResponse `json:"findings"`
	Paging   *model.PageMetadata     `json:"paging"`
}

type ComponentsIn struct {
	HostID int64  `json:"host_id" jsonschema:"host id from list_hosts"`
	Status string `json:"status,omitempty" jsonschema:"open (default), accepted or false_positive"`
}

type ComponentsOut struct {
	Components []model.ComponentResponse `json:"components"`
}

type TriageFindingIn struct {
	FindingID int64  `json:"finding_id" jsonschema:"finding id from search_findings"`
	Status    string `json:"status" jsonschema:"open (reopen), accepted (risk accepted) or false_positive"`
	Note      string `json:"note,omitempty" jsonschema:"why, and until when; shown in the dashboard"`
}

type TriageComponentIn struct {
	HostID int64  `json:"host_id" jsonschema:"host id"`
	Kind   string `json:"kind" jsonschema:"component kind from host_components: os, app or binary"`
	Key    string `json:"key" jsonschema:"component key from host_components"`
	Status string `json:"status" jsonschema:"open (reopen), accepted (risk accepted) or false_positive"`
	Note   string `json:"note,omitempty" jsonschema:"why, and until when; shown in the dashboard"`
}

type TriageOut struct {
	Updated int `json:"updated"`
}

// auditNote marks a verdict as made through MCP, so the dashboard shows where it came from.
func auditNote(note string, auth *model.Auth) string {
	tag := "[via MCP: " + auth.McpTokenName + "]"
	if note = strings.TrimSpace(note); note == "" {
		return tag
	}
	return note + " " + tag
}

// NewServer registers the read-only tools, plus the triage tools when the
// token allows triage.
func NewServer(uc *UseCases, log *logrus.Logger, version string, auth *model.Auth) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "netra-vuln", Version: version}, &mcp.ServerOptions{
		Instructions: "Package vulnerabilities (Trivy) of Linux VMs grouped by client. " +
			"Open = unresolved and not triaged; accepted / false_positive were triaged by an admin. " +
			"A component is one upgrade action: kind os = OS packages from one source package, app = language packages of one app folder, binary = one Go/Rust binary. " +
			"Calls are rate limited per admin: for a large host prefer host_components, filter search_findings by host_id and severity, use page_size 100, and on HTTP 429 wait the Retry-After seconds.",
	})
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}

	mcp.AddTool(s, &mcp.Tool{Name: "list_clients", Annotations: readOnly,
		Description: "List clients with host count and open critical/high findings."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ClientsOut, error) {
			out, err := uc.Client.List(ctx)
			return nil, ClientsOut{Clients: out}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "list_hosts", Annotations: readOnly,
		Description: "List hosts (VMs) with OS, agent, last scan and heartbeat, stale flags, and open critical/high counts. Revoked hosts have revoked_at set."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in HostsIn) (*mcp.CallToolResult, HostsOut, error) {
			out, err := uc.Host.Search(ctx, &model.SearchHostRequest{Client: in.Client})
			return nil, HostsOut{Hosts: out}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "search_findings", Annotations: readOnly,
		Description: "Search findings (one CVE in one package on one host), most severe first. paging.total_page tells how many pages there are."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in FindingsIn) (*mcp.CallToolResult, FindingsOut, error) {
			size := in.PageSize
			if size <= 0 {
				size = defaultPageSize
			}
			out, paging, err := uc.Finding.Search(ctx, &model.SearchFindingRequest{Client: in.Client, HostID: in.HostID,
				Severity: in.Severity, Status: in.Status, Query: in.Query, IncludeResolved: in.IncludeResolved,
				Page: in.Page, Size: min(size, maxPageSize)})
			return nil, FindingsOut{Findings: out, Paging: paging}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "host_components", Annotations: readOnly,
		Description: "What to fix on one host: unresolved findings grouped into components (one upgrade action each), worst first."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ComponentsIn) (*mcp.CallToolResult, ComponentsOut, error) {
			status := in.Status
			if status == "" {
				status = "open"
			}
			out, err := uc.Finding.Components(ctx, &model.SearchFindingRequest{HostID: in.HostID, Status: status})
			return nil, ComponentsOut{Components: out}, err
		})

	if !auth.CanTriage {
		return s
	}
	write := &mcp.ToolAnnotations{DestructiveHint: new(true), IdempotentHint: true}
	mcp.AddTool(s, &mcp.Tool{Name: "triage_finding", Annotations: write,
		Description: "Set the triage verdict of one finding: accepted (risk accepted), false_positive, or open (reopen). " +
			"Accepted and false positive findings leave the open totals. Confirm with the user first."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in TriageFindingIn) (*mcp.CallToolResult, TriageOut, error) {
			if err := uc.Finding.Triage(ctx, &model.TriageFindingRequest{ID: in.FindingID, Status: in.Status, Note: auditNote(in.Note, auth)}); err != nil {
				return nil, TriageOut{}, err
			}
			log.WithFields(logrus.Fields{"by": auth.Username, "token": auth.McpTokenName, "id": in.FindingID, "status": in.Status}).Info("Finding triaged via MCP")
			return nil, TriageOut{Updated: 1}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "triage_component", Annotations: write,
		Description: "Set one triage verdict on every unresolved finding of a component (from host_components). Confirm with the user first."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in TriageComponentIn) (*mcp.CallToolResult, TriageOut, error) {
			out, err := uc.Finding.TriageComponent(ctx, &model.TriageComponentRequest{HostID: in.HostID, Kind: in.Kind, Key: in.Key,
				Status: in.Status, Note: auditNote(in.Note, auth)})
			if err != nil {
				return nil, TriageOut{}, err
			}
			log.WithFields(logrus.Fields{"by": auth.Username, "token": auth.McpTokenName, "host_id": in.HostID, "component": in.Key,
				"status": in.Status, "updated": out.Updated}).Info("Component triaged via MCP")
			return nil, TriageOut{Updated: out.Updated}, nil
		})
	return s
}

// NewHandler serves the tools statelessly with plain JSON responses, so every
// request is self-contained and passes through the Fiber auth middleware. Mount
// it with adaptor.HTTPHandlerWithContext so the token's admin reaches getServer.
// ponytail: builds a server per request (tool schemas re-inferred); cache one
// read-only and one triage server per token if MCP traffic ever gets heavy.
func NewHandler(uc *UseCases, log *logrus.Logger, version string) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		ctx, _ := adaptor.LocalContextFromHTTPRequest(r)
		if ctx == nil {
			return nil
		}
		auth := model.AuthFromContext(ctx)
		if auth == nil {
			return nil
		}
		return NewServer(uc, log, version, auth)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
}
