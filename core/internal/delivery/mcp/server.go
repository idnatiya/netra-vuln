// Package mcp exposes read-only vulnerability data to AI clients (Claude,
// Codex, OpenCode, Antigravity, Cursor, ...) over MCP Streamable HTTP. Tools call
// the same use cases as the admin API and return the admin API's models.
package mcp

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/usecase"
)

const pageSize = 25

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
	Page            int    `json:"page,omitempty" jsonschema:"1-based page, 25 findings per page"`
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

// NewServer registers the read-only tools.
func NewServer(uc *UseCases, version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "netra-vuln", Version: version}, &mcp.ServerOptions{
		Instructions: "Package vulnerabilities (Trivy) of Linux VMs grouped by client. " +
			"Open = unresolved and not triaged; accepted / false_positive were triaged by an admin. " +
			"A component is one upgrade action: kind os = OS packages from one source package, app = language packages of one app folder, binary = one Go/Rust binary.",
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
		Description: "Search findings (one CVE in one package on one host), most severe first, 25 per page."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in FindingsIn) (*mcp.CallToolResult, FindingsOut, error) {
			out, paging, err := uc.Finding.Search(ctx, &model.SearchFindingRequest{Client: in.Client, HostID: in.HostID,
				Severity: in.Severity, Status: in.Status, Query: in.Query, IncludeResolved: in.IncludeResolved,
				Page: in.Page, Size: pageSize})
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
	return s
}

// NewHandler serves the tools statelessly with plain JSON responses, so every
// request is self-contained and passes through the Fiber auth middleware.
func NewHandler(s *mcp.Server) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
}
