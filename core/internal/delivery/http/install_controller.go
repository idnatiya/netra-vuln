package http

import (
	"bytes"
	_ "embed"
	"net/url"
	"regexp"
	"strings"
	"text/template"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"

	"netra-vuln/core/internal/model"
)

//go:embed install.sh.tmpl
var installScript string

var (
	installTemplate = template.Must(template.New("install.sh").Parse(installScript))
	// Both values are pasted into single-quoted shell strings, so neither may hold a quote.
	versionPattern = regexp.MustCompile(`^v[0-9A-Za-z.+-]{1,63}$`)
)

// InstallController serves the one-line agent installer and what the
// dashboard needs to show its command.
type InstallController struct {
	Log    *logrus.Logger
	script []byte // nil = disabled
	Info   model.InstallInfoResponse
}

// NewInstallController renders install.sh once. It stays disabled unless
// publicURL (the URL VMs use to reach central) and version (an agent release
// tag) are set and valid.
func NewInstallController(publicURL, version string, logger *logrus.Logger) *InstallController {
	publicURL = strings.TrimSuffix(publicURL, "/")
	c := &InstallController{Log: logger, Info: model.InstallInfoResponse{PublicURL: publicURL, AgentVersion: version}}
	if publicURL == "" && version == "" {
		return c
	}
	u, err := url.Parse(publicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" || u.RawQuery != "" ||
		u.User != nil || u.String() != publicURL {
		logger.Warnf("install.sh disabled: CENTRAL_PUBLIC_URL %q must be a bare http(s) origin like https://vuln.example.com", publicURL)
		return c
	}
	if !versionPattern.MatchString(version) {
		logger.Warnf("install.sh disabled: CENTRAL_AGENT_VERSION %q must be a release tag like v0.3.0", version)
		return c
	}
	var buf bytes.Buffer
	if err := installTemplate.Execute(&buf, struct{ URL, Version string }{publicURL, version}); err != nil {
		panic(err) // the template is fixed
	}
	c.script = buf.Bytes()
	c.Info.Enabled = true
	return c
}

func (c *InstallController) Script(ctx fiber.Ctx) error {
	if c.script == nil {
		return fiber.NewError(fiber.StatusNotFound, "install.sh disabled: set CENTRAL_PUBLIC_URL and CENTRAL_AGENT_VERSION")
	}
	ctx.Set(fiber.HeaderContentType, "text/x-shellscript; charset=utf-8")
	ctx.Set(fiber.HeaderCacheControl, "no-store")
	return ctx.Send(c.script)
}

func (c *InstallController) Get(ctx fiber.Ctx) error {
	return ctx.JSON(model.WebResponse[model.InstallInfoResponse]{Data: c.Info})
}
