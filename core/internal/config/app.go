package config

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"

	"netra-vuln/core/internal/delivery/http"
	"netra-vuln/core/internal/delivery/http/middleware"
	"netra-vuln/core/internal/delivery/http/route"
	"netra-vuln/core/internal/repository"
	"netra-vuln/core/internal/usecase"
)

type BootstrapConfig struct {
	DB       *gorm.DB
	App      *fiber.App // nil for CLI commands
	Log      *logrus.Logger
	Validate *validator.Validate
	Config   *viper.Viper
	Limits   route.Limits // zero = route.DefaultLimits()
}

// UseCases are the application services, also used by the CLI subcommands.
type UseCases struct {
	Agent     *usecase.AgentUseCase
	Enroll    *usecase.EnrollUseCase
	Client    *usecase.ClientUseCase
	Host      *usecase.HostUseCase
	Finding   *usecase.FindingUseCase
	Dashboard *usecase.DashboardUseCase
	Auth      *usecase.AuthUseCase
	AdminUser *usecase.AdminUserUseCase
}

// Bootstrap wires repositories, use cases, controllers, middleware, and routes.
func Bootstrap(config *BootstrapConfig) *UseCases {
	// setup repositories
	clientRepository := repository.NewClientRepository(config.Log)
	enrollTokenRepository := repository.NewEnrollTokenRepository(config.Log)
	hostRepository := repository.NewHostRepository(config.Log)
	scanRepository := repository.NewScanRepository(config.Log)
	findingRepository := repository.NewFindingRepository(config.Log)
	adminUserRepository := repository.NewAdminUserRepository(config.Log)
	adminSessionRepository := repository.NewAdminSessionRepository(config.Log)

	// setup use cases
	uc := &UseCases{
		Agent:     usecase.NewAgentUseCase(config.DB, config.Log, config.Validate, hostRepository, scanRepository, findingRepository),
		Enroll:    usecase.NewEnrollUseCase(config.DB, config.Log, config.Validate, clientRepository, enrollTokenRepository, hostRepository),
		Client:    usecase.NewClientUseCase(config.DB, config.Log, config.Validate, clientRepository, enrollTokenRepository, hostRepository),
		Host:      usecase.NewHostUseCase(config.DB, config.Log, config.Validate, hostRepository),
		Finding:   usecase.NewFindingUseCase(config.DB, config.Log, config.Validate, findingRepository),
		Dashboard: usecase.NewDashboardUseCase(config.DB, config.Log, config.Validate, clientRepository, hostRepository, scanRepository, findingRepository),
		Auth:      usecase.NewAuthUseCase(config.DB, config.Log, config.Validate, adminUserRepository, adminSessionRepository),
		AdminUser: usecase.NewAdminUserUseCase(config.DB, config.Log, config.Validate, adminUserRepository),
	}
	if config.App == nil {
		return uc
	}

	// setup controllers
	agentController := http.NewAgentController(uc.Agent, uc.Enroll, config.Log)
	authController := http.NewAuthController(uc.Auth, config.Log)
	clientController := http.NewClientController(uc.Client, config.Log)
	hostController := http.NewHostController(uc.Host, config.Log)
	findingController := http.NewFindingController(uc.Finding, config.Log)
	dashboardController := http.NewDashboardController(uc.Dashboard, config.Log)
	installController := http.NewInstallController(config.Config.GetString("web.public_url"), config.Config.GetString("agent.version"), config.Log)

	// setup middleware
	hostAuthMiddleware := middleware.NewHostAuth(uc.Agent)
	authMiddleware := middleware.NewSessionAuth(uc.Auth)

	limits := config.Limits
	if limits == (route.Limits{}) {
		limits = route.DefaultLimits()
	}
	routeConfig := route.RouteConfig{
		App:                 config.App,
		Limits:              limits,
		AgentController:     agentController,
		AuthController:      authController,
		ClientController:    clientController,
		HostController:      hostController,
		FindingController:   findingController,
		DashboardController: dashboardController,
		InstallController:   installController,
		HostAuthMiddleware:  hostAuthMiddleware,
		AuthMiddleware:      authMiddleware,
	}
	routeConfig.Setup()
	return uc
}
