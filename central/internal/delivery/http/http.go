// Package http holds the Fiber controllers for the agent and admin APIs.
package http

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v3"

	"netra-vuln/central/internal/delivery/http/middleware"
)

// decode parses a JSON request body leniently (unknown fields are ignored, so
// newer agents and dashboards keep working).
func decode(ctx fiber.Ctx, v any) error {
	if err := json.Unmarshal(middleware.GetBody(ctx), v); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "decode JSON: "+err.Error())
	}
	return nil
}

func idParam(ctx fiber.Ctx) (int64, error) {
	id, err := strconv.ParseInt(ctx.Params("id"), 10, 64)
	if err != nil || id < 1 {
		return 0, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("id %q", ctx.Params("id")))
	}
	return id, nil
}

func intQuery(ctx fiber.Ctx, key string, def int64) (int64, error) {
	v := ctx.Query(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("%s %q", key, v))
	}
	return n, nil
}
