// Package migrations embeds the golang-migrate SQL migrations
// (<timestamp>_<name>.up.sql / .down.sql), applied by `central migrate`.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
