// Package web embeds the static frontend assets.
package web

import "embed"

// StaticFiles holds the embedded frontend under the "static" prefix.
//
//go:embed static
var StaticFiles embed.FS
