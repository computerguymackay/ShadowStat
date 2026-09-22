// Package version holds build-time version metadata, set via -ldflags.
package version

// Version is overridden at build time: -ldflags "-X ShadowStat/internal/version.Version=..."
var Version = "dev"
