//go:build !testhooks

// Package testhooks contains crash-injection points used only by the acceptance
// matrix (spec 12.2). In release builds every hook compiles to nothing, so the
// mechanism cannot be triggered by an environment variable (spec requirement).
package testhooks

// Crash is a no-op in release builds.
func Crash(stage string) {}

// Enabled reports that crash injection is not compiled in.
func Enabled() bool { return false }

// StageFromEnv always reports an empty stage in release builds.
func StageFromEnv() string { return "" }
