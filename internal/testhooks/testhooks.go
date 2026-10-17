//go:build testhooks

// Package testhooks contains crash-injection points used only by the acceptance
// matrix (spec 12.2). The file is compiled ONLY with "-tags testhooks"; release
// builds get the no-op twin in testhooks_disabled.go.
package testhooks

import "os"

// Crash terminates the process with exit code 137 when EIMMORTAL_TEST_CRASH_AT
// matches stage. It is a no-op otherwise.
func Crash(stage string) {
	for _, name := range []string{"EIMMORTAL_TEST_CRASH_AT", "APEX_TEST_CRASH_AT"} {
		if os.Getenv(name) == stage {
			os.Exit(137)
		}
	}
}

// Enabled reports whether crash injection is compiled in.
func Enabled() bool { return true }

// StageFromEnv reports the requested stage (test and diagnostics helper).
func StageFromEnv() string {
	for _, name := range []string{"EIMMORTAL_TEST_CRASH_AT", "APEX_TEST_CRASH_AT"} {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}
