//go:build !windows

package winctl

// MinimizeConsole is a no-op on non-Windows platforms.
func MinimizeConsole() {}

// Supported reports whether console minimize is available on this OS.
func Supported() bool { return false }
