//go:build !windows

package main

// minimizeConsole is a no-op on non-Windows platforms.
func minimizeConsole() {}
