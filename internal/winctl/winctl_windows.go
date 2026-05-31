//go:build windows

// Package winctl provides small OS window helpers (currently: minimize the
// console window). Windows implementation.
package winctl

import "syscall"

// MinimizeConsole minimizes the console window the app was launched from.
// No-op if the process has no console (e.g. launched from a GUI).
func MinimizeConsole() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	user32 := syscall.NewLazyDLL("user32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	showWindow := user32.NewProc("ShowWindow")
	const swMinimize = 6
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd != 0 {
		showWindow.Call(hwnd, uintptr(swMinimize))
	}
}

// Supported reports whether console minimize is available on this OS.
func Supported() bool { return true }
