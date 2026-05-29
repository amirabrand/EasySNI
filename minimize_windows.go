//go:build windows

package main

import "syscall"

// minimizeConsole minimizes the console window the app was launched from, so
// after the UI window opens the CLI doesn't sit in the foreground. No-op if the
// process has no console (e.g. launched from a GUI).
func minimizeConsole() {
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
