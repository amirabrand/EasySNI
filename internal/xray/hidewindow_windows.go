//go:build windows

package xray

import (
	"os/exec"
	"syscall"
)

// hideWindow prevents a console window from flashing when xray is launched.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
