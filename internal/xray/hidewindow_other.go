//go:build !windows

package xray

import "os/exec"

// hideWindow is a no-op off Windows.
func hideWindow(_ *exec.Cmd) {}
