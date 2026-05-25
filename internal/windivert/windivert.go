// Package windivert ports the original app's WinDivertManager: it installs,
// starts, checks, and removes the WinDivert kernel driver service via the
// Windows Service Controller (sc). It is a no-op with a clear message on
// non-Windows hosts, so the rest of the suite still builds and runs anywhere.
package windivert

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Status is the result of a driver-state query.
type Status struct {
	Supported bool   `json:"supported"` // false on non-Windows
	Admin     bool   `json:"admin"`     // running with admin rights
	Running   bool   `json:"running"`   // service is RUNNING
	Installed bool   `json:"installed"` // service exists
	Detail    string `json:"detail"`    // human-readable summary
}

// Result is returned by install/uninstall actions.
type Result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func sysFileName() string {
	if strings.Contains(runtime.GOARCH, "386") {
		return "WinDivert32.sys"
	}
	return "WinDivert64.sys"
}

// isAdmin reports whether the process has Windows admin rights. On Windows we
// probe with `net session`, which only succeeds for elevated processes.
func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}

func sc(args ...string) (string, error) {
	out, err := exec.Command("sc", args...).CombinedOutput()
	return string(out), err
}

// Check queries the WinDivert service state.
func Check() Status {
	if runtime.GOOS != "windows" {
		return Status{Supported: false, Detail: "WinDivert is Windows-only; this host is " + runtime.GOOS}
	}
	st := Status{Supported: true, Admin: isAdmin()}
	out, _ := sc("query", "WinDivert")
	up := strings.ToUpper(out)
	switch {
	case strings.Contains(up, "RUNNING"):
		st.Running, st.Installed, st.Detail = true, true, "WinDivert is running"
	case strings.Contains(up, "STOPPED"):
		st.Installed, st.Detail = true, "WinDivert is installed but stopped"
	case strings.Contains(up, "1060") || strings.Contains(up, "OPENSERVICE FAILED"):
		st.Detail = "WinDivert is not installed"
	default:
		st.Detail = "WinDivert is not installed"
	}
	return st
}

// findSys looks for the driver .sys file near the executable / cwd / Program
// Files, mirroring the original search order. extraDir is checked first.
func findSys(extraDir string) string {
	name := sysFileName()
	var dirs []string
	if extraDir != "" {
		dirs = append(dirs, extraDir)
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe), filepath.Join(filepath.Dir(exe), "WinDivert"))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd, filepath.Join(cwd, "WinDivert"))
	}
	if pf := os.Getenv("PROGRAMFILES"); pf != "" {
		dirs = append(dirs, filepath.Join(pf, "WinDivert"))
	}
	if pf := os.Getenv("PROGRAMFILES(X86)"); pf != "" {
		dirs = append(dirs, filepath.Join(pf, "WinDivert"))
	}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Install creates and starts the WinDivert kernel service. searchDir, if set,
// is searched first for the .sys file.
func Install(searchDir string) Result {
	if runtime.GOOS != "windows" {
		return Result{false, "WinDivert can only be installed on Windows (host is " + runtime.GOOS + ")"}
	}
	if !isAdmin() {
		return Result{false, "Administrator privileges required — relaunch the app as Administrator"}
	}

	if st := Check(); st.Running {
		return Result{true, "WinDivert is already running"}
	}

	sysFile := findSys(searchDir)
	if sysFile == "" {
		return Result{false, sysFileName() + " not found. Place the WinDivert files next to the app or set the path."}
	}

	// Create the service if it does not already exist.
	if out, _ := sc("query", "WinDivert"); !strings.Contains(strings.ToUpper(out), "WINDIVERT") {
		out, _ := sc("create", "WinDivert",
			"binPath=", sysFile,
			"type=", "kernel",
			"start=", "auto",
			"DisplayName=", "WinDivert")
		if !strings.Contains(strings.ToLower(out), "success") &&
			!strings.Contains(strings.ToLower(out), "already exists") {
			return Result{false, "Failed to create service: " + strings.TrimSpace(out)}
		}
	}

	_, _ = sc("start", "WinDivert")
	time.Sleep(time.Second)

	if Check().Running {
		return Result{true, "WinDivert installed and started"}
	}
	return Result{false, "Service created but failed to start (check that the .sys matches your Windows build)"}
}

// Uninstall stops and deletes the WinDivert service.
func Uninstall() Result {
	if runtime.GOOS != "windows" {
		return Result{false, "WinDivert can only be removed on Windows (host is " + runtime.GOOS + ")"}
	}
	if !isAdmin() {
		return Result{false, "Administrator privileges required — relaunch the app as Administrator"}
	}
	if st := Check(); !st.Installed {
		return Result{true, "WinDivert is not installed — nothing to remove"}
	}
	_, _ = sc("stop", "WinDivert")
	time.Sleep(500 * time.Millisecond)
	out, _ := sc("delete", "WinDivert")
	if strings.Contains(strings.ToLower(out), "success") ||
		strings.Contains(out, "1072") /* marked for deletion */ {
		return Result{true, "WinDivert stopped and removed"}
	}
	if !Check().Installed {
		return Result{true, "WinDivert removed"}
	}
	return Result{false, "Failed to remove service: " + strings.TrimSpace(out)}
}
