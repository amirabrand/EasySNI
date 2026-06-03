//go:build !windows

package tun2socks

// On non-Windows platforms transparent routing is left to the user (the TUN
// device is created, but assigning addresses/routes needs root and differs per
// OS). These are no-ops so the cross-platform Start path stays identical.

func tunRoutesUp(log func(string, string), excludes []string) {
	log("TUN device created. On this OS, set the default route to it manually (needs root).", "WARN")
}

func tunRoutesDown() {}
