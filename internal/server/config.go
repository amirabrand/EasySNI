package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// defaultConfigPath returns the default path for saved config: next to the
// executable (the "running folder"). Falls back to CWD then "ezsni-config.json".
func defaultConfigPath() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		return filepath.Join(filepath.Dir(exe), "ezsni-config.json")
	}
	if wd, err := os.Getwd(); err == nil {
		return filepath.Join(wd, "ezsni-config.json")
	}
	return "ezsni-config.json"
}

// resolveConfigPath uses the caller-supplied path if non-empty (expanding ~/),
// otherwise the default. If it's a directory, "ezsni-config.json" is appended.
func resolveConfigPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return defaultConfigPath()
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return filepath.Join(p, "ezsni-config.json")
	}
	return p
}

// writeSideFile writes data to a file beside the app config (running folder).
func writeSideFile(name string, data []byte) error {
	path := resolveConfigPath("")
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0o755)
	return os.WriteFile(filepath.Join(dir, name), data, 0o600)
}

// readSideFile reads a file beside the app config.
func readSideFile(name string) ([]byte, error) {
	path := resolveConfigPath("")
	return os.ReadFile(filepath.Join(filepath.Dir(path), name))
}
func (s *Server) handleConfigSave(body json.RawMessage) (any, error) {
	var env struct {
		Path   string          `json:"path"`
		Config json.RawMessage `json:"config"`
	}
	// Accept either {path, config} or a bare config object for backward compat.
	if err := json.Unmarshal(body, &env); err != nil || (env.Config == nil && env.Path == "") {
		env.Config = body
	}
	if len(env.Config) == 0 || !json.Valid(env.Config) {
		return nil, errors.New("config must be a JSON object")
	}
	var pretty interface{}
	if err := json.Unmarshal(env.Config, &pretty); err != nil {
		return nil, err
	}
	out, _ := json.MarshalIndent(pretty, "", "  ")
	path := resolveConfigPath(env.Path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, err
	}
	s.log("Config saved → "+path, "OK")
	return map[string]any{"ok": true, "path": path}, nil
}

// handleConfigLoad returns the saved config from "path" (or the default).
func (s *Server) handleConfigLoad(body json.RawMessage) (any, error) {
	var req struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(body, &req)
	path := resolveConfigPath(req.Path)
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || !json.Valid(data) {
		return map[string]any{"found": false, "path": path, "config": map[string]any{}}, nil
	}
	var cfg json.RawMessage = data
	return map[string]any{"found": true, "path": path, "config": cfg}, nil
}
