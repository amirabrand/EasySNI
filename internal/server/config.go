package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// appBaseDir is the app's running folder (next to the executable, else CWD).
func appBaseDir() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		return filepath.Dir(exe)
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// defaultConfigPath returns the default path for the saved config. It now lives
// inside the configs/ folder alongside the rest of the app's saved data.
func defaultConfigPath() string {
	return filepath.Join(configsDir(), "ezsni-config.json")
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

// writeSideFile writes data to a file inside the configs/ folder so all of the
// app's saved data (configs, saved SNIs, stores, CA) lives in one folder.
func writeSideFile(name string, data []byte) error {
	dir := configsDir()
	_ = os.MkdirAll(dir, 0o755)
	return os.WriteFile(filepath.Join(dir, name), data, 0o600)
}

// readSideFile reads a file from the configs/ folder, falling back to the old
// beside-the-exe location (migration from earlier versions).
func readSideFile(name string) ([]byte, error) {
	if data, err := os.ReadFile(filepath.Join(configsDir(), name)); err == nil {
		return data, nil
	}
	legacy := filepath.Join(appBaseDir(), name)
	return os.ReadFile(legacy)
}

// isGroupFile reports whether a configs/ filename is a generated per-group file
// (e.g. "01-Main.json"), as opposed to a store/saved file we must not delete.
func isGroupFile(name string) bool {
	if !strings.HasSuffix(name, ".json") || len(name) < 4 {
		return false
	}
	return name[0] >= '0' && name[0] <= '9' && name[1] >= '0' && name[1] <= '9' && name[2] == '-'
}

// configsDir is the folder where the app config and each config group live.
func configsDir() string {
	return filepath.Join(appBaseDir(), "configs")
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	repl := func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', '\n', '\t':
			return '_'
		}
		return r
	}
	s = strings.Map(repl, s)
	if s == "" {
		s = "group"
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

type cfgGroup struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Configs []json.RawMessage `json:"configs"`
}
type cfgStore struct {
	Groups []cfgGroup      `json:"groups"`
	Cur    string          `json:"cur"`
	Active string          `json:"active"`
	Extra  json.RawMessage `json:"-"`
}

// syncConfigsFolder writes one file per group into configs/, replacing the
// folder contents so deleted groups don't linger.
func syncConfigsFolder(raw []byte) (int, error) {
	var st cfgStore
	if err := json.Unmarshal(raw, &st); err != nil {
		return 0, err
	}
	dir := configsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	// remove old generated per-group files only (keep stores/saved files)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && isGroupFile(e.Name()) {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	n := 0
	for i, g := range st.Groups {
		fname := fmt.Sprintf("%02d-%s.json", i+1, sanitizeName(g.Name))
		out, _ := json.MarshalIndent(g, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, fname), out, 0o600); err == nil {
			n++
		}
	}
	return n, nil
}

// loadConfigsFolder rebuilds the store object from the per-group files.
func loadConfigsFolder() ([]byte, error) {
	dir := configsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && isGroupFile(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	st := cfgStore{Groups: []cfgGroup{}}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var g cfgGroup
		if json.Unmarshal(data, &g) == nil && (g.ID != "" || g.Name != "") {
			st.Groups = append(st.Groups, g)
		}
	}
	if len(st.Groups) > 0 {
		st.Cur = st.Groups[0].ID
	}
	return json.Marshal(st)
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
	if (err != nil || len(data) == 0 || !json.Valid(data)) && req.Path == "" {
		// migration: read the old beside-the-exe ezsni-config.json if present
		legacy := filepath.Join(appBaseDir(), "ezsni-config.json")
		if legacy != path {
			if ld, lerr := os.ReadFile(legacy); lerr == nil && len(ld) > 0 && json.Valid(ld) {
				data, err = ld, nil
			}
		}
	}
	if err != nil || len(data) == 0 || !json.Valid(data) {
		return map[string]any{"found": false, "path": path, "config": map[string]any{}}, nil
	}
	var cfg json.RawMessage = data
	return map[string]any{"found": true, "path": path, "config": cfg}, nil
}
