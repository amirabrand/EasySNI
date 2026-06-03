// Package ghdl downloads GitHub release assets WITHOUT touching api.github.com
// (which is censored in some regions). It resolves the latest tag from the
// github.com "releases/latest" redirect, then downloads the asset from the
// releases/download path (which redirects to objects.githubusercontent.com).
// An optional mirror prefix lets users route through a GitHub proxy.
package ghdl

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	mu sync.RWMutex
	// mirror, when set (e.g. "https://ghproxy.com/"), is prepended to github
	// URLs so downloads can go through a proxy in censored regions.
	mirror string
)

// SetMirror sets a GitHub proxy prefix ("" disables it).
func SetMirror(m string) {
	mu.Lock()
	mirror = strings.TrimSpace(m)
	mu.Unlock()
}

// Mirror returns the current mirror prefix.
func Mirror() string {
	mu.RLock()
	defer mu.RUnlock()
	return mirror
}

func apply(url string) string {
	m := Mirror()
	if m == "" {
		return url
	}
	if !strings.HasSuffix(m, "/") {
		m += "/"
	}
	return m + url
}

func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// LatestTag resolves the newest release tag for owner/repo via the github.com
// redirect, with no use of api.github.com.
func LatestTag(repo string) (string, error) {
	url := apply("https://github.com/" + repo + "/releases/latest")
	// First try without following redirects (direct github.com gives a Location).
	if resp, err := noRedirectClient().Get(url); err == nil {
		defer resp.Body.Close()
		if loc := resp.Header.Get("Location"); loc != "" {
			if tag := tagFrom(loc); tag != "" {
				return tag, nil
			}
		}
	}
	// Fallback (e.g. through a mirror that follows redirects): parse the final URL.
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.Request != nil && resp.Request.URL != nil {
		if tag := tagFrom(resp.Request.URL.String()); tag != "" {
			return tag, nil
		}
	}
	return "", errors.New("could not resolve latest tag for " + repo)
}

func tagFrom(loc string) string {
	if i := strings.LastIndex(loc, "/tag/"); i >= 0 {
		return loc[i+len("/tag/"):]
	}
	return ""
}

// AssetURL builds the download URL for an asset in a release.
func AssetURL(repo, tag, asset string) string {
	return apply("https://github.com/" + repo + "/releases/download/" + tag + "/" + asset)
}

// ListAssets returns the asset filenames of a release by scraping the
// github.com "expanded_assets" fragment (no api.github.com needed).
func ListAssets(repo, tag string) ([]string, error) {
	url := apply("https://github.com/" + repo + "/releases/expanded_assets/" + tag)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	prefix := "/" + repo + "/releases/download/" + tag + "/"
	seen := map[string]bool{}
	var out []string
	for {
		i := strings.Index(html, prefix)
		if i < 0 {
			break
		}
		rest := html[i+len(prefix):]
		j := strings.IndexAny(rest, "\"'<> ")
		if j < 0 {
			break
		}
		name := rest[:j]
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
		html = rest[j:]
	}
	return out, nil
}

// Download GETs a URL (following redirects to objects.githubusercontent.com)
// and returns the bytes.
func Download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("HTTP " + resp.Status + " for " + url)
	}
	return io.ReadAll(resp.Body)
}

// ExtractZip unpacks every file in a .zip into destDir (flattened to base
// names), creating destDir if needed, and returns the written file paths.
func ExtractZip(data []byte, destDir string) ([]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	var out []string
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(f.Name)
		if base == "" || base == "." {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return out, err
		}
		p := filepath.Join(destDir, base)
		w, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return out, err
		}
		_, cerr := io.Copy(w, rc)
		w.Close()
		rc.Close()
		if cerr != nil {
			return out, cerr
		}
		out = append(out, p)
	}
	return out, nil
}

// ExtractTarGz unpacks every regular file in a .tar.gz into destDir (flattened),
// creating destDir if needed, and returns the written file paths.
func ExtractTarGz(data []byte, destDir string) ([]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	var out []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(h.Name)
		if base == "" || base == "." {
			continue
		}
		p := filepath.Join(destDir, base)
		w, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return out, err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return out, err
		}
		w.Close()
		out = append(out, p)
	}
	return out, nil
}

// PickBinary chooses the program binary from extracted paths: an exact name
// match, else a path containing hint (and .exe on Windows), else the largest
// file (which is almost always the binary, not LICENSE/README).
func PickBinary(paths []string, exactName, hint string) string {
	win := runtime.GOOS == "windows"
	for _, p := range paths {
		if filepath.Base(p) == exactName {
			return p
		}
	}
	for _, p := range paths {
		b := strings.ToLower(filepath.Base(p))
		if strings.Contains(b, strings.ToLower(hint)) && (!win || strings.HasSuffix(b, ".exe")) {
			return p
		}
	}
	var best string
	var bestSize int64
	for _, p := range paths {
		if win && !strings.HasSuffix(strings.ToLower(p), ".exe") {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.Size() >= bestSize {
			bestSize = st.Size()
			best = p
		}
	}
	return best
}
