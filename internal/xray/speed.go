package xray

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// fakeReader yields up to N random bytes for upload tests without holding them
// all in memory.
type fakeReader struct {
	left int
	buf  [32 * 1024]byte
}

func (r *fakeReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.left {
		n = r.left
	}
	if n > len(r.buf) {
		n = len(r.buf)
	}
	if r.buf[0] == 0 {
		_, _ = rand.Read(r.buf[:])
	}
	copy(p, r.buf[:n])
	r.left -= n
	return n, nil
}

// socksHTTPClient builds an http.Client that dials targets via the given SOCKS5
// proxy and discards keep-alives so each call is a clean test.
func socksHTTPClient(socksHost string, socksPort int, timeout time.Duration) *http.Client {
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		return socks5Dial(net.JoinHostPort(socksHost, strconv.Itoa(socksPort)), addr, timeout)
	}
	tr := &http.Transport{DialContext: dial, DisableKeepAlives: true, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// MeasureDownload fetches a known-size payload through the given SOCKS proxy and
// returns throughput in kilobits/second.
func MeasureDownload(socksHost string, socksPort, wantBytes int, timeout time.Duration) (int, error) {
	if wantBytes <= 0 {
		wantBytes = 2_000_000
	}
	url := "https://speed.cloudflare.com/__down?bytes=" + strconv.Itoa(wantBytes)
	c := socksHTTPClient(socksHost, socksPort, timeout)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	t0 := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(t0).Seconds()
	if err != nil && n == 0 {
		return 0, err
	}
	if elapsed <= 0 || n <= 0 {
		return 0, errors.New("no bytes received")
	}
	return int(float64(n*8) / elapsed / 1000), nil
}

// MeasureUpload POSTs a known number of bytes through the SOCKS proxy and
// returns throughput in kilobits/second.
func MeasureUpload(socksHost string, socksPort, sendBytes int, timeout time.Duration) (int, error) {
	if sendBytes <= 0 {
		sendBytes = 1_000_000
	}
	url := "https://speed.cloudflare.com/__up"
	c := socksHTTPClient(socksHost, socksPort, timeout)
	reader := &fakeReader{left: sendBytes}
	req, err := http.NewRequest("POST", url, reader)
	if err != nil {
		return 0, err
	}
	req.ContentLength = int64(sendBytes)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	t0 := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(t0).Seconds()
	if elapsed <= 0 {
		return 0, errors.New("zero elapsed")
	}
	return int(float64(sendBytes*8) / elapsed / 1000), nil
}

// truncateErr makes a one-line, bounded version of an error string.
func truncateErr(err error, max int) string {
	if err == nil {
		return ""
	}
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// DetectColo fetches Cloudflare's trace endpoint through the SOCKS proxy and
// returns the colo (datacenter) code, e.g. "FRA". Empty string on failure.
func DetectColo(socksHost string, socksPort int, timeout time.Duration) string {
	c := socksHTTPClient(socksHost, socksPort, timeout)
	req, err := http.NewRequest("GET", "https://speed.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "colo="); ok {
			return v
		}
	}
	return ""
}
