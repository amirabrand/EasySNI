package mitmdf

import "testing"

func TestFrontFor(t *testing.T) {
	r := NewRunner(nil)
	r.cfg = Config{
		Rules: []Rule{
			{Match: "google.com", Front: "www.google.com"},
			{Match: "reddit.com", Front: "github.githubassets.com", Dial: "github.githubassets.com"},
		},
		Default: "",
	}
	cases := []struct {
		host, want string
	}{
		{"www.google.com", "www.google.com"},          // exact
		{"meet.google.com", "www.google.com"},         // subdomain
		{"i.redd.it", ""},                             // not in rules → default ""
		{"reddit.com", "github.githubassets.com"},     // exact fastly
		{"old.reddit.com", "github.githubassets.com"}, // subdomain fastly
		{"example.org", ""},                           // unmatched → default
		{"notgoogle.com", ""},                         // must NOT match google.com suffix trick
	}
	for _, c := range cases {
		if got := r.frontFor(c.host); got != c.want {
			t.Errorf("frontFor(%q)=%q want %q", c.host, got, c.want)
		}
	}

	// dial override: google → real IP (empty), reddit → github.githubassets.com
	if _, dial := r.frontDialFor("meet.google.com"); dial != "" {
		t.Errorf("google dial should be empty, got %q", dial)
	}
	if _, dial := r.frontDialFor("old.reddit.com"); dial != "github.githubassets.com" {
		t.Errorf("reddit dial override: got %q", dial)
	}

	// default front applies to unmatched hosts when set
	r.cfg.Default = "www.fallback.com"
	if got := r.frontFor("example.org"); got != "www.fallback.com" {
		t.Errorf("default front: got %q", got)
	}
}

func TestDefaultRulesNonEmpty(t *testing.T) {
	if len(DefaultRules()) < 5 {
		t.Fatal("expected a populated default ruleset")
	}
	for _, r := range DefaultRules() {
		if r.Match == "" || r.Front == "" {
			t.Fatalf("bad default rule: %+v", r)
		}
	}
}
