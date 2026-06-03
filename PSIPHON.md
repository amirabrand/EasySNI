# Psiphon over MITM — how to use it

V2RayEz can chain **Psiphon** through its client-side **Domain-Fronting MITM**
proxy, exactly like the *PsiphonOverMITM* project:

```
Psiphon app ── upstream proxy ──► V2RayEz MITM (domain fronting) ──► Psiphon network
```

## Recommended path (works in the normal build — no build tags)

1. Open the **Psiphon** tab and click **Start Psiphon over MITM**.
   V2RayEz starts the Domain-Fronting MITM proxy and shows you an address such as
   `http://127.0.0.1:8087`.
2. Install/trust the MITM **CA** (Domain Fronting tab → Download CA) so the proxy
   can read your HTTPS locally.
3. In the **Psiphon app**, go to **Settings → Proxy → Upstream Proxy** and set it to
   the address shown (HTTP), e.g. host `127.0.0.1`, port `8087`.
4. Connect Psiphon. Its traffic now rides over the domain-fronting tunnel.

This mirrors the upstream project, which also runs the Psiphon **app** and only
points its upstream proxy at the local MITM.

## Why there is no one-click embedded Psiphon

`go get github.com/Psiphon-Labs/psiphon-tunnel-core/...` does **not** work as a
library import, and that is expected. psiphon-tunnel-core:

- uses a **local-path replace** in its own `go.mod`
  (`replace github.com/pion/dtls/v2 => ./replace/dtls`), which only resolves
  *inside* its own repository, not when imported elsewhere;
- pins **forked** modules (`github.com/Psiphon-Labs/quic-go`,
  `github.com/Psiphon-Labs/utls`) whose module paths differ from what older
  transitive deps request — this is the `lucas-clemente/quic-go` vs
  `quic-go/quic-go` error spiral you saw;
- requires **Go 1.26+**.

Because of the local-path replace, the only reliable way to build the embedded
engine is to compile **from within a checkout of psiphon-tunnel-core** (so its own
`go.mod`/replaces apply) and expose it as a small service — not to `go get` it into
this module. For almost everyone the **Recommended path** above is simpler and just
works.

## Advanced: embedded engine (`-tags psiphon`)

Only if you specifically want the tunnel embedded in the binary:

1. Use **Go 1.26+**.
2. Build from a local checkout of `psiphon-tunnel-core` (so its `go.mod` with the
   `./replace/dtls` local replace and forked quic-go/utls is in effect), then wire
   `internal/psiphon/psiphon_real.go` against that checkout via a `replace` in this
   module pointing at your local path.
3. `go build -tags psiphon .`  (tags go **before** the dot).

This is intentionally manual; the build scripts skip it and fall back to a standard
build so they never spiral on `go get`.
