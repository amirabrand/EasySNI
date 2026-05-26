//go:build !psiphon

package psiphon

// runPsiphon is replaced by the real engine when built with -tags psiphon.
func runPsiphon(_ Options, _ LogFunc) (stop func(), socks, httpp int, err error) {
	return nil, 0, 0, ErrNoPsiphon
}
