// Package quic provides on-demand loading of the QUIC protocol module.
//
// Import this package to register the QUIC contrib module, then call
// contrib.Load("quic") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/quic"
//	contrib.Load("quic")
package quic

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/quic"
)

func init() {
	contrib.Register("quic", func() {
		// The layers/quic init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
