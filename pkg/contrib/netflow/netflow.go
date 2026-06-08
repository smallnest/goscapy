// Package netflow provides on-demand loading of the Netflow protocol module.
//
// Import this package to register the Netflow contrib module, then call
// contrib.Load("netflow") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/netflow"
//	contrib.Load("netflow")
package netflow

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/netflow"
)

func init() {
	contrib.Register("netflow", func() {
		// The layers/netflow init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
