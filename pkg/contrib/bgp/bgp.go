// Package bgp provides on-demand loading of the BGP protocol module.
//
// Import this package to register the BGP contrib module, then call
// contrib.Load("bgp") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/bgp"
//	contrib.Load("bgp")
package bgp

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/bgp"
)

func init() {
	contrib.Register("bgp", func() {
		// The layers/bgp init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
