// Package dot11 provides on-demand loading of the Dot11 protocol module.
//
// Import this package to register the Dot11 contrib module, then call
// contrib.Load("dot11") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/dot11"
//	contrib.Load("dot11")
package dot11

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/dot11"
)

func init() {
	contrib.Register("dot11", func() {
		// The layers/dot11 init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
