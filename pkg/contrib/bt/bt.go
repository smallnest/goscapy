// Package bt provides on-demand loading of the BT protocol module.
//
// Import this package to register the BT contrib module, then call
// contrib.Load("bt") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/bt"
//	contrib.Load("bt")
package bt

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/bt"
)

func init() {
	contrib.Register("bt", func() {
		// The layers/bt init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
