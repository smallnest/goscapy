// Package radius provides on-demand loading of the RADIUS protocol module.
//
// Import this package to register the RADIUS contrib module, then call
// contrib.Load("radius") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/radius"
//	contrib.Load("radius")
package radius

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/radius"
)

func init() {
	contrib.Register("radius", func() {
		// The layers/radius init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
