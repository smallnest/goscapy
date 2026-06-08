// Package zigbee provides on-demand loading of the Zigbee protocol module.
//
// Import this package to register the Zigbee contrib module, then call
// contrib.Load("zigbee") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/zigbee"
//	contrib.Load("zigbee")
package zigbee

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/zigbee"
)

func init() {
	contrib.Register("zigbee", func() {
		// The layers/zigbee init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
