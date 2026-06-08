// Package lorawan provides on-demand loading of the LoRaWAN protocol module.
//
// Import this package to register the LoRaWAN contrib module, then call
// contrib.Load("lorawan") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/lorawan"
//	contrib.Load("lorawan")
package lorawan

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/lorawan"
)

func init() {
	contrib.Register("lorawan", func() {
		// The layers/lorawan init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
