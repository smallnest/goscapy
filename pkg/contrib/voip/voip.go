// Package voip provides on-demand loading of the VoIP protocol module.
//
// Import this package to register the VoIP contrib module, then call
// contrib.Load("voip") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/voip"
//	contrib.Load("voip")
package voip

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/voip"
)

func init() {
	contrib.Register("voip", func() {
		// The layers/voip init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
