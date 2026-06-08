// Package ntp provides on-demand loading of the NTP protocol module.
//
// Import this package to register the NTP contrib module, then call
// contrib.Load("ntp") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/ntp"
//	contrib.Load("ntp")
package ntp

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/ntp"
)

func init() {
	contrib.Register("ntp", func() {
		// The layers/ntp init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
