// Package lldp provides on-demand loading of the LLDP protocol module.
//
// Import this package to register the LLDP contrib module, then call
// contrib.Load("lldp") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/lldp"
//	contrib.Load("lldp")
package lldp

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/lldp"
)

func init() {
	contrib.Register("lldp", func() {
		// The layers/lldp init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
