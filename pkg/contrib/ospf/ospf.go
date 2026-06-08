// Package ospf provides on-demand loading of the OSPF protocol module.
//
// Import this package to register the OSPF contrib module, then call
// contrib.Load("ospf") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/ospf"
//	contrib.Load("ospf")
package ospf

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/ospf"
)

func init() {
	contrib.Register("ospf", func() {
		// The layers/ospf init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
