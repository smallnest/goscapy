// Package snmp provides on-demand loading of the SNMP protocol module.
//
// Import this package to register the SNMP contrib module, then call
// contrib.Load("snmp") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/snmp"
//	contrib.Load("snmp")
package snmp

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/snmp"
)

func init() {
	contrib.Register("snmp", func() {
		// The layers/snmp init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
