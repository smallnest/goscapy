// Package kerberos provides on-demand loading of the Kerberos protocol module.
//
// Import this package to register the Kerberos contrib module, then call
// contrib.Load("kerberos") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/kerberos"
//	contrib.Load("kerberos")
package kerberos

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/kerberos"
)

func init() {
	contrib.Register("kerberos", func() {
		// The layers/kerberos init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
