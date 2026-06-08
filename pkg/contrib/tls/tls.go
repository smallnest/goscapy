// Package tls provides on-demand loading of the TLS protocol module.
//
// Import this package to register the TLS contrib module, then call
// contrib.Load("tls") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/tls"
//	contrib.Load("tls")
package tls

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/tls"
)

func init() {
	contrib.Register("tls", func() {
		// The layers/tls init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
