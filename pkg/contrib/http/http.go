// Package http provides on-demand loading of the HTTP protocol module.
//
// Import this package to register the HTTP contrib module, then call
// contrib.Load("http") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/http"
//	contrib.Load("http")
package http

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/http"
)

func init() {
	contrib.Register("http", func() {
		// The layers/http init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
