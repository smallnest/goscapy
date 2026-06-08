// Package erspan provides on-demand loading of the ERSPAN protocol module.
//
// Import this package to register the ERSPAN contrib module, then call
// contrib.Load("erspan") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/erspan"
//	contrib.Load("erspan")
package erspan

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/erspan"
)

func init() {
	contrib.Register("erspan", func() {
		// The layers/erspan init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
