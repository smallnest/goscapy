// Package ldap provides on-demand loading of the LDAP protocol module.
//
// Import this package to register the LDAP contrib module, then call
// contrib.Load("ldap") to activate it:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/ldap"
//	contrib.Load("ldap")
package ldap

import (
	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/layers/ldap"
)

func init() {
	contrib.Register("ldap", func() {
		// The layers/ldap init() already ran via the import above.
		// This function is a no-op marker that the module is loaded.
	})
}
