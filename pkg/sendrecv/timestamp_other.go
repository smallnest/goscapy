//go:build !linux && !darwin

package sendrecv

import "fmt"

// EnableTimestamping is not supported on this platform.
func (c *RawConn) EnableTimestamping(hardware bool) error {
	return fmt.Errorf("rawconn: EnableTimestamping not implemented on this platform")
}
