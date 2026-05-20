package sendrecv

// BatchMsg represents a single message in a batch send operation.
type BatchMsg struct {
	Data []byte
	Dst  string
}

// BatchResult represents a single received message in a batch receive operation.
type BatchResult struct {
	Data []byte
	Src  string
}

// BatchConn wraps a RawConn and adds high-performance batch send/receive methods.
type BatchConn struct {
	*RawConn
}

// Batch returns a BatchConn wrapping the RawConn.
func (c *RawConn) Batch() *BatchConn {
	return &BatchConn{RawConn: c}
}
