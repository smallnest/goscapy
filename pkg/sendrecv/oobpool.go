package sendrecv

import "sync"

// oobBufSize is the size of pooled OOB (ancillary data) receive buffers.
// 256 bytes is sufficient for a single timestamp cmsg (16–48 bytes) plus a
// pktinfo cmsg (12–20 bytes) with cmsghdr overhead on both 32-bit and 64-bit
// platforms.
const oobBufSize = 256

// oobPool provides reusable OOB receive buffers to avoid per-packet allocation.
var oobPool = sync.Pool{
	New: func() any { return make([]byte, oobBufSize) },
}

// getOOBBuf retrieves a buffer from the pool.
func getOOBBuf() []byte {
	return oobPool.Get().([]byte)
}

// putOOBBuf returns a buffer to the pool.
func putOOBBuf(b []byte) {
	oobPool.Put(b)
}
