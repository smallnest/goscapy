//go:build linux

package sendrecv

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// ErrNotSupported is returned when zero-copy operations are not supported on the host OS.
var ErrNotSupported = errors.New("zerocopy: not supported on this platform")

const (
	soZeroCopy  = 60
	msgZeroCopy = 0x4000000
)

type sockExtendedErr struct {
	Errno  uint32
	Origin uint8
	Type   uint8
	Code   uint8
	Pad    uint8
	Info   uint32
	Data   uint32
}

// SetZeroCopy enables/disables zero-copy mode on the underlying raw socket.
func (c *RawConn) SetZeroCopy(enable bool) error {
	val := 0
	if enable {
		val = 1
	}

	if err := syscall.SetsockoptInt(c.fd, syscall.SOL_SOCKET, soZeroCopy, val); err != nil {
		return fmt.Errorf("zerocopy: setsockopt SO_ZEROCOPY: %w", err)
	}

	c.zeroCopyMu.Lock()
	c.zeroCopy = enable
	if enable {
		c.nextSendSeq = 0
		c.completed = make(map[uint32]bool)
		c.lowestPending = 0
	}
	c.zeroCopyMu.Unlock()

	return nil
}

// WaitZeroCopyCompletion blocks until all pending zero-copy transmissions have completed
// or the context is cancelled.
func (c *RawConn) WaitZeroCopyCompletion(ctx context.Context) error {
	c.zeroCopyMu.Lock()
	targetSeq := c.nextSendSeq
	lowest := c.lowestPending
	c.zeroCopyMu.Unlock()

	if lowest >= targetSeq {
		return nil
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		c.zeroCopyMu.Lock()
		lowest = c.lowestPending
		c.zeroCopyMu.Unlock()

		if lowest >= targetSeq {
			return nil
		}

		oob := make([]byte, 1024)
		dummy := make([]byte, 128)

		oobn, _, _, _, err := syscall.Recvmsg(
			c.fd,
			dummy,
			oob,
			syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT,
		)

		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				time.Sleep(1 * time.Millisecond)
				continue
			}
			return fmt.Errorf("zerocopy: recvmsg errqueue: %w", err)
		}

		if oobn > 0 {
			cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				return fmt.Errorf("zerocopy: parse control msg: %w", err)
			}
			for _, cmsg := range cmsgs {
				if cmsg.Header.Level == syscall.SOL_IP && cmsg.Header.Type == syscall.IP_RECVERR {
					if len(cmsg.Data) >= 16 {
						seerr := (*sockExtendedErr)(unsafe.Pointer(&cmsg.Data[0]))
						if seerr.Origin == 5 { // SO_EE_ORIGIN_ZEROCOPY (5)
							c.zeroCopyMu.Lock()
							for seq := seerr.Data; seq <= seerr.Info; seq++ {
								c.completed[seq] = true
							}
							for c.completed[c.lowestPending] {
								delete(c.completed, c.lowestPending)
								c.lowestPending++
							}
							c.zeroCopyMu.Unlock()
						}
					}
				}
			}
		}
	}
}
