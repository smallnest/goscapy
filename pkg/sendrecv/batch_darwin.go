//go:build darwin

package sendrecv

import (
	"errors"
	"fmt"
	"time"
)

// SendBatch sends multiple payloads sequentially.
func (c *BatchConn) SendBatch(msgs []BatchMsg) (int, error) {
	for i, msg := range msgs {
		if err := c.Send(msg.Data, msg.Dst); err != nil {
			return i, err
		}
	}
	return len(msgs), nil
}

// RecvBatch receives multiple payloads sequentially.
func (c *BatchConn) RecvBatch(n int, timeout time.Duration) ([]BatchResult, error) {
	deadline := time.Now().Add(timeout)
	var results []BatchResult

	for len(results) < n {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if len(results) > 0 {
				return results, nil
			}
			return nil, fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}

		data, srcIP, err := c.Recv(remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				if len(results) > 0 {
					return results, nil
				}
				return nil, err
			}
			return nil, err
		}

		results = append(results, BatchResult{
			Data: data,
			Src:  srcIP,
		})
	}

	return results, nil
}
