package sendrecv

import (
	"context"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

// LoopResult is one iteration of a send/receive loop: the response (nil if
// the iteration timed out without a match) and the time the probe was sent.
type LoopResult struct {
	// Response is the first matching reply, or nil if none arrived in time.
	Response *packet.Packet
	// Sent is the wall-clock time the probe was transmitted.
	Sent time.Time
	// RTT is the round-trip time when Response is non-nil.
	RTT time.Duration
}

// SrLoopOptions configures SrLoop / SrpLoop.
type SrLoopOptions struct {
	// Count is the number of iterations (0 = loop until ctx is cancelled).
	Count int
	// Interval is the delay between the start of consecutive iterations.
	// If an iteration's send+wait exceeds Interval, the next starts immediately.
	Interval time.Duration
	// Timeout is the per-iteration wait for a matching response.
	Timeout time.Duration
	// Match matches responses against the sent packet. If nil, DefaultMatch is used.
	Match MatchFunc
}

func (o SrLoopOptions) withDefaults(pkt *packet.Packet) SrLoopOptions {
	if o.Interval <= 0 {
		o.Interval = time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = o.Interval
	}
	if o.Match == nil {
		o.Match = DefaultMatch(pkt)
	}
	return o
}

// SrLoop repeatedly sends pkt at L3 and waits for a matching response on each
// iteration, mirroring Scapy's srloop(). It invokes cb (if non-nil) with each
// LoopResult and returns all results. The loop stops after opts.Count
// iterations or when ctx is cancelled.
//
// The receiver is opened once and reused across iterations, so SrLoop is
// suitable for latency probing and liveness monitoring.
func SrLoop(ctx context.Context, pkt *packet.Packet, iface string, opts SrLoopOptions, cb func(LoopResult)) ([]LoopResult, error) {
	return srLoop(ctx, pkt, iface, opts, cb, false)
}

// SrpLoop is like SrLoop but sends at L2 (Ethernet frames), mirroring Scapy's
// srploop(). The packet must include an Ethernet layer.
func SrpLoop(ctx context.Context, pkt *packet.Packet, iface string, opts SrLoopOptions, cb func(LoopResult)) ([]LoopResult, error) {
	return srLoop(ctx, pkt, iface, opts, cb, true)
}

func srLoop(ctx context.Context, pkt *packet.Packet, iface string, opts SrLoopOptions, cb func(LoopResult), l2 bool) ([]LoopResult, error) {
	opts = opts.withDefaults(pkt)

	rx, err := OpenReceiver(iface)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rx.Close() }()

	var results []LoopResult
	for i := 0; opts.Count <= 0 || i < opts.Count; i++ {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		start := time.Now()
		var sendErr error
		if l2 {
			sendErr = Sendp(pkt, iface)
		} else {
			sendErr = Send(pkt, iface)
		}
		if sendErr != nil {
			return results, sendErr
		}

		deadline := start.Add(opts.Timeout)
		resp, ok := collectFirstResponse(rx, deadline, opts.Match, pkt)
		res := LoopResult{Sent: start}
		if ok {
			res.Response = resp
			res.RTT = time.Since(start)
		}
		results = append(results, res)
		if cb != nil {
			cb(res)
		}

		// Sleep until the next interval boundary (unless this was the last one).
		if opts.Count <= 0 || i < opts.Count-1 {
			elapsed := time.Since(start)
			if wait := opts.Interval - elapsed; wait > 0 {
				select {
				case <-ctx.Done():
					return results, ctx.Err()
				case <-time.After(wait):
				}
			}
		}
	}
	return results, nil
}

// SrFloodOptions configures SrFlood / SrpFlood.
type SrFloodOptions struct {
	// Duration bounds the flood (0 = until ctx is cancelled).
	Duration time.Duration
	// PPS limits the send rate in packets per second (0 = as fast as possible).
	PPS int
	// Collect, when true, opens a receiver and gathers matching responses.
	// When false, SrFlood only transmits (lower overhead).
	Collect bool
	// Match matches responses when Collect is true. If nil, DefaultMatch is used.
	Match MatchFunc
}

// SrFlood sends pkt at L3 as fast as allowed (optionally rate-limited by PPS)
// for the configured duration, mirroring Scapy's srflood(). It returns the
// number of packets sent and, if Collect is set, any matching responses
// captured concurrently.
//
// SrFlood is a load-generation primitive. Use it only against hosts you are
// authorized to test; high PPS can saturate links and trip intrusion
// detection.
func SrFlood(ctx context.Context, pkt *packet.Packet, iface string, opts SrFloodOptions) (sent int, responses []*packet.Packet, err error) {
	return srFlood(ctx, pkt, iface, opts, false)
}

// SrpFlood is like SrFlood but sends at L2 (Ethernet frames), mirroring
// Scapy's srpflood().
func SrpFlood(ctx context.Context, pkt *packet.Packet, iface string, opts SrFloodOptions) (sent int, responses []*packet.Packet, err error) {
	return srFlood(ctx, pkt, iface, opts, true)
}

func srFlood(ctx context.Context, pkt *packet.Packet, iface string, opts SrFloodOptions, l2 bool) (int, []*packet.Packet, error) {
	if opts.Match == nil {
		opts.Match = DefaultMatch(pkt)
	}

	if opts.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Duration)
		defer cancel()
	}

	// Optional concurrent response collection.
	var (
		responses []*packet.Packet
		rx        Receiver
		respDone  chan struct{}
	)
	if opts.Collect {
		var err error
		rx, err = OpenReceiver(iface)
		if err != nil {
			return 0, nil, err
		}
		defer func() { _ = rx.Close() }()
		respDone = make(chan struct{})
		go func() {
			defer close(respDone)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				resp, err := rx.Recv(200 * time.Millisecond)
				if err != nil {
					continue
				}
				if opts.Match(pkt, resp) {
					responses = append(responses, resp)
				}
			}
		}()
	}

	// Rate limiting.
	var ticker *time.Ticker
	if opts.PPS > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(opts.PPS))
		defer ticker.Stop()
	}

	sent := 0
	for {
		select {
		case <-ctx.Done():
			if opts.Collect {
				<-respDone
			}
			return sent, responses, nil
		default:
		}

		var sendErr error
		if l2 {
			sendErr = Sendp(pkt, iface)
		} else {
			sendErr = Send(pkt, iface)
		}
		if sendErr != nil {
			if opts.Collect {
				<-respDone
			}
			return sent, responses, sendErr
		}
		sent++

		if ticker != nil {
			select {
			case <-ctx.Done():
				if opts.Collect {
					<-respDone
				}
				return sent, responses, nil
			case <-ticker.C:
			}
		}
	}
}
