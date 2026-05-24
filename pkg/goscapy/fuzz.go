package goscapy

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"reflect"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// Fuzz randomizes all default-valued fields on a layer, preserving
// explicitly set values. It returns the same Layer for chaining.
//
// Use with the Builder API:
//
//	goscapy.NewIP().DstIP("10.0.0.1").Over(goscapy.Fuzz(goscapy.NewTCP().Layer()))
func Fuzz(layer *packet.Layer) *packet.Layer {
	for _, f := range layer.Fields() {
		if cf, ok := f.(*fields.ConditionalField); ok {
			if !cf.Active(layer.Values()) {
				continue
			}
		}
		if !isDefault(layer, f) {
			continue
		}
		if rv, ok := randomValue(f); ok {
			layer.Set(f.Name(), rv)
		}
	}
	return layer
}

// FuzzPacket randomizes all default-valued fields across every layer in a packet.
func FuzzPacket(pkt *packet.Packet) {
	for _, l := range pkt.Layers() {
		Fuzz(l)
	}
}

// isDefault reports whether the field's current value equals its default.
func isDefault(l *packet.Layer, f fields.Field) bool {
	cur, err := l.Get(f.Name())
	if err != nil {
		return true
	}
	def := f.DefaultVal()
	return valEqual(cur, def)
}

func valEqual(a, b any) bool {
	// Both nil (typed or untyped).
	if isNil(a) && isNil(b) {
		return true
	}
	if isNil(a) || isNil(b) {
		return false
	}

	switch av := a.(type) {
	case uint8:
		bv, ok := b.(uint8)
		return ok && av == bv
	case uint16:
		bv, ok := b.(uint16)
		return ok && av == bv
	case uint32:
		bv, ok := b.(uint32)
		return ok && av == bv
	case int32:
		bv, ok := b.(int32)
		return ok && av == bv
	case uint64:
		bv, ok := b.(uint64)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case net.HardwareAddr:
		bv, ok := b.(net.HardwareAddr)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
		return true
	case net.IP:
		bv, ok := b.(net.IP)
		if !ok {
			return false
		}
		// net.IP(nil).Equal(net.IP(nil)) returns true, but both-zero-length
		// should match as "both nil-like".
		if len(av) == 0 && len(bv) == 0 {
			return true
		}
		return av.Equal(bv)
	case []byte:
		bv, ok := b.([]byte)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
		return true
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// isNil handles both untyped nil and typed nil (e.g. net.IP(nil)).
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	}
	return false
}

func randomValue(f fields.Field) (any, bool) {
	switch ft := f.(type) {
	case *fields.ByteField:
		return randByte(), true
	case *fields.XByteField:
		return randByte(), true
	case *fields.ShortField:
		return randUint16(), true
	case *fields.LEShortField:
		return randUint16(), true
	case *fields.ThreeBytesField:
		return randUint24(), true
	case *fields.IntField:
		return randUint32(), true
	case *fields.SignedIntField:
		return randInt32(), true
	case *fields.LEIntField:
		return randUint32(), true
	case *fields.LongField:
		return randUint64(), true
	case *fields.LELongField:
		return randUint64(), true
	case *fields.BitField:
		mask := uint8((1 << ft.BitSize()) - 1)
		return randByte() & mask, true
	case *fields.MACField:
		mac := make(net.HardwareAddr, 6)
		rand.Read(mac)
		mac[0] &^= 0x01 // unicast
		return mac, true
	case *fields.IPField:
		ip := make(net.IP, 4)
		rand.Read(ip)
		return ip, true
	case *fields.IPv6Field:
		ip := make(net.IP, 16)
		rand.Read(ip)
		return ip, true
	case *fields.StrField:
		b := make([]byte, randIntN(32)+1)
		rand.Read(b)
		return string(b), true
	case *fields.StrLenField:
		b := make([]byte, randIntN(32)+1)
		rand.Read(b)
		return string(b), true
	case *fields.StrFixedField:
		size := ft.FixedSize()
		b := make([]byte, size)
		rand.Read(b)
		return b, true
	case *fields.PacketField:
		return nil, false
	case *fields.ConditionalField:
		return randomValue(ft.Field)
	default:
		return nil, false
	}
}

func randByte() uint8 {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

func randUint16() uint16 {
	var b [2]byte
	rand.Read(b[:])
	return uint16(b[0])<<8 | uint16(b[1])
}

func randUint24() uint32 {
	var b [3]byte
	rand.Read(b[:])
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func randInt32() int32 {
	return int32(randUint32())
}

func randUint64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func randIntN(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}
