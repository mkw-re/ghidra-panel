// Package bitring provides a ring buffer bitmap
package bitring

import (
	"math/bits"
	"sync/atomic"
)

// It is depressing that Go does not provides memory fences.

// BitRing provides a bitmap spanning a ring buffer.
type BitRing struct {
	n    uint64
	mask uint64
	v    []uint64
}

func NewBitRing(sz uint64) BitRing {
	mask := (1 << bits.LeadingZeros64(sz)) - 1
	mask |= 0x3f
	return BitRing{
		n:    0,
		mask: sz,
		v:    make([]uint64, (sz+1)/64),
	}
}

// fits returns whether index n is within the ring buffer.
func (r *BitRing) fits(n uint64) bool {
	return atomic.LoadUint64(&r.n)-n <= r.mask
}

func (r *BitRing) Contains(n uint64) bool {
	idx := n & r.mask
	return r.fits(n) && ((r.v[idx/64] & (idx % 64)) != 0)
}

func (r *BitRing) Advance() uint64 {
	n := atomic.AddUint64(&r.n, 1)
	// clear bit
	idx := n & r.mask
	for {
		vOld := r.v[idx/64]
		vNew := vOld &^ (1 << (idx % 64))
		if atomic.CompareAndSwapUint64(&r.v[idx/64], vOld, vNew) {
			break
		}
	}
	return n
}

func (r *BitRing) Insert(n uint64) (exist bool, ok bool) {
	if !r.fits(n) {
		return false, false
	}
	idx := n & r.mask
	var vOld uint64
	for {
		vOld = r.v[idx/64]
		vNew := vOld | (1 << (idx % 64))
		if atomic.CompareAndSwapUint64(&r.v[idx/64], vOld, vNew) {
			break
		}
	}
	return (vOld & (1 << (idx % 64))) != 0, true
}
