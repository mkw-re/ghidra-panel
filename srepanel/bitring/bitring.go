// Package bitring provides a ring buffer bitmap
package bitring

import (
	"math/bits"
	"sync/atomic"
)

// It is depressing that Go does not provides memory fences.

// BitRing provides a bitmap spanning a ring buffer.
type BitRing struct {
	n    atomic.Uint64
	mask uint64
	v    []atomic.Uint64
}

func NewBitRing(sz uint64) BitRing {
	mask := (1 << bits.LeadingZeros64(sz)) - 1
	mask |= 0x3f
	return BitRing{
		mask: sz,
		v:    make([]atomic.Uint64, (sz+1)/64),
	}
}

// fits returns whether index n is within the ring buffer.
func (r *BitRing) fits(n uint64) bool {
	return r.n.Load()-n <= r.mask
}

func (r *BitRing) Contains(n uint64) (exist, ok bool) {
	if !r.fits(n) {
		return false, false
	}
	idx := n & r.mask
	return (r.v[idx/64].Load() & (idx % 64)) != 0, true
}

func (r *BitRing) Advance() uint64 {
	n := r.n.Add(1)
	// clear bit
	idx := n & r.mask
	for {
		vOld := r.v[idx/64].Load()
		vNew := vOld &^ (1 << (idx % 64))
		if r.v[idx/64].CompareAndSwap(vOld, vNew) {
			break
		}
	}
	return n
}

func (r *BitRing) Insert(n uint64) (exist, ok bool) {
	if !r.fits(n) {
		return false, false
	}
	idx := n & r.mask
	var vOld uint64
	for {
		vOld = r.v[idx/64].Load()
		vNew := vOld | (1 << (idx % 64))
		if r.v[idx/64].CompareAndSwap(vOld, vNew) {
			break
		}
	}
	return (vOld & (1 << (idx % 64))) != 0, true
}
