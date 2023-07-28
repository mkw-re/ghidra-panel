package discord_auth

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"strings"
	"time"
)

const oauth2Validity = 30 * time.Second

const csrfDepth = 65536

// csrfProt is a rolling log of previously used state values.
type csrfProt struct {
	log    [csrfDepth][32]byte
	bitmap [csrfDepth / 64]uint64
	n      uint64
	macKey [32]byte
	mac    hash.Hash
}

func newCSRFProt() *csrfProt {
	c := new(csrfProt)
	if _, randErr := crand.Read(c.macKey[:]); randErr != nil {
		panic("crypto rand read failed: " + randErr.Error())
	}
	c.mac = hmac.New(sha256.New, c.macKey[:])
	return c
}

func (c *csrfProt) issue() string {
	// 0:32 = hmac key
	// 32:40 = counter
	// 40:48 = timestamp
	var key [48]byte

	// issue new key
	n := c.n
	idx := n % csrfDepth
	// clear bit
	c.bitmap[idx/64] &^= 1 << (idx % 64)
	binary.LittleEndian.PutUint64(key[32:40], n)
	binary.LittleEndian.PutUint64(key[40:48], uint64(time.Now().Unix()))

	// hmac key
	c.mac.Reset()
	_, _ = c.mac.Write(key[32:48])
	c.mac.Sum(key[:0])

	// wind up for next iteration
	c.n++
	return "v0:" + base64.URLEncoding.EncodeToString(key[:])
}

func (c *csrfProt) check(x string) bool {
	if !strings.HasPrefix(x, "v0:") {
		return false
	}
	x = x[3:]

	var key [48]byte
	_, err := base64.URLEncoding.Decode(key[:], []byte(x))
	if err != nil {
		return false
	}

	// check if expired
	timestamp := binary.LittleEndian.Uint64(key[40:48])
	if time.Now().Unix()-int64(timestamp) > int64(oauth2Validity)/int64(time.Second) {
		return false
	}

	// verify hmac key
	var verify [32]byte
	c.mac.Reset()
	_, _ = c.mac.Write(key[32:48])
	c.mac.Sum(verify[:0])
	macValid := subtle.ConstantTimeCompare(key[:32], verify[:]) == 1

	// check if reused
	n := binary.LittleEndian.Uint64(key[32:40])
	idx := n % csrfDepth
	isReused := c.bitmap[idx/64]&(1<<(idx%64)) != 0

	valid := macValid && !isReused
	if valid {
		// set bit
		c.bitmap[idx/64] |= 1 << (idx % 64)
	}
	return valid
}
