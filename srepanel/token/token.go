package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"go.mkw.re/ghidra-panel/common"
)

// TODO Integrate BitRing for token expiry

// jwtPrefix is the JWT header of type HS256
const jwtPrefix = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."

const jwtValidity = 90 * 24 * time.Hour

type Issuer struct {
	Secret *[32]byte
}

func NewIssuer(secret *[32]byte) Issuer {
	return Issuer{secret}
}

type Claims struct {
	Sub        uint64 `json:"sub,string"`
	Name       string `json:"name"`
	AvatarHash string `json:"avatar"`
	Iat        int64  `json:"iat"`
}

func (c *Claims) String() string {
	buf, err := json.Marshal(c)
	if err != nil {
		panic("json marshal failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (iss Issuer) Issue(ident *common.Identity) string {
	claims := &Claims{
		Sub:        ident.ID,
		Name:       ident.Username,
		AvatarHash: ident.AvatarHash,
		Iat:        time.Now().Unix(),
	}
	body := jwtPrefix + claims.String()
	return body + "." + iss.sign(body)
}

func (iss Issuer) sign(payload string) string {
	var sig [32]byte
	mac := hmac.New(sha256.New, iss.Secret[:])
	_, _ = mac.Write([]byte(payload))
	mac.Sum(sig[:0])

	return base64.RawURLEncoding.EncodeToString(sig[:])
}

func (iss Issuer) Verify(jwt string) (ident *common.Identity, ok bool) {
	// Laziness
	if !strings.HasPrefix(jwt, jwtPrefix) {
		return nil, false
	}

	// Find signature
	sigSep := strings.LastIndex(jwt, ".")
	if sigSep == -1 {
		return nil, false
	}
	sigB64 := jwt[sigSep+1:]

	// Decode signature
	var sig [32]byte
	_, err := base64.RawURLEncoding.Decode(sig[:], []byte(sigB64))
	if err != nil {
		return nil, false
	}

	// Verify signature
	var sig2 [32]byte
	mac := hmac.New(sha256.New, iss.Secret[:])
	_, _ = mac.Write([]byte(jwt[:sigSep]))
	mac.Sum(sig2[:0])
	macValid := subtle.ConstantTimeCompare(sig[:], sig2[:]) == 1
	if !macValid {
		return nil, false
	}

	// Decode claims
	claimsB64 := jwt[len(jwtPrefix):sigSep]
	claimsBuf, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return nil, false
	}
	var claims Claims
	if err = json.Unmarshal(claimsBuf, &claims); err != nil {
		return nil, false
	}

	// Check expiry
	if time.Now().Unix()-claims.Iat > int64(jwtValidity)/int64(time.Second) {
		return nil, false
	}

	// Reconstruct identity
	return &common.Identity{
		ID:         claims.Sub,
		Username:   claims.Name,
		AvatarHash: claims.AvatarHash,
	}, true
}
