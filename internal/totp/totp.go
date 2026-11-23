package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func NewSecret() (string, error) {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
func URI(secret, account string) string {
	q := url.Values{"secret": {secret}, "issuer": {"ssh-protecter"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("ssh-protecter:"+account) + "?" + q.Encode()
}
func Code(secret string, at time.Time) (string, error) { return code(secret, at.Unix()/30, 6) }
func code(secret string, step int64, digits int) (string, error) {
	b, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if e != nil || len(b) < 20 || step < 0 {
		return "", fmt.Errorf("invalid TOTP secret/time")
	}
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(step))
	h := hmac.New(sha1.New, b)
	h.Write(c[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 15
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1000000)
	if digits == 8 {
		mod = 100000000
	}
	return fmt.Sprintf("%0*d", digits, v%mod), nil
}

// Verify deliberately allows replay within the configured fixed +/- one step window.
func Verify(secret, input string, at time.Time) bool {
	if len(input) != 6 {
		return false
	}
	for _, c := range input {
		if c < '0' || c > '9' {
			return false
		}
	}
	valid := 0
	for _, delta := range []int64{-1, 0, 1} {
		v, e := code(secret, at.Unix()/30+delta, 6)
		if e == nil {
			valid |= subtle.ConstantTimeCompare([]byte(v), []byte(input))
		}
	}
	return valid == 1
}
