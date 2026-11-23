package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestRFC6238(t *testing.T) {
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		at   int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		got, e := code(s, v.at/30, 8)
		if e != nil || got != v.want {
			t.Fatalf("%d: %s %v", v.at, got, e)
		}
	}
}
func TestReplayAndWindow(t *testing.T) {
	s, e := NewSecret()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	c, e := Code(s, now)
	if e != nil {
		t.Fatal(e)
	}
	if !Verify(s, c, now) || !Verify(s, c, now) || !Verify(s, c, now.Add(30*time.Second)) || Verify(s, c, now.Add(60*time.Second)) || Verify(s, "0000000", now) {
		t.Fatal("incorrect TOTP validation window/replay")
	}
}
