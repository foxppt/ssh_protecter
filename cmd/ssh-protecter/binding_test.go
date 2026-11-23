package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestBindingInfoQRAndPlainFallback(t *testing.T) {
	for _, v := range []struct {
		name   string
		qr     bool
		width  int
		wantQR bool
	}{{"normal", true, 120, true}, {"narrow", true, 20, false}, {"plain", false, 120, false}} {
		t.Run(v.name, func(t *testing.T) {
			var out bytes.Buffer
			const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
			if e := writeBindingInfo(&out, secret, "server.example", v.qr, v.width); e != nil {
				t.Fatal(e)
			}
			if strings.Contains(out.String(), "\x1b[30;107m") != v.wantQR {
				t.Fatal("incorrect QR fallback")
			}
			if !strings.Contains(out.String(), secret) || !strings.Contains(out.String(), "otpauth://totp/") {
				t.Fatal("missing manual binding fallback")
			}
		})
	}
}
