package totp

import (
	"github.com/makiuchi-d/gozxing"
	zxingqr "github.com/makiuchi-d/gozxing/qrcode"
	"image"
	"image/color"
	"net/url"
	"strings"
	"testing"
)

// Decode the actual rendered terminal glyphs with an independent QR decoder,
// rather than checking the encoder's own payload or copying its matrix.
func TestTerminalQRScansToAuthenticatorURI(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, account := range []string{"server.example.com", "服务器01", "host:with spaces/?&"} {
		t.Run(account, func(t *testing.T) {
			text, columns, e := TerminalQR(secret, account)
			if e != nil {
				t.Fatal(e)
			}
			text = strings.ReplaceAll(text, "\x1b[30;107m", "")
			text = strings.ReplaceAll(text, "\x1b[0m", "")
			lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
			const scale = 6
			img := image.NewGray(image.Rect(0, 0, columns*scale, len(lines)*2*scale))
			for y, line := range lines {
				cells := []rune(line)
				if len(cells) != columns {
					t.Fatal("inconsistent row widths")
				}
				for x, c := range cells {
					var top, bottom bool
					switch c {
					case '█':
						top, bottom = true, true
					case '▀':
						top = true
					case '▄':
						bottom = true
					case ' ':
					default:
						t.Fatalf("unexpected QR glyph %q", c)
					}
					for dy := 0; dy < 2*scale; dy++ {
						black := top
						if dy >= scale {
							black = bottom
						}
						v := color.Gray{Y: 255}
						if black {
							v.Y = 0
						}
						for dx := 0; dx < scale; dx++ {
							img.SetGray(x*scale+dx, y*2*scale+dy, v)
						}
					}
				}
			}
			bitmap, e := gozxing.NewBinaryBitmapFromImage(img)
			if e != nil {
				t.Fatal(e)
			}
			result, e := zxingqr.NewQRCodeReader().Decode(bitmap, nil)
			if e != nil {
				t.Fatalf("rendered QR cannot be scanned: %v", e)
			}
			payload := result.GetText()
			if payload != URI(secret, account) {
				t.Fatalf("scanned QR does not match binding URI: got %q want %q", payload, URI(secret, account))
			}
			u, e := url.Parse(payload)
			if e != nil {
				t.Fatal(e)
			}
			if u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != secret || u.Query().Get("issuer") != "ssh-protecter" || u.Query().Get("digits") != "6" || u.Query().Get("period") != "30" {
				t.Fatal("incorrect authenticator provisioning parameters")
			}
		})
	}
}
