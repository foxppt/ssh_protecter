package totp

import (
	qrcode "github.com/skip2/go-qrcode"
	"strings"
)

// TerminalQR encodes only the local otpauth URI. Four-module quiet zones are
// retained. Half-blocks use one terminal cell for two square modules vertically.
// Explicit black foreground/white background works with light and dark themes.
func TerminalQR(secret, account string) (text string, columns int, err error) {
	code, err := qrcode.New(URI(secret, account), qrcode.Medium)
	if err != nil {
		return "", 0, err
	}
	columns = len(code.Bitmap())
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(code.ToSmallString(true), "\n"), "\n") {
		b.WriteString("\x1b[30;107m")
		b.WriteString(line)
		b.WriteString("\x1b[0m\n")
	}
	return b.String(), columns, nil
}
