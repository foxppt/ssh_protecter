//go:build !linux

package firewall

import "fmt"

func AcquireNative() (Runner, func(), error) {
	return nil, nil, fmt.Errorf("firewall application is supported only on Linux")
}
