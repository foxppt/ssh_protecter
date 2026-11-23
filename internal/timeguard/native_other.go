//go:build !linux

package timeguard

import "fmt"

func CheckSynchronized() error { return fmt.Errorf("kernel synchronization check requires Linux") }
