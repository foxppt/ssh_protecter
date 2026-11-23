package service

import (
	"crypto/tls"
	"fmt"
	"ssh-protecter/internal/config"
	"sync/atomic"
)

type Certificates struct {
	current atomic.Pointer[tls.Certificate]
}

func PrepareCertificate(c config.Config) (*tls.Certificate, error) {
	if c.HTTP.Mode != "direct_tls" {
		return nil, nil
	}
	cert, e := tls.LoadX509KeyPair(c.HTTP.TLSCertFile, c.HTTP.TLSKeyFile)
	if e != nil {
		return nil, fmt.Errorf("prepare TLS certificate: %w", e)
	}
	return &cert, nil
}
func (c *Certificates) Publish(cert *tls.Certificate) { c.current.Store(cert) }
func (c *Certificates) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	v := c.current.Load()
	if v == nil {
		return nil, fmt.Errorf("TLS certificate unavailable")
	}
	return v, nil
}
