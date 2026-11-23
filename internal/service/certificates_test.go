package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"ssh-protecter/internal/config"
	"testing"
	"time"
)

func certificateFiles(t *testing.T, serial int64) (string, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	v := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, v, v, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); e != nil {
		t.Fatal(e)
	}
	return certPath, keyPath
}
func TestCertificateSwitchOnNewHandshake(t *testing.T) {
	c := config.Defaults()
	c.HTTP.TLSCertFile, c.HTTP.TLSKeyFile = certificateFiles(t, 1)
	first, e := PrepareCertificate(c)
	if e != nil {
		t.Fatal(e)
	}
	slot := &Certificates{}
	slot.Publish(first)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	server.TLS = &tls.Config{GetCertificate: slot.GetCertificate, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	// httptest adds its default certificate; remove it so every handshake uses our callback.
	server.TLS.Certificates = nil
	serial := func() int64 {
		conn, e := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	if serial() != 1 {
		t.Fatal("initial certificate not used")
	}
	c.HTTP.TLSCertFile, c.HTTP.TLSKeyFile = certificateFiles(t, 2)
	second, e := PrepareCertificate(c)
	if e != nil {
		t.Fatal(e)
	}
	slot.Publish(second)
	if serial() != 2 {
		t.Fatal("new handshake did not use replacement certificate")
	}
	c.HTTP.TLSKeyFile = "missing"
	if _, e = PrepareCertificate(c); e == nil {
		t.Fatal("bad certificate accepted")
	}
	if serial() != 2 {
		t.Fatal("bad certificate replaced working certificate")
	}
}
