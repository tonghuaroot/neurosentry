// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// pki is a tiny test certificate authority that can issue leaf certs.
type pki struct {
	caPEM  []byte
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "neurosentry-fleet-ca"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31-1, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	return &pki{
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		caCert: caCert,
		caKey:  key,
	}
}

// issue mints a leaf cert/key PEM signed by the CA, valid for the given DNS name.
func (p *pki) issue(t *testing.T, cn, dnsName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if dnsName != "" {
		if ip := net.ParseIP(dnsName); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{dnsName}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestMTLSEnrollSucceedsWithClientCert(t *testing.T) {
	p := newPKI(t)
	srvCert, srvKey := p.issue(t, "control-plane", "127.0.0.1")
	cliCert, cliKey := p.issue(t, "agent-1", "")

	reg := NewRegistry(0)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/fleet/enroll", func(w http.ResponseWriter, r *http.Request) {
		id, _ := reg.Enroll("", AgentInfo{Hostname: "mtls-node"})
		json.NewEncoder(w).Encode(map[string]string{"id": id})
	})

	srv := httptest.NewUnstartedServer(mux)
	sc, err := ServerTLSConfig(p.caPEM, srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = sc
	srv.StartTLS()
	defer srv.Close()

	// Client WITH a valid client cert: handshake + enroll succeed.
	cc, err := ClientTLSConfig(p.caPEM, cliCert, cliKey)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(srv.URL, "token").WithTLS(cc)
	if _, err := c.Enroll(context.Background(), AgentInfo{Hostname: "mtls-node"}); err != nil {
		t.Fatalf("mTLS enroll should succeed with a valid client cert: %v", err)
	}
}

func TestMTLSRejectsClientWithoutCert(t *testing.T) {
	p := newPKI(t)
	srvCert, srvKey := p.issue(t, "control-plane", "127.0.0.1")

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	sc, _ := ServerTLSConfig(p.caPEM, srvCert, srvKey)
	srv.TLS = sc
	srv.StartTLS()
	defer srv.Close()

	// Client that trusts the CA for the server but presents NO client cert:
	// the server must reject the handshake (RequireAndVerifyClientCert).
	noCertCfg, _ := ClientTLSConfig(p.caPEM, srvCert, srvKey) // reuse a cert...
	noCertCfg.Certificates = nil                              // ...then drop it
	c := NewClient(srv.URL, "token").WithTLS(noCertCfg)
	if _, err := c.Enroll(context.Background(), AgentInfo{}); err == nil {
		t.Error("mTLS server must reject a client that presents no certificate")
	}
}

func TestMTLSConfigRejectsBadCA(t *testing.T) {
	if _, err := ServerTLSConfig([]byte("not-a-cert"), nil, nil); err == nil {
		t.Error("bad CA PEM should error")
	}
}
