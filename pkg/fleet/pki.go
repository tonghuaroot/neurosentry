// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateDevPKI creates a self-signed CA plus a server and an agent (client)
// leaf certificate under dir — ca.crt/ca.key, server.crt/server.key,
// client.crt/client.key — if they don't already exist (idempotent). It is a
// bootstrap convenience so mTLS works out of the box for demos and single-node
// setups; production should supply certificates from a real CA and never ship
// these. Returns nil when the files are already present.
func GenerateDevPKI(dir string) error {
	files := []string{"ca.crt", "ca.key", "server.crt", "server.key", "client.crt", "client.key"}
	allExist := true
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			allExist = false
			break
		}
	}
	if allExist {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               pkix.Name{CommonName: "NeuroSentry Fleet CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writeCertKey(dir, "ca", caDER, caKey); err != nil {
		return err
	}

	host, _ := os.Hostname()
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: serialNumber(),
		Subject:      pkix.Name{CommonName: "neurosentry-fleet-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", host},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writeCertKey(dir, "server", srvDER, srvKey); err != nil {
		return err
	}

	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: serialNumber(),
		Subject:      pkix.Name{CommonName: "neurosentry-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	return writeCertKey(dir, "client", cliDER, cliKey)
}

func serialNumber() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if n == nil {
		return big.NewInt(1)
	}
	return n
}

func writeCertKey(dir, name string, der []byte, key *ecdsa.PrivateKey) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), certPEM, 0o644); err != nil { //nolint:gosec // G306: certificates are public/world-readable by design
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return os.WriteFile(filepath.Join(dir, name+".key"), keyPEM, 0o600)
}
