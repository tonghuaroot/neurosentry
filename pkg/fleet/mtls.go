// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// Mutual TLS for the fleet control plane. The shared enrollment token proves an
// agent knows a secret; mTLS additionally proves it holds a private key whose
// certificate a trusted CA issued — the stronger authentication enterprises
// expect for agent↔control-plane traffic. These builders produce the tls.Config
// for a dedicated agent listener (server side) and the agent (client side); both
// verify the peer against the same CA.

// ServerTLSConfig builds a server tls.Config that presents certPEM/keyPEM and
// REQUIRES a client certificate signed by caPEM (mutual auth).
func ServerTLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: server keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mtls: no CA certs parsed")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ClientTLSConfig builds a client tls.Config that presents certPEM/keyPEM and
// verifies the server against caPEM.
func ClientTLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: client keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mtls: no CA certs parsed")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
