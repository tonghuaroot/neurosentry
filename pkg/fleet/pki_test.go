// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDevPKIAndMutualTLS(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateDevPKI(dir); err != nil {
		t.Fatal(err)
	}
	// Idempotent: a second call is a no-op and keeps the same CA.
	caBefore, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err := GenerateDevPKI(dir); err != nil {
		t.Fatal(err)
	}
	caAfter, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if string(caBefore) != string(caAfter) {
		t.Error("GenerateDevPKI regenerated an existing CA")
	}

	read := func(n string) []byte { b, _ := os.ReadFile(filepath.Join(dir, n)); return b }
	srvCfg, err := ServerTLSConfig(read("ca.crt"), read("server.crt"), read("server.key"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	srv.TLS = srvCfg
	srv.StartTLS()
	defer srv.Close()

	// A client presenting the agent cert is accepted.
	cliCfg, err := ClientTLSConfig(read("ca.crt"), read("client.crt"), read("client.key"))
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cliCfg}}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("client with cert should be accepted: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Errorf("unexpected body: %q", b)
	}

	// A client WITHOUT a client cert is rejected at the handshake.
	noCert := ClientTLSConfigNoCert(read("ca.crt"))
	c2 := &http.Client{Transport: &http.Transport{TLSClientConfig: noCert}}
	if _, err := c2.Get(srv.URL); err == nil {
		t.Error("client without a certificate should be rejected by mTLS")
	}
}

// ClientTLSConfigNoCert trusts the CA but presents no client cert (for the
// negative mTLS test).
func ClientTLSConfigNoCert(caPEM []byte) *tls.Config {
	cfg, _ := ClientTLSConfig(caPEM, nil, nil)
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.Certificates = nil
	return cfg
}
