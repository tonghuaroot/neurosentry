// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/xml"
	"net/url"
	"testing"

	"github.com/crewjam/saml"
)

// idpMetadataXML builds a minimal but valid IdP SAML metadata document with a
// real signing certificate, so NewSAMLProvider can be exercised offline.
func idpMetadataXML(t *testing.T) string {
	t.Helper()
	_, cert, err := ephemeralKeypair("https://idp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ssoURL, _ := url.Parse("https://idp.example.com/sso")
	idp := saml.IdentityProvider{
		Certificate: cert,
		MetadataURL: url.URL{Scheme: "https", Host: "idp.example.com", Path: "/metadata"},
		SSOURL:      *ssoURL,
	}
	md := idp.Metadata()
	b, err := xml.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func testSAMLConfig(t *testing.T) SAMLConfig {
	return SAMLConfig{
		SPEntityID:      "https://neurosentry.example.com/saml",
		ACSURL:          "https://neurosentry.example.com/api/auth/sso/saml/acs",
		IDPMetadataXML:  idpMetadataXML(t),
		GroupsAttribute: "groups",
		EmailAttribute:  "email",
		RoleMap:         map[string]Role{"sec-admins": RoleAdmin},
		DefaultRoles:    []Role{RoleViewer},
	}
}

func TestSAMLProviderParsesMetadata(t *testing.T) {
	p, err := NewSAMLProvider(testSAMLConfig(t))
	if err != nil {
		t.Fatalf("provider setup failed: %v", err)
	}
	if p.sp.IDPMetadata == nil || p.sp.IDPMetadata.EntityID == "" {
		t.Error("IdP metadata not loaded")
	}
	if !p.sp.AllowIDPInitiated {
		t.Error("expected IdP-initiated SSO to be allowed")
	}
}

func TestSAMLProviderRejectsInvalidMetadata(t *testing.T) {
	cfg := testSAMLConfig(t)
	cfg.IDPMetadataXML = "<not-metadata/>"
	if _, err := NewSAMLProvider(cfg); err == nil {
		t.Error("invalid IdP metadata should error")
	}
}

// A garbage / unsigned response must be rejected — proving we actually validate
// the signature via the vetted library rather than trusting input.
func TestSAMLRejectsUnsignedResponse(t *testing.T) {
	p, err := NewSAMLProvider(testSAMLConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"bm90LWJhc2U2NA==", // not a SAML doc
		"PFJlc3BvbnNlPjxBc3NlcnRpb24+bm8gc2lnbmF0dXJlPC9Bc3NlcnRpb24+PC9SZXNwb25zZT4=", // unsigned <Response>
	} {
		if _, err := p.ParseAssertion(bad); err == nil {
			t.Errorf("unsigned/garbage response %q must be rejected", bad)
		}
	}
	if _, err := p.ParseAssertion("!!!not base64!!!"); err == nil {
		t.Error("non-base64 must be rejected")
	}
}

// extract() is the assertion -> claims logic; test it directly on a built
// assertion (no signature needed for this unit).
func TestSAMLExtractClaims(t *testing.T) {
	p, err := NewSAMLProvider(testSAMLConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	assertion := &saml.Assertion{
		Subject: &saml.Subject{NameID: &saml.NameID{Value: "jane@example.com"}},
		AttributeStatements: []saml.AttributeStatement{{
			Attributes: []saml.Attribute{
				{Name: "groups", Values: []saml.AttributeValue{{Value: "sec-admins"}, {Value: "everyone"}}},
				{Name: "email", Values: []saml.AttributeValue{{Value: "jane@example.com"}}},
			},
		}},
	}
	c := p.extract(assertion)
	if c.NameID != "jane@example.com" || c.Email != "jane@example.com" {
		t.Errorf("unexpected identity: %+v", c)
	}
	if len(c.Groups) != 2 {
		t.Errorf("expected 2 groups, got %v", c.Groups)
	}
	roles := p.MapRoles(c.Groups)
	if !hasRole(roles, RoleAdmin) || !hasRole(roles, RoleViewer) {
		t.Errorf("group mapping wrong: %v", roles)
	}
}

func TestSAMLMapRolesFloor(t *testing.T) {
	cfg := SAMLConfig{} // no defaults, no map
	if roles := cfg.MapRoles([]string{"unmapped"}); len(roles) != 1 || roles[0] != RoleViewer {
		t.Errorf("expected viewer floor, got %v", roles)
	}
}
