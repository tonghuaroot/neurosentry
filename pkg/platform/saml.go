// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/crewjam/saml"
)

// SAML 2.0 single sign-on. The security-critical work — XML canonicalization
// and signature verification — is delegated to the vetted crewjam/saml +
// goxmldsig libraries; NeuroSentry only configures the Service Provider from the
// IdP's metadata and maps the returned assertion's attributes onto RBAC roles,
// exactly as the OIDC path does. Never hand-roll XML-DSig.

// SAMLConfig configures one SAML IdP for a tenant.
type SAMLConfig struct {
	SPEntityID      string          `json:"sp_entity_id"`     // this SP's entity ID
	ACSURL          string          `json:"acs_url"`          // assertion consumer service URL
	IDPMetadataXML  string          `json:"idp_metadata_xml"` // the IdP's SAML metadata document
	GroupsAttribute string          `json:"groups_attribute"` // assertion attribute holding groups
	EmailAttribute  string          `json:"email_attribute"`  // assertion attribute holding email
	RoleMap         map[string]Role `json:"role_map"`         // IdP group -> role
	DefaultRoles    []Role          `json:"default_roles"`
}

// SAMLClaims is the subset of a verified assertion NeuroSentry consumes.
type SAMLClaims struct {
	NameID string
	Email  string
	Groups []string
}

// SAMLProvider validates SAML responses for one IdP.
type SAMLProvider struct {
	sp     saml.ServiceProvider
	cfg    SAMLConfig
	acsURL url.URL
}

// NewSAMLProvider builds a provider from the IdP metadata and SP settings.
func NewSAMLProvider(cfg SAMLConfig) (*SAMLProvider, error) {
	if cfg.IDPMetadataXML == "" || cfg.ACSURL == "" {
		return nil, fmt.Errorf("saml: idp_metadata_xml and acs_url are required")
	}
	meta, err := parseIDPMetadata([]byte(cfg.IDPMetadataXML))
	if err != nil {
		return nil, fmt.Errorf("saml: parse idp metadata: %w", err)
	}
	acs, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: bad acs_url: %w", err)
	}
	// The SP key/cert are used to sign AuthnRequests and decrypt encrypted
	// assertions. For validating signed (unencrypted) responses they're not
	// consulted, but the struct wants them non-nil, so mint an ephemeral pair.
	key, cert, err := ephemeralKeypair(cfg.SPEntityID)
	if err != nil {
		return nil, err
	}
	if cfg.GroupsAttribute == "" {
		cfg.GroupsAttribute = "groups"
	}
	if cfg.EmailAttribute == "" {
		cfg.EmailAttribute = "email"
	}
	sp := saml.ServiceProvider{
		EntityID:          cfg.SPEntityID,
		Key:               key,
		Certificate:       cert,
		AcsURL:            *acs,
		IDPMetadata:       meta,
		AllowIDPInitiated: true, // accept IdP-initiated SSO (no prior AuthnRequest)
	}
	return &SAMLProvider{sp: sp, cfg: cfg, acsURL: *acs}, nil
}

// ParseAssertion validates a base64 SAMLResponse (signature, issuer, audience,
// time bounds — all via the vetted library) and returns its claims.
func (p *SAMLProvider) ParseAssertion(samlResponseB64 string) (*SAMLClaims, error) {
	raw, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return nil, fmt.Errorf("saml: bad base64: %w", err)
	}
	// IdP-initiated: no request IDs to correlate (AllowIDPInitiated permits it).
	assertion, err := p.sp.ParseXMLResponse(raw, []string{}, p.acsURL)
	if err != nil {
		return nil, fmt.Errorf("saml: response rejected: %w", err)
	}
	return p.extract(assertion), nil
}

func (p *SAMLProvider) extract(a *saml.Assertion) *SAMLClaims {
	c := &SAMLClaims{}
	if a.Subject != nil && a.Subject.NameID != nil {
		c.NameID = a.Subject.NameID.Value
	}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			name := attr.Name
			friendly := attr.FriendlyName
			switch {
			case name == p.cfg.GroupsAttribute || friendly == p.cfg.GroupsAttribute:
				for _, v := range attr.Values {
					if v.Value != "" {
						c.Groups = append(c.Groups, v.Value)
					}
				}
			case name == p.cfg.EmailAttribute || friendly == p.cfg.EmailAttribute:
				if len(attr.Values) > 0 {
					c.Email = attr.Values[0].Value
				}
			}
		}
	}
	if c.Email == "" {
		c.Email = c.NameID // NameID is often the email address
	}
	return c
}

// MapRoles resolves IdP groups to NeuroSentry roles (default-role floor),
// mirroring the OIDC mapping semantics.
func (cfg SAMLConfig) MapRoles(groups []string) []Role {
	seen := map[Role]struct{}{}
	var roles []Role
	add := func(r Role) {
		if _, dup := seen[r]; !dup {
			seen[r] = struct{}{}
			roles = append(roles, r)
		}
	}
	for _, r := range cfg.DefaultRoles {
		add(r)
	}
	for _, g := range groups {
		if r, ok := cfg.RoleMap[g]; ok {
			add(r)
		}
	}
	if len(roles) == 0 {
		add(RoleViewer)
	}
	return roles
}

// MapRoles on the provider delegates to its config.
func (p *SAMLProvider) MapRoles(groups []string) []Role { return p.cfg.MapRoles(groups) }

// parseIDPMetadata unmarshals a SAML metadata document, accepting either a bare
// EntityDescriptor or an EntitiesDescriptor wrapper (taking the first entity).
func parseIDPMetadata(data []byte) (*saml.EntityDescriptor, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err == nil && ed.EntityID != "" {
		return &ed, nil
	}
	var eds saml.EntitiesDescriptor
	if err := xml.Unmarshal(data, &eds); err != nil {
		return nil, err
	}
	if len(eds.EntityDescriptors) == 0 {
		return nil, fmt.Errorf("no entity descriptors in metadata")
	}
	return &eds.EntityDescriptors[0], nil
}

// ephemeralKeypair mints a throwaway self-signed RSA key/cert for the SP.
func ephemeralKeypair(cn string) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("saml: sp key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("saml: sp cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}
