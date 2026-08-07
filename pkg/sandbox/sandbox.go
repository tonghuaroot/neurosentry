// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package sandbox

import "fmt"

type Access int

const (
	AccessRead Access = iota
	AccessReadWrite
	AccessDeny
)

type Rule struct {
	Path   string `json:"path" yaml:"path"`
	Access Access `json:"access" yaml:"access"`
}

func (r Rule) String() string {
	labels := map[Access]string{
		AccessRead:      "read",
		AccessReadWrite: "read-write",
		AccessDeny:      "deny",
	}
	return fmt.Sprintf("%s:%s", labels[r.Access], r.Path)
}

type Profile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Rules   []Rule `json:"rules"`
}

func NewProfile(name string) *Profile {
	return &Profile{Name: name, Enabled: true}
}

func (p *Profile) AllowRead(path string) {
	p.Rules = append(p.Rules, Rule{Path: path, Access: AccessRead})
}

func (p *Profile) AllowReadWrite(path string) {
	p.Rules = append(p.Rules, Rule{Path: path, Access: AccessReadWrite})
}

func (p *Profile) DenyAccess(path string) {
	p.Rules = append(p.Rules, Rule{Path: path, Access: AccessDeny})
}

func (p *Profile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("profile name is required")
	}
	for i, r := range p.Rules {
		if r.Path == "" {
			return fmt.Errorf("rule %d: path is required", i)
		}
	}
	return nil
}

type Config struct {
	Enabled        bool     `mapstructure:"enabled" yaml:"enabled"`
	ReadOnlyPaths  []string `mapstructure:"read_only_paths" yaml:"read_only_paths"`
	ReadWritePaths []string `mapstructure:"read_write_paths" yaml:"read_write_paths"`
	DenyPaths      []string `mapstructure:"deny_paths" yaml:"deny_paths"`
}

func DefaultConfig() Config {
	return Config{Enabled: false}
}

func ProfileFromConfig(cfg Config) *Profile {
	p := NewProfile("neurosentry-sandbox")
	p.Enabled = cfg.Enabled
	for _, path := range cfg.ReadOnlyPaths {
		p.AllowRead(path)
	}
	for _, path := range cfg.ReadWritePaths {
		p.AllowReadWrite(path)
	}
	for _, path := range cfg.DenyPaths {
		p.DenyAccess(path)
	}
	return p
}
