// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

func IsSupported() bool { return false }

func (p *Profile) Apply() error {
	if !p.Enabled {
		return nil
	}
	return nil
}
