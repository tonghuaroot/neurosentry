// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	landlockAccessFSReadFile  = 1 << 0
	landlockAccessFSReadDir   = 1 << 1
	landlockAccessFSWriteFile = 1 << 5
	landlockAccessFSMakeDir   = 1 << 7
)

func IsSupported() bool {
	attr := unix.LandlockRulesetAttr{
		Access_fs: landlockAccessFSReadFile,
	}
	fd, err := landlockCreateRuleset(&attr, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

func (p *Profile) Apply() error {
	if !p.Enabled {
		return nil
	}

	if err := p.Validate(); err != nil {
		return err
	}

	if !IsSupported() {
		log.Printf("Landlock not supported on this kernel, sandbox rules not enforced")
		return nil
	}

	var handledAccess uint64
	for _, r := range p.Rules {
		switch r.Access {
		case AccessRead:
			handledAccess |= landlockAccessFSReadFile | landlockAccessFSReadDir
		case AccessReadWrite:
			handledAccess |= landlockAccessFSReadFile | landlockAccessFSReadDir |
				landlockAccessFSWriteFile | landlockAccessFSMakeDir
		case AccessDeny:
			handledAccess |= landlockAccessFSReadFile | landlockAccessFSReadDir |
				landlockAccessFSWriteFile | landlockAccessFSMakeDir
		}
	}

	attr := unix.LandlockRulesetAttr{
		Access_fs: handledAccess,
	}
	rulesetFd, err := landlockCreateRuleset(&attr, 0)
	if err != nil {
		return fmt.Errorf("landlock_create_ruleset: %w", err)
	}
	defer unix.Close(rulesetFd)

	for _, r := range p.Rules {
		if r.Access == AccessDeny {
			continue
		}

		var allowedAccess uint64
		switch r.Access {
		case AccessRead:
			allowedAccess = landlockAccessFSReadFile | landlockAccessFSReadDir
		case AccessReadWrite:
			allowedAccess = landlockAccessFSReadFile | landlockAccessFSReadDir |
				landlockAccessFSWriteFile | landlockAccessFSMakeDir
		case AccessDeny:
			// Filtered out above (continue); listed for exhaustiveness.
			continue
		}

		pathFd, err := unix.Open(r.Path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			log.Printf("sandbox: cannot open path %s: %v (skipping rule)", r.Path, err)
			continue
		}

		pathAttr := unix.LandlockPathBeneathAttr{
			Allowed_access: allowedAccess,
			Parent_fd:      int32(pathFd), //nolint:gosec // G115: file descriptors are small non-negative ints
		}
		err = landlockAddRule(rulesetFd, &pathAttr)
		unix.Close(pathFd)
		if err != nil {
			return fmt.Errorf("landlock_add_rule for %s: %w", r.Path, err)
		}
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(NO_NEW_PRIVS): %w", err)
	}

	if err := landlockRestrictSelf(rulesetFd, 0); err != nil {
		return fmt.Errorf("landlock_restrict_self: %w", err)
	}

	log.Printf("Landlock sandbox applied: %d rules", len(p.Rules))
	return nil
}

func landlockCreateRuleset(attr *unix.LandlockRulesetAttr, flags uint32) (int, error) {
	r, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
		uintptr(flags),
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

func landlockAddRule(rulesetFd int, attr *unix.LandlockPathBeneathAttr) error {
	const LANDLOCK_RULE_PATH_BENEATH = 1
	_, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFd),
		LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(attr)),
		0, 0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func landlockRestrictSelf(rulesetFd int, flags uint32) error {
	_, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(rulesetFd),
		uintptr(flags),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
