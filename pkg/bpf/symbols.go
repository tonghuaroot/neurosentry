// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux
// +build linux

package bpf

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SymbolInfo contains information about an ELF symbol
type SymbolInfo struct {
	Name   string
	Offset uint64
}

// resolveELFSymbols parses an ELF file and returns symbols matching the given patterns
// Results are ordered by pattern priority (first pattern = highest priority)
func resolveELFSymbols(libPath string, patterns []string) ([]SymbolInfo, error) {
	f, err := elf.Open(libPath)
	if err != nil {
		return nil, fmt.Errorf("opening ELF file %s: %w", libPath, err)
	}
	defer f.Close()

	// Compile patterns into regexes
	regexes := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			// Treat as literal string match if not a valid regex
			re = regexp.MustCompile(regexp.QuoteMeta(pattern))
		}
		regexes = append(regexes, re)
	}

	// Collect all symbols from both tables
	allSyms := make(map[string]elf.Symbol)

	// Try dynamic symbols first (for shared libraries)
	dynSyms, err := f.DynamicSymbols()
	if err == nil {
		for _, sym := range dynSyms {
			if sym.Value != 0 {
				allSyms[sym.Name] = sym
			}
		}
	}

	// Also check regular symbol table
	syms, err := f.Symbols()
	if err == nil {
		for _, sym := range syms {
			if sym.Value != 0 {
				if _, exists := allSyms[sym.Name]; !exists {
					allSyms[sym.Name] = sym
				}
			}
		}
	}

	// Match symbols in pattern priority order
	var result []SymbolInfo
	matched := make(map[string]bool)

	for _, re := range regexes {
		for name, sym := range allSyms {
			if matched[name] {
				continue
			}
			if re.MatchString(name) {
				result = append(result, SymbolInfo{
					Name:   name,
					Offset: sym.Value,
				})
				matched[name] = true
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no symbols found matching patterns: %v", patterns)
	}

	return result, nil
}

// findPickleModule finds the Python _pickle C extension module
func findPickleModule() (string, error) {
	// Common paths for _pickle module
	picklePaths := []string{
		// System Python on Debian/Ubuntu
		"/usr/lib/python3*/lib-dynload/_pickle.cpython-*.so",
		"/usr/lib/x86_64-linux-gnu/python3*/lib-dynload/_pickle.cpython-*.so",
		// System Python on RHEL/CentOS
		"/usr/lib64/python3*/lib-dynload/_pickle.cpython-*.so",
		// Conda environments
		"/home/*/miniconda3/lib/python3*/lib-dynload/_pickle.cpython-*.so",
		"/home/*/anaconda3/lib/python3*/lib-dynload/_pickle.cpython-*.so",
		"/opt/conda/lib/python3*/lib-dynload/_pickle.cpython-*.so",
		// Virtual environments
		"*/venv/lib/python3*/lib-dynload/_pickle.cpython-*.so",
		// pyenv
		"/home/*/.pyenv/versions/3*/lib/python3*/lib-dynload/_pickle.cpython-*.so",
	}

	// First try to find from running Python processes
	pickleFromProc, err := findPickleFromProc()
	if err == nil && pickleFromProc != "" {
		return pickleFromProc, nil
	}

	// Fall back to searching common paths
	return findLibrary(picklePaths)
}

// findPickleFromProc finds _pickle module from running Python processes
func findPickleFromProc() (string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		// Check if it's a number (PID)
		var pidNum int
		if _, err := fmt.Sscanf(pid, "%d", &pidNum); err != nil {
			continue
		}

		// Read maps to find _pickle module
		mapsPath := fmt.Sprintf("/proc/%s/maps", pid)
		mapsData, err := os.ReadFile(mapsPath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(mapsData), "\n")
		for _, line := range lines {
			if strings.Contains(line, "_pickle.cpython") && strings.HasSuffix(line, ".so") {
				fields := strings.Fields(line)
				if len(fields) > 5 {
					libPath := fields[len(fields)-1]
					if _, err := os.Stat(libPath); err == nil {
						return libPath, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("_pickle module not found in running processes")
}

// findPyTorchModule finds a PyTorch shared library with symbols
func findPyTorchModule() (string, error) {
	// Common PyTorch library paths to search
	torchPaths := []string{
		// User-local pip installs
		"/home/*/.local/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
		"/root/.local/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
		// System-wide installs
		"/usr/local/lib/python3*/dist-packages/torch/lib/libtorch_cpu.so",
		"/usr/local/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
		"/usr/lib/python3*/dist-packages/torch/lib/libtorch_cpu.so",
		"/usr/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
		// Conda environments
		"/home/*/miniconda3/envs/*/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
		"/home/*/miniconda3/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
		"/home/*/anaconda3/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
		"/opt/conda/envs/*/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
		"/opt/conda/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
		// Virtual environments
		"*/venv/lib/python3*/site-packages/torch/lib/libtorch_cpu.so",
	}

	// First try to find from running processes
	torchFromProc, err := findTorchFromProc()
	if err == nil && torchFromProc != "" {
		return torchFromProc, nil
	}

	// Fall back to searching common paths
	return findLibrary(torchPaths)
}

// findTorchFromProc finds libtorch from running processes
func findTorchFromProc() (string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		var pidNum int
		if _, err := fmt.Sscanf(pid, "%d", &pidNum); err != nil {
			continue
		}

		mapsPath := fmt.Sprintf("/proc/%s/maps", pid)
		mapsData, err := os.ReadFile(mapsPath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(mapsData), "\n")
		for _, line := range lines {
			if strings.Contains(line, "libtorch") && strings.HasSuffix(line, ".so") {
				fields := strings.Fields(line)
				if len(fields) > 5 {
					libPath := fields[len(fields)-1]
					if _, err := os.Stat(libPath); err == nil {
						return libPath, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("libtorch not found in running processes")
}

// getPickleSymbolPatterns returns regex patterns for pickle-related symbols
// Patterns are ordered by priority - first match wins
// Supports Python 3.8 - 3.13+
func getPickleSymbolPatterns() []string {
	return []string{
		// Highest priority: direct pickle load functions (if _pickle.so exists separately)
		// Python 3.8-3.12: separate _pickle.cpython-*.so module
		`^_pickle_loads$`,                    // pickle.loads entry
		`^_pickle_load$`,                     // pickle.load entry
		`^_pickle_Unpickler_load$`,           // Unpickler.load method
		`^_pickle_Unpickler_load_impl$`,      // Internal implementation

		// High priority: module initialization (always available in libpython)
		// Called once when module is imported
		`^PyInit__pickle$`, // Python 3.x module init

		// Medium priority: internal functions (may be available in some builds)
		`^load_reduce$`,    // __reduce__ handler - security critical
		`^load_global$`,    // GLOBAL opcode handler - security critical
		`^load_build$`,     // BUILD opcode handler
		`^load_inst$`,      // INST opcode handler
		`^load_newobj$`,    // NEWOBJ opcode handler
		`^load_newobj_ex$`, // NEWOBJ_EX opcode handler

		// Python C API functions (fallback)
		// These are called during pickle operations
		`^PyObject_Call$`,              // Generic object call (noisy but reliable)
		`^PyPickleBuffer_FromObject$`,  // Python 3.8+ buffer protocol
		`^PyPickleBuffer_GetBuffer$`,
		`^PyPickleBuffer_Release$`,

		// Broad patterns as last resort
		`_pickle.*load`,
		`Unpickler.*load`,
		`pickle.*deserialize`,
	}
}

// getPythonVersionSymbols returns version-specific symbol patterns
// This helps handle differences between Python versions
func getPythonVersionSymbols(majorMinor string) []string {
	base := getPickleSymbolPatterns()

	// Add version-specific patterns
	switch majorMinor {
	case "3.8", "3.9":
		// Python 3.8-3.9: _pickle module usually separate
		return append([]string{
			`^_pickle_Unpickler___init__$`,
		}, base...)
	case "3.10", "3.11":
		// Python 3.10-3.11: similar to 3.9
		return append([]string{
			`^_pickle_Unpickler___init___impl$`,
		}, base...)
	case "3.12", "3.13":
		// Python 3.12+: some functions may be inlined
		return append([]string{
			`^_Unpickler_New$`,
			`^Unpickler_init$`,
		}, base...)
	default:
		return base
	}
}

// detectPythonVersion attempts to detect the Python version from the library path
func detectPythonVersion(libPath string) string {
	// Extract version from path like /usr/lib/python3.12/... or libpython3.12.so
	patterns := []string{
		`python3\.(\d+)`,
		`python(\d)\.(\d+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(libPath)
		if len(matches) >= 2 {
			if len(matches) == 2 {
				return "3." + matches[1]
			}
			return matches[1] + "." + matches[2]
		}
	}

	return "" // Unknown version
}

// getPyTorchSymbolPatterns returns regex patterns for PyTorch-related symbols
// Supports PyTorch 1.x and 2.x
func getPyTorchSymbolPatterns() []string {
	return []string{
		// PyTorch 2.x torch.load
		`torch::jit::load`,
		`torch::jit::_load_for_mobile`,
		`torch::serialize::InputArchive`,
		`torch::serialize::OutputArchive`,

		// PyTorch 1.x/2.x common
		`THPModule_load`,
		`_load_from_file`,
		`load_tensor`,

		// Serialization functions
		`torch.*serialize.*load`,
		`torch.*load`,

		// Pickle integration (PyTorch uses pickle internally)
		`Unpickler`,
		`pickle.*load`,

		// Generic patterns as fallback
		`serialize.*Archive`,
		`jit.*load`,
	}
}

// SymbolResolutionStrategy defines how to resolve symbols
type SymbolResolutionStrategy int

const (
	// StrategyBestMatch tries all patterns and returns best matches
	StrategyBestMatch SymbolResolutionStrategy = iota
	// StrategyFirstMatch returns first matching symbol
	StrategyFirstMatch
	// StrategyAllMatches returns all matching symbols
	StrategyAllMatches
)

// ResolveSymbolsWithStrategy resolves symbols using specified strategy
func ResolveSymbolsWithStrategy(libPath string, patterns []string, strategy SymbolResolutionStrategy) ([]SymbolInfo, error) {
	symbols, err := resolveELFSymbols(libPath, patterns)
	if err != nil {
		return nil, err
	}

	switch strategy {
	case StrategyFirstMatch:
		if len(symbols) > 0 {
			return symbols[:1], nil
		}
	case StrategyBestMatch:
		// Sort by pattern priority (already done in resolveELFSymbols)
		if len(symbols) > 3 {
			return symbols[:3], nil
		}
	case StrategyAllMatches:
		return symbols, nil
	}

	return symbols, nil
}

// expandGlobPatterns expands glob patterns and returns all matching paths
func expandGlobPatterns(patterns []string) []string {
	var results []string
	seen := make(map[string]bool)

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if !seen[match] {
				seen[match] = true
				results = append(results, match)
			}
		}
	}

	return results
}
