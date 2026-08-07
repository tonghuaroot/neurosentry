// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import "time"

// Detection-efficacy validation (purple-team). A detection you can't prove
// fires is a detection you don't have. AttackScenario pairs a rule ID with a
// synthetic signal chain that should trigger it; ValidateRules replays each
// scenario through a fresh correlator and reports which rules fired. Run in CI
// so a refactor that silently breaks a detection fails the build, and so every
// new rule is forced to ship with a proof-of-fire (see the completeness check
// in the test).

// AttackScenario is a named, replayable attack that should trip exactly the
// rule named by WantRuleID.
type AttackScenario struct {
	Name       string
	WantRuleID string
	Signals    []Signal
}

// ValidationResult reports the outcome of replaying one scenario.
type ValidationResult struct {
	Scenario string
	RuleID   string
	Fired    bool
}

// ValidateRules replays every scenario against a fresh correlator (isolated per
// scenario so cooldowns/among-rule interference can't mask a miss) and reports
// whether each expected rule fired.
func ValidateRules(scenarios []AttackScenario) []ValidationResult {
	out := make([]ValidationResult, 0, len(scenarios))
	for _, sc := range scenarios {
		c := NewCorrelator(BuiltinRules())
		fired := map[string]bool{}
		c.OnFinding(func(f Finding) { fired[f.RuleID] = true })
		for _, s := range sc.Signals {
			c.Ingest(s)
		}
		out = append(out, ValidationResult{
			Scenario: sc.Name,
			RuleID:   sc.WantRuleID,
			Fired:    fired[sc.WantRuleID],
		})
	}
	return out
}

// BuiltinScenarios is the curated purple-team suite: one proof-of-fire per
// built-in correlation rule. Timestamps are ordered within each rule's window.
func BuiltinScenarios() []AttackScenario {
	base := time.Unix(1_700_000_000, 0)
	at := func(d time.Duration) time.Time { return base.Add(d) }

	return []AttackScenario{
		{
			Name: "secret read then LLM egress", WantRuleID: "NS-CORR-001",
			Signals: []Signal{
				{PID: 10, Layer: LayerKernelFile, Kind: "file_read", Attributes: map[string]string{"path": "/etc/shadow"}, Timestamp: at(0)},
				{PID: 10, Layer: LayerKernelNet, Kind: "net_connect", Attributes: map[string]string{"ai_provider": "openai"}, Timestamp: at(time.Second)},
			},
		},
		{
			Name: "tool call then external egress", WantRuleID: "NS-CORR-002",
			Signals: []Signal{
				{PID: 11, Layer: LayerMCP, Kind: "tool_call", Attributes: map[string]string{"tool": "fetch"}, Timestamp: at(0)},
				{PID: 11, Layer: LayerKernelNet, Kind: "net_connect", Attributes: map[string]string{"dst": "203.0.113.7"}, Timestamp: at(time.Second)},
			},
		},
		{
			Name: "tool call then process exec", WantRuleID: "NS-CORR-003",
			Signals: []Signal{
				{PID: 12, Layer: LayerMCP, Kind: "tool_call", Attributes: map[string]string{"tool": "run"}, Timestamp: at(0)},
				{PID: 12, Layer: LayerKernelProc, Kind: "exec", Attributes: map[string]string{"comm": "python"}, Timestamp: at(time.Second)},
			},
		},
		{
			Name: "prompt injection then kernel side effect", WantRuleID: "NS-CORR-004",
			Signals: []Signal{
				{PID: 13, Layer: LayerAI, Kind: "prompt", Attributes: map[string]string{"injection": "malicious"}, Timestamp: at(0)},
				{PID: 13, Layer: LayerKernelProc, Kind: "exec", Attributes: map[string]string{"comm": "sh"}, Timestamp: at(2 * time.Second)},
			},
		},
		{
			Name: "unverified model load", WantRuleID: "NS-CORR-005",
			Signals: []Signal{
				{PID: 14, Layer: LayerModel, Kind: "load", Attributes: map[string]string{"verified": "false"}, Timestamp: at(0)},
			},
		},
		{
			Name: "pickle load then exec (deserialization RCE)", WantRuleID: "NS-CORR-006",
			Signals: []Signal{
				{PID: 15, Layer: LayerModel, Kind: "pickle_load", Attributes: map[string]string{"path": "model.pkl"}, Timestamp: at(0)},
				{PID: 15, Layer: LayerKernelProc, Kind: "exec", Attributes: map[string]string{"comm": "bash"}, Timestamp: at(time.Second)},
			},
		},
		{
			Name: "model read then external egress (weight theft)", WantRuleID: "NS-CORR-007",
			Signals: []Signal{
				{PID: 16, Layer: LayerKernelFile, Kind: "file_read", Attributes: map[string]string{"path": "/models/llama.safetensors"}, Timestamp: at(0)},
				{PID: 16, Layer: LayerKernelNet, Kind: "net_connect", Attributes: map[string]string{"dst": "198.51.100.9"}, Timestamp: at(3 * time.Second)},
			},
		},
		{
			Name: "shell process opens external connection (C2)", WantRuleID: "NS-CORR-008",
			Signals: []Signal{
				{PID: 17, Layer: LayerKernelProc, Kind: "exec", Attributes: map[string]string{"comm": "nc"}, Timestamp: at(0)},
				{PID: 17, Layer: LayerKernelNet, Kind: "net_connect", Attributes: map[string]string{"dst": "203.0.113.42"}, Timestamp: at(time.Second)},
			},
		},
		{
			Name: "container-escape path access", WantRuleID: "NS-CORR-009",
			Signals: []Signal{
				{PID: 18, Layer: LayerKernelFile, Kind: "file_open", Attributes: map[string]string{"path": "/var/run/docker.sock"}, Timestamp: at(0)},
			},
		},
		{
			Name: "shadow-AI egress", WantRuleID: "NS-CORR-010",
			Signals: []Signal{
				{PID: 19, Layer: LayerKernelNet, Kind: "net_connect", Attributes: map[string]string{"shadow_ai": "true", "dst": "104.18.0.1"}, Timestamp: at(0)},
			},
		},
		{
			Name: "tool call then secret read", WantRuleID: "NS-CORR-011",
			Signals: []Signal{
				{PID: 20, Layer: LayerMCP, Kind: "tool_call", Attributes: map[string]string{"tool": "read_file"}, Timestamp: at(0)},
				{PID: 20, Layer: LayerKernelFile, Kind: "file_read", Attributes: map[string]string{"path": "/home/u/.aws/credentials"}, Timestamp: at(time.Second)},
			},
		},
	}
}
