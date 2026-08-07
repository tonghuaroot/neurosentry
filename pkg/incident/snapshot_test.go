package incident

import (
	"github.com/neurosentry/neurosentry/pkg/correlate"
	"testing"
)

func TestCaseSnapshotRestore(t *testing.T) {
	s := NewStore()
	s.Add(correlate.Finding{RuleID: "NS-CORR-001", Rule: "secret", Severity: "critical", PID: 42})
	s.Add(correlate.Finding{RuleID: "NS-CORR-008", Rule: "revshell", Severity: "critical", PID: 99})
	blob, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	s2 := NewStore()
	if err := s2.Restore(blob); err != nil {
		t.Fatal(err)
	}
	if got := len(s2.List(Filter{})); got != 2 {
		t.Fatalf("restored store should have 2 cases, got %d", got)
	}
}
