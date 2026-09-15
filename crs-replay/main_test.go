package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestReplayDetectsAttackInEncodedQuery(t *testing.T) {
	engine, err := newReplayEngine()
	if err != nil {
		t.Fatal(err)
	}
	result := engine.replay(event{
		EventID: "EV-4821",
		eventFields: eventFields{
			IP:       "10.21.224.123",
			Method:   "GET",
			Path:     "/?instawp-database-manager=/../../../%2e%2fmigrate%2ftemplates%2fdebug%2fdb-table&table_name=wp_users--%20-",
			Protocol: "HTTP/1.1",
			Status:   200,
		},
	})

	if result.Error != "" {
		t.Fatal(result.Error)
	}
	if result.AttackCount == 0 {
		t.Fatalf("expected an attack rule, got %#v", result.Matched)
	}
	if result.Coverage.Level != "partial" {
		t.Fatalf("expected partial coverage, got %q", result.Coverage.Level)
	}
}

func TestReplayDoesNotMarkOrdinaryRequestAsAttack(t *testing.T) {
	engine, err := newReplayEngine()
	if err != nil {
		t.Fatal(err)
	}
	result := engine.replay(event{
		eventFields: eventFields{
			IP:       "192.0.2.10",
			Method:   "GET",
			Path:     "/products?category=books&page=2",
			Protocol: "HTTP/1.1",
		},
	})

	if result.Error != "" {
		t.Fatal(result.Error)
	}
	if result.AttackCount != 0 {
		t.Fatalf("expected no attack rule, got %#v", result.Matched)
	}
}

func TestRunKeepsOneOutputPerInputLine(t *testing.T) {
	input := strings.Join([]string{
		`{"event_id":"valid","ip":"192.0.2.10","method":"GET","path":"/","protocol":"HTTP/1.1"}`,
		`{"event_id":`,
	}, "\n")
	var output bytes.Buffer
	if err := run(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two output lines, got %d", len(lines))
	}
	for _, line := range lines {
		var result replayResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.Fatalf("invalid JSONL output: %v", err)
		}
	}
}
