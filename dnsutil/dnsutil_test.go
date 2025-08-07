package dnsutil

import (
	"testing"
)

func TestTrimZone(t *testing.T) {
	tests := []struct {
		qname    string
		zone     string
		expected string
	}{
		{"a.example.org", "example.org", "a"},
		{"a.b.example.org", "example.org", "a.b"},
		{"b.", ".", "b"},
		{"example.org", "example.org", ""},
		{"org", "example.org", ""},
	}

	for i, tc := range tests {
		got := Trim(Fqdn(tc.qname), Fqdn(tc.zone))
		if got != tc.expected {
			t.Errorf("Test %d, expected %s, got %s", i, tc.expected, got)
			continue
		}
	}
}
