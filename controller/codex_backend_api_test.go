package controller

import (
	"testing"

	"github.com/QuantumNous/new-api/model"
)

func TestToCodexBackendRateLimitWindowRoundsFields(t *testing.T) {
	window := &model.SubscriptionRateLimitWindow{
		UsedAmount:         1,
		LimitAmount:        3,
		UsedPercent:        33.6,
		LimitWindowSeconds: 300,
		ResetAfterSeconds:  120,
		ResetAt:            1_740_000_000,
	}

	got := toCodexBackendRateLimitWindow(window)
	if got == nil {
		t.Fatal("expected window")
	}
	if got.UsedPercent != 34 {
		t.Fatalf("expected rounded used percent 34, got %d", got.UsedPercent)
	}
	if got.LimitWindowSeconds != 300 {
		t.Fatalf("expected limit window seconds 300, got %d", got.LimitWindowSeconds)
	}
	if got.ResetAfterSeconds != 120 {
		t.Fatalf("expected reset after seconds 120, got %d", got.ResetAfterSeconds)
	}
	if got.ResetAt != 1_740_000_000 {
		t.Fatalf("expected reset at 1740000000, got %d", got.ResetAt)
	}
}

func TestToCodexBackendRateLimitDetailsHandlesNilUsage(t *testing.T) {
	got := toCodexBackendRateLimitDetails(nil)
	if got.Allowed {
		t.Fatal("expected nil usage to be disallowed")
	}
	if !got.LimitReached {
		t.Fatal("expected nil usage to report limit reached")
	}
	if got.PrimaryWindow != nil {
		t.Fatal("expected nil primary window")
	}
	if got.SecondaryWindow != nil {
		t.Fatal("expected nil secondary window")
	}
}
