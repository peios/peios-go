package security

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestConditionBooleanDepthBoundary(t *testing.T) {
	for _, operator := range []string{" && ", " || "} {
		t.Run(strings.TrimSpace(operator), func(t *testing.T) {
			const comparison = "@User.x == 1"
			for _, count := range []int{127, 128, 129, 256} {
				input := strings.Repeat(comparison+operator, count-1) + comparison
				encoded, err := ParseCondition(input)
				if count > 128 {
					if !errors.Is(err, syscall.EINVAL) {
						t.Fatalf("%d comparisons: expected EINVAL, got %v", count, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%d comparisons: %v", count, err)
				}
				formatted, err := FormatCondition(encoded)
				if err != nil || formatted != input {
					t.Fatalf("%d comparisons: round trip = %q, %v", count, formatted, err)
				}
			}
		})
	}
}

func TestConditionDepthIncludesUnaryAndMixedOperators(t *testing.T) {
	for _, prefix := range []string{"", "!", "@User.y == 2 && "} {
		input := prefix + "(" + strings.Repeat("@User.x == 1 || ", 127) + "@User.x == 1)"
		_, err := ParseCondition(input)
		if prefix == "" {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("prefix %q: expected EINVAL, got %v", prefix, err)
		}
	}
}
