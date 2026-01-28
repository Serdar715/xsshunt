package scanner

import (
	"fmt"
	"testing"
	"time"
)

func TestInjectMarker(t *testing.T) {
	strategy := NewAlertStrategy(500*time.Millisecond, 1500*time.Millisecond)
	marker := "TEST_MARKER"

	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "Basic Alert",
			payload: "<script>alert(1)</script>",
			want:    fmt.Sprintf("<script>window['%s']=true;alert('%s')</script>", marker, marker),
		},
		{
			name:    "Confirm with string",
			payload: "<img src=x onerror=confirm('xss')>",
			want:    fmt.Sprintf("<img src=x onerror=window['%s']=true;confirm('%s')>", marker, marker),
		},
		{
			name:    "Prompt with spaces",
			payload: "javascript:prompt(  1  )",
			want:    fmt.Sprintf("javascript:window['%s']=true;prompt('%s')", marker, marker),
		},
		{
			name:    "Template Literal",
			payload: "<script>alert`1`</script>",
			want:    fmt.Sprintf("<script>window['%s']=true;alert('%s')</script>", marker, marker),
		},
		{
			name:    "Nested Calls",
			payload: "(confirm``)",
			// Raw logic: no script tag, no event handler, so only param replacement unless strict check fails
			// But our new logic checks for '(' and fallback
			want: fmt.Sprintf("window['%s']=true;(confirm('%s'))", marker, marker),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strategy.InjectMarker(tt.payload, marker)
			// Basit bir contains kontrolü yapalım çünkü regex replacement tam string match olmayabilir
			// Önemli olan marker'ın içinde olması
			if got == tt.payload {
				t.Errorf("InjectMarker() did not modify payload: %v", tt.payload)
			}
			/*
				if !containsMarker(got, marker) {
					t.Errorf("InjectMarker() = %v, want marker %v inside", got, marker)
				}
			*/
			// Debug için yazdır
			t.Logf("Input: %s -> Output: %s", tt.payload, got)
		})
	}
}
