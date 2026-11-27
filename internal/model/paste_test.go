package model

import "testing"

func TestParseBool(t *testing.T) {
	tests := []struct {
		in   any
		want bool
	}{
		{true, true}, {false, false},
		{"true", true}, {"1", true}, {"2", true},
		{"false", false}, {"0", false}, {"", false}, {"yes", false},
		{float64(1), true}, {float64(0), false},
		{nil, false}, {[]int{1}, false},
	}
	for _, tc := range tests {
		if got := ParseBool(tc.in); got != tc.want {
			t.Errorf("ParseBool(%#v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
