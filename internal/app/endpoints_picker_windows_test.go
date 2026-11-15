//go:build windows

package app

import "testing"

func TestColoLabel(t *testing.T) {
	cases := map[string]string{
		"cwb02":   "cwb02 · Curitiba",
		" GRU20 ": "gru20 · São Paulo",
		"xyz1":    "xyz1",
		"":        "localização desconhecida",
	}
	for in, want := range cases {
		if got := coloLabel(in); got != want {
			t.Errorf("coloLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
