//go:build windows

package app

import "testing"

func TestParseRelayEndpointsCanonicalizesAndDeduplicates(t *testing.T) {
	got, err := parseRelayEndpoints("127.0.0.1:2408, 127.0.0.1:2408")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "127.0.0.1:2408" {
		t.Fatalf("relays = %v", got)
	}
}
