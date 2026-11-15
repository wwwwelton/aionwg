package app

import (
	"net/netip"
	"testing"
)

// A WFP app other than the game tunnels only to servers the game has used.
func TestGameDstSplitsOtherWFPApps(t *testing.T) {
	e := &Engine{gameDst: map[netip.Addr]bool{}}
	game := netip.MustParseAddr("104.28.196.100")
	other := netip.MustParseAddr("172.67.218.111")

	if e.isGameDst(game) {
		t.Fatal("fresh engine must not treat any server as a game server")
	}
	e.markGameDst(game)
	if !e.isGameDst(game) {
		t.Fatal("game server not recorded: WFP app would lose the game route")
	}
	if e.isGameDst(other) {
		t.Fatal("non-game server tunnelled: WFP app traffic outside the game would leave the normal route")
	}
}
