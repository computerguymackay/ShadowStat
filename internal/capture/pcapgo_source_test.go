package capture

import "testing"

// TestIsPromiscuousOnLoopback exercises the real /sys/class/net parsing path
// against an interface guaranteed to exist on any Linux box. loopback is
// never promiscuous, so this also implicitly checks the bit test is correct
// (not just "doesn't error").
func TestIsPromiscuousOnLoopback(t *testing.T) {
	promisc, err := isPromiscuous("lo")
	if err != nil {
		t.Fatal(err)
	}
	if promisc {
		t.Error("expected loopback to never be reported as promiscuous")
	}
}

func TestIsPromiscuousUnknownInterface(t *testing.T) {
	if _, err := isPromiscuous("no-such-interface-xyz"); err == nil {
		t.Error("expected an error for a nonexistent interface")
	}
}
