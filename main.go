// Command shadowstat is a self-contained Linux network monitoring tool that
// captures WAN traffic off a mirrored switch port and serves per-host bandwidth
// statistics and interactive graphs over HTTPS.
package main

import (
	"os"

	"ShadowStat/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
