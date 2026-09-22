// Package cmd implements ShadowStat's CLI subcommands.
package cmd

import (
	"fmt"
	"os"
)

// Execute dispatches to the requested subcommand based on os.Args.
func Execute() int {
	args := os.Args[1:]
	sub := "run"
	if len(args) > 0 && !isFlag(args[0]) {
		sub = args[0]
		args = args[1:]
	}

	switch sub {
	case "run":
		return runCmd(args)
	case "version":
		return versionCmd(args)
	default:
		fmt.Fprintf(os.Stderr, "shadowstat: unknown subcommand %q\n", sub)
		fmt.Fprintln(os.Stderr, "usage: shadowstat [run|version] [flags]")
		return 2
	}
}

func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}
