package cmd

import (
	"fmt"

	"ShadowStat/internal/version"
)

func versionCmd(args []string) int {
	fmt.Printf("shadowstat %s\n", version.Version)
	return 0
}
