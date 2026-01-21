package main

import (
	"fmt"
	"os"

	"github.com/Serdar715/xsshunt/internal/cli"
)

func main() {
	// XSSHunt Entry Point
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
