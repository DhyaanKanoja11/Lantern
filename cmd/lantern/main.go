package main

import (
	"os"

	"github.com/DhyaanKanoja11/Lantern/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
