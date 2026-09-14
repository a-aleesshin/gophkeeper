package main

import "github.com/a-aleesshin/gophkeeper/internal/client/cli"

var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	cli.Execute(version, buildDate)
}
