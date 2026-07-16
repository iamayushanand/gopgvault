package main

import (
	"fmt"
	"os"

	command "github.com/iamayushanand/gopass/cmd"
)

func main() {
	root := command.NewRootCommand(os.Args[1:])
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
