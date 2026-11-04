package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("47c version dev")
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "47c:", err)
			os.Exit(1)
		}
	case "user":
		if err := runUser(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "47c:", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "47c:", err)
			os.Exit(1)
		}
	case "backup":
		if err := runBackup(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "47c:", err)
			os.Exit(1)
		}
	case "health":
		if err := runHealth(os.Args[2:]); err != nil {
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: 47c <command> [flags]

commands:
  serve    run the web UI, scheduler, and job runner
  scan     run a one-off scan against the current scope
  user     manage users
  backup   snapshot the database
  health   check database health
  version  print the version
`)
}
