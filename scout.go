package main

import (
	"flag"
	"os"

	"franklindata.com.au/scout/scanners"
)

func main() {

	dbPtr := flag.String("db", "", "name of database")
	domainsPtr := flag.String("domains", "", "full path of domains file")
	flag.Parse()

	if *dbPtr == "" || *domainsPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	db := *dbPtr
	domains := *domainsPtr

	// This function has no input besides a domains file, and only runs once per line.
	// Optimising it for lambda-execution is probably not worthwhile
	scanners.DomainScan(db, domains)

}
