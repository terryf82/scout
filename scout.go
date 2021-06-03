package main

import (
	"flag"
	"fmt"
	"os"

	"franklindata.com.au/scout/scanners"
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	funPtr := flag.String("f", "", "name of function")
	flag.Parse()
	if *funPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Printf("cmd recevied: %v\n", *funPtr)

	switch *funPtr {
	case "scan-target":
		lambda.Start(scanners.ScanTargetHandler)
	case "scan-domain":
		lambda.Start(scanners.ScanDomainHandler)
	case "scan-url":
		lambda.Start(scanners.ScanUrlHandler)
	case "scan-nuclei":
		lambda.Start(scanners.ScanNucleiHandler)
	}
}

// Manual execution logic, fold this back in at some point for local development/testing
/*func main() {

	dbPtr := flag.String("db", "", "name of database")
	domainsPtr := flag.String("domains", "", "full path of domains file")
	flag.Parse()

	if *dbPtr == "" || *domainsPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	db := *dbPtr
	domains := *domainsPtr

	scanners.DomainScan(db, domains)

}*/
