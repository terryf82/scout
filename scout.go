package main

import (
	"flag"
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
