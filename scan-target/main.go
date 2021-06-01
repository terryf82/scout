package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

type ScoutTarget struct {
	Database string
	Domains  []string
}

func PrintMessage(message events.SQSMessage) error {
	fmt.Printf("received %v\n", message)

	return nil
}

func TargetScan(ctx context.Context, sqsEvent events.SQSEvent) error {
	for _, message := range sqsEvent.Records {
		err := PrintMessage(message)
		if err != nil {
			return err
		}
	}

	return nil

	// fmt.Printf("-> running domain scan for target %v: %v\n", target.Database, target.Domains)
	// scanners.DomainScan(target.Database, target.Domains)
	// return nil
}

func main() {
	fmt.Println("scan-target::main")
	lambda.Start(TargetScan)
}

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

	// This function has no input besides a domains file, and only runs once per line.
	// Optimising it for lambda-execution is probably not worthwhile
	scanners.DomainScan(db, domains)

}*/
