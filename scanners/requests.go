package scanners

import "github.com/aws/aws-sdk-go/service/sqs"

var sqsQueue *sqs.SQS

type ScanTargetRequest struct {
	Database string
	Domains  []string
}

type ScanDomainRequest struct {
	Database string
	Domain   string
}

type ScanUrlRequest struct {
	Database string
	Domain   string
	Url      string
}
