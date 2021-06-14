package scanners

import "github.com/aws/aws-sdk-go/service/sqs"

var sqsQueue *sqs.SQS

type ScanTargetRequest struct {
	Target  string
	Domains []string
}

type ScanDomainRequest struct {
	Target string
	Domain string
}

type ScanUrlRequest struct {
	Target string
	Domain string
	Url    string
}

type ScanNucleiRequest struct {
	Target    string
	Url       string
	Webserver string
}
