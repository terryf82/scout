package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"franklindata.com.au/scout/utils"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
)

func init() {
	sess := session.Must(session.NewSession())
	sqsQueue = sqs.New(sess)
}

func ScanTargetHandler(ctx context.Context, event events.SQSEvent) error {
	for _, message := range event.Records {
		fmt.Printf("ScanTargetHandler: %v\n", message.Body)
		var request ScanTargetRequest
		json.Unmarshal([]byte(message.Body), &request)

		for _, domain := range request.Domains {
			// Request scan of domain via SQS
			var output = ScanDomainRequest{
				Target: request.Target,
				Domain: domain,
			}
			outputJson, err := json.Marshal(output)
			if err != nil {
				return err
			}

			_, err = sqsQueue.SendMessage(&sqs.SendMessageInput{
				MessageBody: aws.String(string(outputJson)),
				QueueUrl:    aws.String(os.Getenv("SCAN_DOMAIN_QUEUE")),
			})

			utils.Check(err)
		}
	}
	return nil
}
