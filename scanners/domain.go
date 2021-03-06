package scanners

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

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

func ScanDomainHandler(ctx context.Context, event events.SQSEvent) error {
	for _, message := range event.Records {
		fmt.Printf("ScanDomainHandler: %v\n", message.Body)
		var request ScanDomainRequest
		json.Unmarshal([]byte(message.Body), &request)

		// Merge the RootDomain node
		_, err := utils.WriteQuery(
			"neo4j",
			[]string{
				"MERGE (d:Domain{id:$domain})",
				"ON CREATE SET d:RootDomain:" + request.Target + ", d.first_seen = datetime()",
				"ON MATCH SET d:RootDomain:" + request.Target + ", d.last_seen = datetime()",
				"RETURN d",
			},
			map[string]interface{}{
				"domain": request.Domain,
			},
		)
		utils.Check(err)
		fmt.Printf("TLDomain %v merged\n", request.Domain)

		// Request scan of url (domain) via SQS
		urlRequest := &ScanUrlRequest{
			Target: request.Target,
			Domain: request.Domain,
			Url:    request.Domain,
		}
		urlRequestJson, err := json.Marshal(urlRequest)
		utils.Check(err)

		_, err = sqsQueue.SendMessage(&sqs.SendMessageInput{
			MessageBody: aws.String(string(urlRequestJson)),
			QueueUrl:    aws.String(os.Getenv("SCAN_URL_QUEUE")),
		})
		utils.Check(err)
		fmt.Printf("Requesting scan of domain 'url' %v\n", request.Domain)

		// Find any subdomains
		// TODO enable screenshot capture & s3 upload
		fdCmd := exec.Command("findomain", "-t", request.Domain, "-i", "--http-status", "-q")
		fmt.Printf("-> %v\n", fdCmd)
		fdCmdOut, err := fdCmd.StdoutPipe()
		utils.Check(err)

		fdCmd.Start()
		fdCmdBuf := bufio.NewReader(fdCmdOut)
		for {
			line, _, err := fdCmdBuf.ReadLine()
			if err == io.EOF {
				break
			}

			// Transform the line into a csv row
			row := strings.Split(string(line), ",")
			/*
				row[0] = subdomain
				row[1] = ip
				row[2] = url
			*/

			// Skip "Chromium/Chrome is correctly installed, performing enumeration!" output line
			if row[0] == "Chromium/Chrome is correctly installed" {
				fmt.Println("- skipping chromium debug output")
				continue
			}

			// Skip the TLD itself
			if row[0] == request.Domain {
				fmt.Printf("- skipping TLD %v\n", row[0])
				continue
			}

			// Merge subdomain and link to Domain
			fmt.Printf("- found subdomain %v / %v\n", row[0], row[1])
			_, err = utils.WriteQuery(
				"neo4j",
				[]string{
					"MERGE (s:Domain{id:$subdomain})",
					"ON CREATE SET s:Subdomain:" + request.Target + ", s.first_seen = datetime()",
					"ON MATCH SET s:Subdomain:" + request.Target + ",s.last_seen = datetime()",
					"WITH s",
					"MATCH (d:Domain{id:$domain})",
					"WITH s, d",
					"MERGE (s)-[:IS_PART_OF]->(d)",
					"RETURN s",
				},
				map[string]interface{}{
					"subdomain": row[0],
					"domain":    request.Domain,
				},
			)
			utils.Check(err)

			// Request url scan of subdomain
			urlRequest := &ScanUrlRequest{
				Target: request.Target,
				Domain: row[0],
				Url:    row[0],
			}
			urlRequestJson, err := json.Marshal(urlRequest)
			utils.Check(err)

			_, err = sqsQueue.SendMessage(&sqs.SendMessageInput{
				MessageBody: aws.String(string(urlRequestJson)),
				QueueUrl:    aws.String(os.Getenv("SCAN_URL_QUEUE")),
			})
			utils.Check(err)
			fmt.Printf("Requesting scan of subdomain 'url' %v\n", row[0])
		}
	}

	fmt.Println("findomain scan complete")
	return nil
}
