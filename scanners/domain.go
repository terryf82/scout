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
		// Read the event
		var domainRequest ScanDomainRequest
		json.Unmarshal([]byte(message.Body), &domainRequest)

		// Merge the TLDomain node
		_, err := utils.WriteQuery(
			domainRequest.Database,
			[]string{
				"MERGE (d:TopLevelDomain:Domain{id:$domain})",
				"ON CREATE SET d.first_seen = datetime()", // first_checked && last_checked?
				"ON MATCH SET d.last_seen = datetime()",
				"RETURN d",
			},
			map[string]interface{}{
				"domain": domainRequest.Domain,
			},
		)
		utils.Check(err)

		// Request url scan of domain
		urlRequest := &ScanUrlRequest{
			Database: domainRequest.Database,
			Domain:   domainRequest.Domain,
			Url:      domainRequest.Domain,
		}
		urlRequestJson, err := json.Marshal(urlRequest)
		utils.Check(err)

		_, err = sqsQueue.SendMessage(&sqs.SendMessageInput{
			MessageBody: aws.String(string(urlRequestJson)),
			QueueUrl:    aws.String(os.Getenv("SCAN_URL_QUEUE")),
		})
		utils.Check(err)

		// Find any subdomains
		// TODO enable screenshot capture & s3 upload
		// fdCmd := exec.Command("findomain", "-t", domainRequest.Domain, "-i", "--http-status", "-q", "-s", fmt.Sprintf("./programs/%v/screenshots", db))
		fdCmd := exec.Command("findomain", "-t", domainRequest.Domain, "-i", "--http-status", "-q")
		fdCmdOut, err := fdCmd.StdoutPipe()
		utils.Check(err)

		fmt.Printf("-> %v\n", fdCmd)
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
			if row[0] == domainRequest.Domain {
				fmt.Printf("- skipping TLD %v\n", row[0])
				continue
			}

			// Merge subdomain and link to Domain
			fmt.Printf("- found subdomain %v / %v\n", row[0], row[1])
			_, err = utils.WriteQuery(
				domainRequest.Database,
				[]string{
					"MERGE (s:Subdomain:Domain{id:$subdomain})",
					"ON CREATE SET s.first_seen = datetime()",
					"ON MATCH SET s.last_seen = datetime()",
					// Ip data seems unreliable, disabling for now
					// "WITH s",
					// "MERGE (i:Ip{id:$ip})",
					// "ON CREATE SET i.first_seen = datetime()",
					// "ON MATCH SET i.last_seen = datetime()",
					// "WITH s, i",
					// "MERGE (s)-[:IS_HOSTED_AT]->(i)",
					"WITH s",
					"MATCH (d:Domain{id:$domain})",
					"WITH s, d",
					"MERGE (s)-[:IS_PART_OF]->(d)",
					"RETURN s",
				},
				map[string]interface{}{
					"subdomain": row[0],
					// "ip":        row[1],
					"domain": domainRequest.Domain,
				},
			)
			utils.Check(err)

			// Request url scan of subdomain
			urlRequest := &ScanUrlRequest{
				Database: domainRequest.Database,
				Domain:   domainRequest.Domain,
				Url:      row[0],
			}
			urlRequestJson, err := json.Marshal(urlRequest)
			utils.Check(err)

			_, err = sqsQueue.SendMessage(&sqs.SendMessageInput{
				MessageBody: aws.String(string(urlRequestJson)),
				QueueUrl:    aws.String(os.Getenv("SCAN_URL_QUEUE")),
			})
			utils.Check(err)
		}
	}

	fmt.Println("findomain scan complete")
	return nil
}
