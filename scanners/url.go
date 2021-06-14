package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

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

func ScanUrlHandler(ctx context.Context, event events.SQSEvent) error {
	for _, message := range event.Records {
		fmt.Printf("ScanUrlHandler: %v\n", message.Body)
		var request ScanUrlRequest
		json.Unmarshal([]byte(message.Body), &request)

		// Call httpx on url
		httpxCmd := fmt.Sprintf("echo %s | httpx -H \"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0\" -silent -json", request.Url)
		fmt.Printf("-> %s\n", httpxCmd)
		httpxOut, err := exec.Command("/bin/sh", "-c", httpxCmd).Output()
		utils.Check(err)

		if len(httpxOut) == 0 {
			fmt.Println("no response from httpx")
			continue
		}

		var resp HttpxResponse
		// Hackish approach here of casting byte[] httpxOut to a string to achieve base64-decoding, before converting it back to byte[]
		json.Unmarshal([]byte(string(httpxOut)), &resp)

		_, err = utils.WriteQuery(
			request.Database,
			[]string{
				"MATCH (d:Domain{id:$domain})",
				"WITH d",
				"MERGE (u:Url{id:$url})",
				"SET u.scheme = $scheme, u.port = $port, u.path = $path, u.title = $title, u.webserver = $webserver, u.content_type = $content_type, u.method = $method, u.host = $host, u.status_code = $status_code",
				"MERGE (u)-[:BELONGS_TO]->(d)",
				"RETURN u",
			},
			map[string]interface{}{
				"domain":       request.Domain,
				"url":          resp.Url,
				"scheme":       resp.Scheme,
				"port":         resp.Port,
				"path":         resp.Path,
				"title":        resp.Title,
				"webserver":    resp.Webserver,
				"content_type": resp.ContentType,
				"method":       resp.Method,
				"host":         resp.Host,
				"status_code":  resp.StatusCode,
			},
		)
		utils.Check(err)

		// Request nuclei scan for valid urls
		if resp.Url != "" {
			fmt.Printf("Requesting nuclei scan of url %v\n", resp.Url)
			nucleiRequest := &ScanNucleiRequest{
				Database:  request.Database,
				Url:       resp.Url,
				Webserver: resp.Webserver,
			}
			nucleiRequestJson, err := json.Marshal(nucleiRequest)
			utils.Check(err)

			_, err = sqsQueue.SendMessage(&sqs.SendMessageInput{
				MessageBody: aws.String(string(nucleiRequestJson)),
				QueueUrl:    aws.String(os.Getenv("SCAN_NUCLEI_TEMPLATE_QUEUE")),
			})
			utils.Check(err)
		}
	}
	return nil
}
