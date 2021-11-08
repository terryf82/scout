package scanners

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	"franklindata.com.au/scout/utils"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
)

func init() {
	sess := session.Must(session.NewSession())
	sqsQueue = sqs.New(sess)
}

func ScanPortHandler(event events.SQSEvent) error {
	for _, message := range event.Records {
		fmt.Printf("ScanPortHandler: %v\n", message.Body)
		var request ScanPortRequest
		json.Unmarshal([]byte(message.Body), &request)

		// Call naabu port scanner against Ip
		naabuCmd := exec.Command("naabu", "-host", request.Ip, "-silent", "-json")
		fmt.Printf("-> %v\n", naabuCmd)
		naabuCmdOut, err := naabuCmd.StdoutPipe()
		utils.Check(err)

		naabuCmd.Start()
		naabuCmdBuf := bufio.NewReader(naabuCmdOut)

		var foundPorts []int16
		for {
			line, _, err := naabuCmdBuf.ReadLine()
			if err == io.EOF {
				break
			}

			var resp NaabuResponse
			// Cast byte[] line to a string to achieve base64-decoding, before converting it back to byte[]
			json.Unmarshal([]byte(string(line)), &resp)

			foundPorts = append(foundPorts, resp.Port)
		}

		fmt.Printf("found open ports %v on %v\n", foundPorts, request.Url)
		if len(foundPorts) != 0 {
			_, err = utils.WriteQuery(
				"neo4j",
				[]string{
					"MATCH (u:Url{id:$url, host:$ip})",
					"SET u.open_ports = apoc.convert.toJson($ports)",
				},
				map[string]interface{}{
					"url":   request.Url,
					"ip":    request.Ip,
					"ports": foundPorts,
				},
			)
			utils.Check(err)
		}

	}
	return nil
}
