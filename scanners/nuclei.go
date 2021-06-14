package scanners

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"franklindata.com.au/scout/utils"
	"github.com/aws/aws-lambda-go/events"
)

func ScanNucleiHandler(ctx context.Context, event events.SQSEvent) error {
	for _, message := range event.Records {
		fmt.Printf("ScanNucleiHandler: %v\n", message.Body)
		var request ScanNucleiRequest
		json.Unmarshal([]byte(message.Body), &request)

		// Lookup the supplied webserver to determine which template tags to run
		response, err := utils.ReadList(
			"neo4j",
			[]string{
				"MATCH (w:Webserver)-[:SHOULD_BE_SCANNED_WITH]->(t:Tag)",
				"WHERE $webserver =~ w.regex",
				"RETURN t.id AS tag",
			},
			map[string]interface{}{
				"webserver": request.Webserver,
			},
		)
		utils.Check(err)

		// Transform response into a single string
		nucleiTags := strings.Join(response.([]string), ",")

		if nucleiTags == "" {
			fmt.Printf("- no compatible tags for %v\n", request.Webserver)
			return nil
		}

		nucleiCmd := exec.Command("nuclei", "-u", request.Url, "-silent", "-json", "-tags", nucleiTags, "-ud", "/nuclei-templates", "-config", "/nuclei-custom.yaml")
		// nucleiCmd := exec.Command("nuclei", "-u", request.Url, "-silent", "-json", "-tags", nucleiTags, "-ud", "/nuclei-moved", "-config", "/nuclei-custom.yaml", "-etags", "xss")
		fmt.Printf("-> %v\n", nucleiCmd)

		var nucleiOut, nucleiErr bytes.Buffer
		nucleiCmd.Stdout = &nucleiOut
		nucleiCmd.Stderr = &nucleiErr
		// nucleiOut, err := nucleiCmd.StdoutPipe()
		// utils.Check(err)

		err = nucleiCmd.Run()
		// Additional error checking here, to avoid silent failures
		if nucleiErr.Bytes() != nil {
			fmt.Printf("StdErr output: %v\n", nucleiErr.String())
		}
		utils.Check(err)

		nucleiBuf := bufio.NewReader(bytes.NewReader(nucleiOut.Bytes()))
		for {
			line, _, err := nucleiBuf.ReadLine()
			if err == io.EOF {
				break
			}

			fmt.Printf("%s\n", line)
			var resp NucleiResponse
			// Hackish approach here of casting byte[] httpxOut to a string to achieve base64-decoding, before converting it back to byte[]
			json.Unmarshal([]byte(line), &resp)

			_, err = utils.WriteQuery(
				request.Database,
				[]string{
					"MATCH (u:Url{id:$url})",
					"WITH u",
					"CREATE (u)-[:IS_VULNERABLE_TO]->(v:VulnReport)",
					"SET v.template_id = $template_id, v.severity = $severity, v.type = $type, v.host = $host, v.matched = $matched, v.ip = $ip, v.discovered = datetime()",
					"RETURN v",
				},
				map[string]interface{}{
					"url":         request.Url,
					"template_id": resp.TemplateId,
					"severity":    resp.Info.Severity,
					"type":        resp.Type,
					"host":        resp.Host,
					"matched":     resp.Matched,
					"ip":          resp.Ip,
				},
			)
			utils.Check(err)
		}
	}
	fmt.Printf("nuclei scan complete\n")
	return nil
}
