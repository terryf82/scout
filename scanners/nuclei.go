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

		// Lambda allows scanning from multiple IPs automatically, useful for avoiding IP blacklisting
		// ipOut, err := exec.Command("curl", "https://icanhazip.com").Output()
		// utils.Check(err)
		// fmt.Printf("initiaiting request from ip: %s\n", ipOut)

		nucleiCmd := exec.Command("nuclei", "-u", request.Url, "-silent", "-json", "-tags", nucleiTags, "-ud", "/nuclei-templates", "-config", "/nuclei-custom.yaml")
		fmt.Printf("-> %v\n", nucleiCmd)

		var nucleiOut, nucleiErr bytes.Buffer
		nucleiCmd.Stdout = &nucleiOut
		nucleiCmd.Stderr = &nucleiErr

		err = nucleiCmd.Run()
		// Additional error checking here, to avoid silent failures
		if nucleiErr.String() != "" {
			fmt.Printf("StdErr output: %v\n", nucleiErr.String())
		}
		utils.Check(err)

		if nucleiOut.String() == "" {
			fmt.Printf("no vulnerabilities found\n")
		}

		nucleiBuf := bufio.NewReader(bytes.NewReader(nucleiOut.Bytes()))
		for {
			line, _, err := nucleiBuf.ReadLine()
			if err == io.EOF {
				break
			}

			fmt.Printf("%s\n", line)
			var resp NucleiResponse
			json.Unmarshal([]byte(line), &resp)

			_, err = utils.WriteQuery(
				"neo4j",
				[]string{
					"MATCH (u:Url{id:$url})",
					"WITH u",
					"MERGE (v:VulnReport:" + request.Target + "{host:$host,template_id:$template_id})",
					"MERGE (u)-[:IS_VULNERABLE_TO]->(v:VulnReport)",
					"SET v.severity = $severity, v.type = $type, v.matched = $matched, v.ip = $ip, v.discovered = datetime()",
					"RETURN v",
				},
				map[string]interface{}{
					"url":         request.Url,
					"host":        resp.Host,
					"template_id": resp.TemplateId,
					"severity":    resp.Info.Severity,
					"type":        resp.Type,
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
