package scanners

import (
	"context"
	"encoding/json"
	"fmt"
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
			"shared",
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
			continue
		}

		nucleiCmd := fmt.Sprintf("echo %s | nuclei -silent -json -tags %s", request.Url, nucleiTags)
		fmt.Printf("-> %s\n", nucleiCmd)
		nucleiOut, err := exec.Command("bash", "-c", nucleiCmd).Output()
		utils.Check(err)

		if len(nucleiOut) == 0 {
			fmt.Println("no response from nuclei")
			continue
		}

		fmt.Printf("%s\n", nucleiOut)
		var resp NucleiResponse
		// Hackish approach here of casting byte[] httpxOut to a string to achieve base64-decoding, before converting it back to byte[]
		json.Unmarshal([]byte(string(nucleiOut)), &resp)

		_, err = utils.WriteQuery(
			request.Database,
			[]string{
				"MATCH (u:Url{id:$url})",
				"WITH u",
				"CREATE (v:VulnReport)<-[:IS_VULNERABLE_TO]-(u)",
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
	return nil
}
