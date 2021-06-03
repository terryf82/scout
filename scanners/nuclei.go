package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"franklindata.com.au/scout/utils"
)

type NucleiResponse struct {
	TemplateId string `json:"templateID"`
	Info       struct {
		Severity string
		Tags     string
		Name     string
		Author   string
	}
	Type      string
	Host      string
	Matched   string
	Ip        string
	Timestamp string
}

func ScanNucleiHandler(payload string) error {
	fmt.Printf("NucleiScanHandler: %v\n", payload)
	return nil
}

func NucleiScan(db string, url string, webserver string) {

	// Lookup the supplied webserver to determine which tags to run
	response, err := utils.ReadList(
		"shared",
		[]string{
			"MATCH (w:Webserver)-[:SHOULD_BE_SCANNED_WITH]->(t:Tag)",
			"WHERE $webserver =~ w.regex",
			"RETURN t.id AS tag",
		},
		map[string]interface{}{
			"webserver": webserver,
		},
	)

	utils.Check(err)

	// Transform response into a single string
	nucleiTags := strings.Join(response.([]string), ",")

	if nucleiTags == "" {
		fmt.Printf("- no compatible tags for %v\n", webserver)
		return
	}

	nucleiCmd := fmt.Sprintf("echo %s | nuclei -silent -json -tags %s", url, nucleiTags)
	fmt.Printf("-> %s\n", nucleiCmd)
	nucleiOut, err := exec.Command("bash", "-c", nucleiCmd).Output()

	utils.Check(err)

	if len(nucleiOut) == 0 {
		// fmt.Println("no response from nuclei")
		return
	}

	fmt.Printf("%s\n", nucleiOut)
	var resp NucleiResponse
	// Hackish approach here of casting byte[] httpxOut to a string to achieve base64-decoding, before converting it back to byte[]
	json.Unmarshal([]byte(string(nucleiOut)), &resp)

	_, err = utils.WriteQuery(
		db,
		[]string{
			"MATCH (u:Url{id:$url})",
			"WITH u",
			"CREATE (v:VulnReport)<-[:IS_VULNERABLE_TO]-(u)",
			"SET v.template_id = $template_id, v.severity = $severity, v.type = $type, v.host = $host, v.matched = $matched, v.ip = $ip, v.discovered = datetime()",
			"RETURN v",
		},
		map[string]interface{}{
			"url":         url,
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
