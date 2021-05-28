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
		fmt.Println("no compatible tags found")
		return
	}

	nucleiCmd := fmt.Sprintf("echo %s | nuclei -silent -json -tags %s", url, nucleiTags)
	fmt.Printf("-> %s\n", nucleiCmd)
	nucleiOut, err := exec.Command("bash", "-c", nucleiCmd).Output()

	utils.Check(err)

	if len(nucleiOut) == 0 {
		fmt.Println("no response from nuclei")
		return
	}

	fmt.Printf("%s\n", nucleiOut)
	var resp NucleiResponse
	// Hackish approach here of casting byte[] httpxOut to a string to achieve base64-decoding, before converting it back to byte[]
	json.Unmarshal([]byte(string(nucleiOut)), &resp)

	// fmt.Printf("as a single value: %v\n", strings.Join(nucleiTags, ","))
	// for _, nt := range response.([]string) {
	// 	fmt.Printf("run nuclei tag %v\n", nt)
	// }
}
