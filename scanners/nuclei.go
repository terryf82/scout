package scanners

import (
	"fmt"

	"franklindata.com.au/scout/utils"
)

// Run nuclei against the specified domain using the best tags for the webserver
func NucleiScan(db string, domain string, webserver string) {

	fmt.Printf("webserver lookup for %v:\n", webserver)

	nucleiTags, err := utils.ReadList(
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

	for _, nt := range nucleiTags.([]string) {
		fmt.Printf("run nuclei tag %v\n", nt)
	}
}
