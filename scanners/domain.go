package scanners

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"franklindata.com.au/scout/utils"
)

// Scan target TLDs for subdomains
func DomainScan(db string, filename string) {
	// TODO ensure db (and relevant constraints) exists first

	fmt.Printf("reading domains from %v\n", filename)

	// Read domains file and process each individually
	domainsFile, err := os.Open(filename)
	utils.Check(err)

	scanner := bufio.NewScanner(domainsFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		// Merge each top-level domain
		tldomain := scanner.Text()

		// Merge the TLDomain node
		_, err := utils.WriteQuery(
			db,
			[]string{
				"MERGE (d:TopLevelDomain:Domain{id:$domain})",
				"ON CREATE SET d.first_seen = datetime()", // first_checked && last_checked?
				"ON MATCH SET d.last_seen = datetime()",
				"RETURN d",
			},
			map[string]interface{}{
				"domain": tldomain,
			},
		)
		utils.Check(err)

		// Call httpxScan() for the TLD
		HttpxScan(db, tldomain, tldomain)

		fdCmd := exec.Command("findomain", "-t", tldomain, "-i", "--http-status", "-q", "-s", fmt.Sprintf("./programs/%v/screenshots", db))

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
			if row[0] == tldomain {
				fmt.Printf("- skipping TLD %v\n", row[0])
				continue
			}

			// Merge subdomain and establish IP / Domain context
			fmt.Printf("- found subdomain %v / %v\n", row[0], row[1])
			_, err = utils.WriteQuery(
				db,
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
					"ip":        row[1],
					"domain":    tldomain,
				},
			)
			utils.Check(err)

			// Run httpx scan for the subdomain
			HttpxScan(db, row[0], row[0])
		}
	}

	fmt.Println("findomain scan complete")
}
