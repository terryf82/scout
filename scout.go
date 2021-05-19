package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/joho/godotenv"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

func goDotEnvVar(key string) string {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatal(err)
	}

	return os.Getenv(key)
}

func main() {
	dbPtr := flag.String("db", "", "name of database")
	domainsPtr := flag.String("domains", "", "full path of domains file")
	flag.Parse()

	if *dbPtr == "" || *domainsPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Printf("reading domains from %v\n", *domainsPtr)

	// Setup the neo4j connection
	driver, err := neo4j.NewDriver("neo4j://localhost", neo4j.BasicAuth(goDotEnvVar("NEO4J_USER"), goDotEnvVar("NEO4J_PASSWORD"), ""))
	if err != nil {
		log.Fatal(err)
	}

	defer driver.Close()

	session := driver.NewSession(neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeWrite,
		DatabaseName: *dbPtr,
	})
	defer session.Close()

	// Read domains file and process each individually
	domainsFile, err := os.Open(*domainsPtr)
	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(domainsFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		// Iterate over each domain, merge a node & call findomains
		newDomain := scanner.Text()

		// Merge the Domain node
		// TODO needs a function
		_, err = session.WriteTransaction(func(transaction neo4j.Transaction) (interface{}, error) {
			result, err := transaction.Run(
				strings.Join([]string{
					"MERGE (d:Domain{id:$domain})",
					"ON CREATE SET d.first_seen = datetime()", // first_checked && last_checked?
					"ON MATCH SET d.last_seen = datetime()",
					"RETURN d",
				}, " "),
				map[string]interface{}{
					"domain": newDomain,
				})

			if err != nil {
				return nil, err
			}

			if result.Next() {
				return result.Record().Values[0], nil
			}

			return nil, result.Err()
		})
		if err != nil {
			log.Fatal(err)
		}

		fdCmd := exec.Command("findomain", "-t", newDomain, "-i", "--http-status", "-q", "-s", fmt.Sprintf("./programs/%v/screenshots", *dbPtr))

		fdCmdOut, err := fdCmd.StdoutPipe()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("-> %v\n", fdCmd)
		fdCmd.Start()

		fdCmdBuf := bufio.NewReader(fdCmdOut)
		for {
			line, _, err := fdCmdBuf.ReadLine()
			if err == io.EOF {
				break
			}

			// fmt.Printf("findomain produced (raw): %v\n", line)
			// fmt.Printf("findomain produced (string): %v\n", string(line))

			// Transform the line into a csv row
			row := strings.Split(string(line), ",")

			// Skip "Chromium/Chrome is correctly installed, performing enumeration!" output line
			if row[0] == "Chromium/Chrome is correctly installed" {
				continue
			}

			// Call httpx on the subdomain
			httpxCmd := fmt.Sprintf("echo %s | httpx -H \"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0\" -silent -json", row[0])
			httpxOut, err := exec.Command("bash", "-c", httpxCmd).Output()
			if err != nil {
				log.Fatal(err)
			}

			// fmt.Printf("raw: %s\n", string(httpxOut))

			type httpxResponse struct {
				Scheme string
				Port   string // Should be int?
				Path   string
				// Url         string
				Title       string
				Webserver   string
				ContentType string `json:"content-type"`
				Method      string
				Host        string
				StatusCode  int16 `json:"status-code"`
			}

			var resp httpxResponse
			// Hackish approach here of casting byte[] httpxOut to a string to achieve base64-decoding, before converting it back to byte[]
			json.Unmarshal([]byte(string(httpxOut)), &resp)

			// Not a real subdomain, record data against domain node
			if row[0] == newDomain {
				fmt.Printf("- skipping duplicate %v\n", row[0])
				_, err = session.WriteTransaction(func(transaction neo4j.Transaction) (interface{}, error) {
					result, err := transaction.Run(
						strings.Join([]string{
							"MATCH (d:Domain{id:$domain})",
							"SET d.last_seen = datetime(), d.url = $url, d.scheme = $scheme, d.port = $port, d.path = $path, d.title = $title, d.webserver = $webserver, d.content_type = $content_type, d.method = $method, d.host = $host, d.status_code = $status_code",
							"MERGE (i:Ip{id:$ip})",
							"WITH d, i",
							"MERGE (d)-[:IS_HOSTED_AT]->(i)",
							"RETURN d",
						}, " "),
						map[string]interface{}{
							"domain":       row[0],
							"url":          row[2],
							"scheme":       resp.Scheme,
							"port":         resp.Port,
							"path":         resp.Path,
							"title":        resp.Title,
							"webserver":    resp.Webserver,
							"content_type": resp.ContentType,
							"method":       resp.Method,
							"host":         resp.Host,
							"status_code":  resp.StatusCode,
							"ip":           row[1],
						})

					if err != nil {
						return nil, err
					}

					if result.Next() {
						return result.Record().Values[0], nil
					}

					return nil, result.Err()
				})
				if err != nil {
					log.Fatal(err)
				}
				continue
			}

			fmt.Printf("- found subdomain %v / %v\n", row[0], row[1])
			/*
				row[0] = subdomain
				row[1] = ip
				row[2] = url
			*/

			// Merge subdomain
			_, err = session.WriteTransaction(func(transaction neo4j.Transaction) (interface{}, error) {
				result, err := transaction.Run(
					strings.Join([]string{
						"MERGE (s:Subdomain{id:$subdomain})",
						"ON CREATE SET s.first_seen = datetime()",
						"ON MATCH SET s.last_seen = datetime()",
						"WITH s",
						"SET s.url = $url, s.scheme = $scheme, s.port = $port, s.path = $path, s.title = $title, s.webserver = $webserver, s.content_type = $content_type, s.method = $method, s.host = $host, s.status_code = $status_code",
						"WITH s",
						"MATCH (d:Domain{id:$domain})",
						"MERGE (s)-[:IS_PART_OF]->(d)",
						"RETURN s",
					}, " "),
					map[string]interface{}{
						"subdomain":    row[0],
						"url":          row[2],
						"scheme":       resp.Scheme,
						"port":         resp.Port,
						"path":         resp.Path,
						"title":        resp.Title,
						"webserver":    resp.Webserver,
						"content_type": resp.ContentType,
						"method":       resp.Method,
						"host":         resp.Host,
						"status_code":  resp.StatusCode,
						"domain":       newDomain,
					})

				if err != nil {
					return nil, err
				}

				if result.Next() {
					return result.Record().Values[0], nil
				}

				return nil, result.Err()
			})
			if err != nil {
				log.Fatal(err)
			}

			// Merge IP
			_, err = session.WriteTransaction(func(transaction neo4j.Transaction) (interface{}, error) {
				result, err := transaction.Run(
					strings.Join([]string{
						"MERGE (i:Ip{id:$ip})",
						"ON CREATE SET i.first_seen = datetime()",
						"ON MATCH SET i.last_seen = datetime()",
						"WITH i",
						"MATCH (d:Domain{id:$domain}), (s:Subdomain{id:$subdomain})",
						"MERGE (s)-[:IS_HOSTED_AT]->(i)",
						"MERGE (d)<-[:BELONGS_TO]-(i)",
						"RETURN i",
					}, " "),
					map[string]interface{}{
						"ip":        row[1],
						"domain":    newDomain,
						"subdomain": row[0],
					})

				if err != nil {
					return nil, err
				}

				if result.Next() {
					return result.Record().Values[0], nil
				}

				return nil, result.Err()
			})
			if err != nil {
				log.Fatal(err)
			}

		}
	}
}
