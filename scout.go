package main

import (
	"bufio"
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

		// subdomainsPath := fmt.Sprintf("./programs/%v/subdomains", *dbPtr)
		// subdomainsFile := fmt.Sprintf("%v/%v.csv", subdomainsPath, newDomain)
		// os.MkdirAll(subdomainsPath, 0755)

		// outfile, err := os.Create(subdomainsFile)
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// defer outfile.Close()
		// cmd.Stdout = outfile

		// .Run() is blocking, no need to use .Wait()
		fmt.Printf("-> %v\n", fdCmd)
		fdCmd.Start()
		// err = cmd.Run()
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// Read the subdomains CSV back in for processing
		// A pipe could simplify this, and speed up the process
		// f, err := os.Open(subdomainsFile)
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// r := csv.NewReader(f)
		fdCmdBuf := bufio.NewReader(fdCmdOut)
		for {
			// row, err := r.Read()
			line, _, err := fdCmdBuf.ReadLine()
			if err == io.EOF {
				break
			}

			// Transform the line into a csv row
			row := strings.Split(string(line), ",")

			// Not a real subdomain, record data against domain node
			if row[0] == newDomain {
				fmt.Printf("- skipping duplicate %v\n", row[0])
				_, err = session.WriteTransaction(func(transaction neo4j.Transaction) (interface{}, error) {
					result, err := transaction.Run(
						strings.Join([]string{
							"MATCH (d:Domain{id:$subdomain})",
							"SET d.url = $url",
							"MERGE (i:Ip{id:$ip})",
							"WITH d, i",
							"MERGE (d)-[:IS_HOSTED_AT]->(i)",
							"RETURN d",
						}, " "),
						map[string]interface{}{
							"subdomain": row[0],
							"ip":        row[1],
							"url":       row[2],
							"domain":    newDomain,
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

			// Hack to skip "Chromium/Chrome is correctly installed, performing enumeration!" output line
			if row[0] == "Chromium/Chrome is correctly installed" {
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
						"SET s.url = $url",
						"WITH s",
						"MATCH (d:Domain{id:$domain})",
						"MERGE (s)-[:IS_PART_OF]->(d)",
						"RETURN s",
					}, " "),
					map[string]interface{}{
						"subdomain": row[0],
						"url":       row[2],
						"domain":    newDomain,
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
