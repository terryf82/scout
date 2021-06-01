package main

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"franklindata.com.au/scout/utils"
	"github.com/aws/aws-lambda-go/lambda"
)

type httpxResponse struct {
	Scheme      string
	Port        string // Should be int?
	Path        string
	Url         string
	Title       string
	Webserver   string
	ContentType string `json:"content-type"`
	Method      string
	Host        string
	StatusCode  int16 `json:"status-code"`
}

func main() {
	fmt.Println("scan-httpx::main")
	lambda.Start(HttpxScan)
}

// Call httpx on the specified domain
func HttpxScan(db string, domain string, url string) {

	httpxCmd := fmt.Sprintf("echo %s | httpx -H \"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0\" -silent -json", url)

	fmt.Printf("-> %s\n", httpxCmd)

	httpxOut, err := exec.Command("bash", "-c", httpxCmd).Output()

	utils.Check(err)

	if len(httpxOut) == 0 {
		fmt.Println("no response from httpx")
		return
	}

	var resp httpxResponse
	// Hackish approach here of casting byte[] httpxOut to a string to achieve base64-decoding, before converting it back to byte[]
	json.Unmarshal([]byte(string(httpxOut)), &resp)

	_, err = utils.WriteQuery(
		db,
		[]string{
			"MATCH (d:Domain{id:$domain})",
			"WITH d",
			"MERGE (u:Url{id:$url})",
			"SET u.scheme = $scheme, u.port = $port, u.path = $path, u.title = $title, u.webserver = $webserver, u.content_type = $content_type, u.method = $method, u.host = $host, u.status_code = $status_code",
			"MERGE (u)-[:BELONGS_TO]->(d)",
			"RETURN u",
		},
		map[string]interface{}{
			"domain":       domain,
			"url":          resp.Url,
			"scheme":       resp.Scheme,
			"port":         resp.Port,
			"path":         resp.Path,
			"title":        resp.Title,
			"webserver":    resp.Webserver,
			"content_type": resp.ContentType,
			"method":       resp.Method,
			"host":         resp.Host,
			"status_code":  resp.StatusCode,
		},
	)
	utils.Check(err)

	// Run nuclei for the valid urls
	if resp.Url != "" {
		// NucleiScan(db, resp.Url, resp.Webserver)
		// Send SQS
	}
}
