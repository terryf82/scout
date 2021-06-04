package scanners

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

type HttpxResponse struct {
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
