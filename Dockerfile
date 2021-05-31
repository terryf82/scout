FROM golang:buster

WORKDIR /go/src/app
COPY . .

# Get dependencies
RUN go get -d -v ./...

RUN wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain
RUN chmod o+x /usr/local/bin/findomain

ENV GO111MODULE=on
RUN go get -v github.com/projectdiscovery/httpx/cmd/httpx
RUN go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
RUN nuclei -update-templates

