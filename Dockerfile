FROM golang:alpine

# Install curl
RUN apk update && apk add curl

# Install usually static dependencies first
RUN wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain
RUN chmod o+x /usr/local/bin/findomain

ENV GO111MODULE=on
RUN go get -v github.com/projectdiscovery/httpx/cmd/httpx
RUN go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@v2.3.8
RUN nuclei -version
RUN nuclei -update-templates

# /root folder isn't accessible within lambda context
RUN cp -R ~/nuclei-templates /nuclei-templates
RUN chmod -R 777 /nuclei-templates
COPY nuclei-custom.yaml /

WORKDIR /go/src/app
COPY . .

# Download all dependencies
RUN go get -d -v ./...

# Install binaries
RUN go install -v ./...

ENTRYPOINT [ "/go/bin/scout" ]
