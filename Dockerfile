FROM golang:alpine

# Install required packages
RUN apk update && apk add curl build-base gcc abuild binutils binutils-doc gcc-doc libpcap-dev

# Install usually static dependencies first
RUN wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain
RUN chmod o+x /usr/local/bin/findomain

ENV GO111MODULE=on
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@v2.4.3

RUN nuclei -version
RUN nuclei -update-templates

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# /root folder isn't accessible within lambda context, move templates and config dir to /
RUN cp -R ~/nuclei-templates /nuclei-templates
RUN chmod -R 777 /nuclei-templates

RUN cp -R ~/.config /
ENV HOME=/

# Copy in custom templates
COPY ./custom-templates/ /nuclei-templates/

WORKDIR /go/src/app
COPY . .

# Download all dependencies
RUN go get -d -v ./...

# Install binaries
RUN go install -v ./...

ENTRYPOINT [ "/go/bin/scout" ]
