FROM golang:buster

# Install usually static dependencies first
RUN wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain
RUN chmod o+x /usr/local/bin/findomain

ENV GO111MODULE=on
RUN go get -v github.com/projectdiscovery/httpx/cmd/httpx
RUN go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
RUN nuclei -update-templates

WORKDIR /go/src/app
COPY . .

# Download all dependencies
RUN go get -d -v ./...

# Install binaries
RUN go install -v ./...

# Add Lambda Runtime Interface Emulator (RIE) and use a script in the ENTRYPOINT for simpler local runs
# ADD https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie /usr/bin/aws-lambda-rie
# RUN chmod 755 /usr/bin/aws-lambda-rie
# COPY entry.sh /
# RUN chmod 755 /entry.sh
ENTRYPOINT [ "/go/bin/scout" ]