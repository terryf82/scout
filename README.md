# scout

Graph-based network reconnaissance, using [AWS Lambda](https://aws.amazon.com/lambda/), [Golang](https://golang.org/) and [Neo4j Aura](https://neo4j.com/cloud/aura/)

## What does it do?
Scout provides a fast, distributed way of exploring an organisation's network to determine their domain structure & hierarchy, and at the same time capture a snapshot of their webservices. It also allows for automated, targeted scanning of services using [nuclei](https://github.com/projectdiscovery/nuclei), by evaluating the service's reported webserver (e.g. Apache) against a tag-based ontology that returns a relevant set of [nuclei templates](https://github.com/projectdiscovery/nuclei-templates). Data is stored in Neo4j Aura, a managed graph-databse service that provides free tier usage.

## How does it work?
Scout is essentially a hierarchy of AWS Lambda functions, with each processing a specific type of request and delivering tasks to other purpose-specific functions as needed. This allows parallel rather than sequential execution, enabling large networks to be explored in a much shorter period of time.

The functions currently included are:
1. scan-target: receives a target name and list of root domains to scan
2. scan-domain: receives a domain to scan, returns a list of found subdomains via [Findomain](https://github.com/Findomain/Findomain)
3. scan-url: receives a subdomain url to scan, returns webserver details via [httpx](https://github.com/projectdiscovery/httpx)
4. scan-nuclei: receives a url and webserver, executes relevant nuclei templates

## Why is it useful?
Fully exploring an organisation's network (e.g. for a bug bounty program) often involves a lot of manual work, and the use of many different tools. For large networks this becomes problematic if those tools are running against a long list of targets (such as urls) sequentially, when they could run much faster if executed in parallel. Threading can help in this respect, but still leaves you vulnerable to IP blacklisting. Scout distributes work across AWS Lambda functions which execute from a large pool of AWS IPs, reducing the chance of your activities being thwarted by IP filtering.

Beyond scaling for better performance, the true value of scout lies in its graph-based approach to mapping out a network. Once a target has been fully scanned, you can interact with the data via Neo4j cypher queries to identify:
- domain hierarchies, which may indicate trust & cross-domain relationships
- multiple domains / sub-domains hosted on the same IP
- multiple sites running the same webserver
- nuclei templates most likely to be relevant to a specific organisation's network resources

This is really just the start of what can be learned through graph-based network discovery. New features will continue to be added over time, and suggestions are always welcome.

## What does it cost to run?
Scout is provided free as an open-source software project. In terms of running costs, it should be possible to keep these very low if you're looking to scan < 100 small-medium networks:
- AWS Lambda [free tier](https://aws.amazon.com/lambda/pricing/) provides 1M free requests per month and 400,000 GB-seconds of compute time per month
- Neo4j Aura [free tier](https://neo4j.com/cloud/aura/pricing/) provides a single database with up to 50k nodes and 175k relationships in a multi-tenant environment (you may need more than this if you were to scan a large organisation like Apple that has an entire A-Class range, but for anything smaller it should be sufficient)

## Installation
These instructions assume usage of an ECR repo. Using another provider such as DockerHub would require additional configuration.

#### 1. Build the image using the included `Dockerfile` and push it to your image repo:
```
docker build -t your.repo.here/scout:tag
docker push your.repo.here/scout:tag
```

#### 2. Set the following AWS environment variables in `.env`:
```
AWS_REGION=<region your lamba will be deployed in>
AWS_ECR_REPO=your.repo.here/scout:tag
```

#### 3. Provision a Neo4j Aura cluster
Visit [https://neo4j.com/cloud/aura/](https://neo4j.com/cloud/aura/) to register your instance (requires valid credit card but free-tier usage is available as mentioned above)

#### 4. Set the following NEO4J environment variables in `.env`:
```
NEO4J_SERVER_ADDRESS=<aura connection string>
NEO4J_USER=neo4j
NEO4J_PASSWORD=<aura password>
```

#### 5. Deploy the application to AWS Lambda:
```
serverless deploy
```