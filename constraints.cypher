CREATE CONSTRAINT domain_id IF NOT EXISTS ON (d:Domain) ASSERT (d.id) IS UNIQUE
CREATE CONSTRAINT url_id IF NOT EXISTS ON (u:Url) ASSERT (u.id) IS UNIQUE
CREATE CONSTRAINT vulnreport_host_template_id IF NOT EXISTS ON (v:VulnReport) ASSERT (v.host, v.template_id) IS NODE KEY
