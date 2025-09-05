# ELASTIC STACK extension

- Extension Name: elastic
- Description: Add Elastic Stack (Elasticsearch, Kibana, Logstash) EDR server and Elastic Agents on all domain computers
- Machine name: {{lab_name}}-ELASTIC  
- Compatible with labs: *

## Prerequisites

On ludus prepare template:
```
ludus templates add -d ubuntu-22.04-x64-server
ludus templates build
```

## Install
```
instance_id> install_extension elastic
```

## Access
- Kibana Web UI: https://{{ip_range}}.52:5601
- Default credentials: admin / elastic_admin_password

## Features
- Elasticsearch for log storage and search
- Kibana for visualization and dashboards
- Logstash for log processing
- Fleet Server for agent management
- Elastic Defend EDR on all endpoints
- Pre-configured security dashboards
- Active Directory attack detection rules