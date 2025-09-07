# Elastic Security Extension for GOAD

This extension deploys the Elastic Security stack (Elasticsearch, Kibana, Fleet Server) on a dedicated Ubuntu VM inside your GOAD lab and automatically enrolls all Windows machines with the Elastic Agent + Elastic Defend enabled.

## Requirements
- GOAD installed and working
- `docker.io` and `docker-compose-plugin` available on the ELASTIC VM (handled by Ansible)
- At least **12GB RAM** and **4 CPUs** for the ELASTIC VM
- Internet access for downloading Docker images and Elastic Agent MSI

## Usage

* Elasticsearch: [http://elastic01:9200](http://elastic01:9200)
* Kibana: [http://elastic01:5601](http://elastic01:5601) (login with `elastic / ElasticStack123!`)
* Fleet Server: [http://elastic01:8220](http://elastic01:8220)

All Windows hosts will automatically install and enroll the Elastic Agent with Elastic Defend enabled.

## Notes

* This deployment is **insecure** (no TLS) for simplicity inside the lab.
* Adjust resources (CPU/RAM) if the ELASTIC VM is unstable.
* Elastic Defend can be tested with simulated attacks in the GOAD environment.