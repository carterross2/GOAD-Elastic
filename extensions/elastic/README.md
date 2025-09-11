# ELASTIC STACK extension

- Extension Name: elastic
- Description: Add Elastic Stack (Elasticsearch, Kibana, Logstash) EDR server and Elastic Agents on Windows domain computers only
- Machine name: {{lab_name}}-ELASTIC  
- Compatible with labs: *
- Provider: VirtualBox, VMware, AWS, Azure, Ludus

## Prerequisites

- Ensure you have sufficient system resources (12GB RAM will be allocated to the Elastic VM by default)
- Network connectivity configured for your chosen provider
- Ubuntu 22.04 template available (will be downloaded automatically)

## Install
```bash
./goad.sh -t install -l <your_lab> -p <provider> -e elastic
```

## Configuration

You can customize resource allocation by setting variables before installation:

```bash
# For smaller environments (8GB VM, 2.4GB heap)
export ELASTIC_VM_MEMORY_GB=8
export ELASTIC_VM_CPUS=2

# For larger environments (16GB VM, 4.8GB heap) 
export ELASTIC_VM_MEMORY_GB=16
export ELASTIC_VM_CPUS=4
```

**Default Resources:** 4 CPU cores, 12GB RAM (heap automatically set to 30% of total RAM)

## Access

### From Host Machine (Port Forwarding)
- Kibana Web UI: http://localhost:5601
- Elasticsearch API: http://localhost:9200

### From Lab Network
- Kibana Web UI: http://192.168.56.52:5601 (or your configured IP range)
- Elasticsearch API: http://192.168.56.52:9200

### Credentials
- Username: `elastic`
- Password: `elastic`

## Features

### Core Components
- **Elasticsearch 8.11.0**: Log storage, search engine, and analytics
- **Kibana 8.11.0**: Web-based visualization and dashboard interface
- **Logstash 8.11.0**: Log processing pipeline with Windows-specific parsing
- **Elastic Agents**: Deployed on all Windows domain machines only

### Security Monitoring
- Windows Event Log collection (Security, System, Application, Setup)
- Endpoint security with malware and ransomware protection
- Real-time process, file, network, and registry monitoring
- System metrics collection (CPU, memory, network, filesystem)

### Pre-built Dashboards
- **Windows Security Events Dashboard**: Comprehensive security event analysis
- **Active Directory Authentication Dashboard**: Logon patterns and Kerberos monitoring
- **Endpoint Security Overview Dashboard**: Malware detection and system changes
- **Network Security Dashboard**: Network connections and DNS analysis
- **Attack Timeline Dashboard**: Chronological security event correlation

### Attack Detection
- Automatic categorization of security events by severity
- High-severity events routed to dedicated security-alerts index
- GeoIP analysis for source IP addresses
- Built-in detection for common AD attack patterns:
  - Kerberoasting (RC4 encryption patterns)
  - DCSync (directory service access anomalies)
  - Authentication anomalies and privilege escalation

## VM Specifications
- **Operating System**: Ubuntu 22.04 LTS
- **Default Resources**: 4 CPU cores, 12GB RAM (configurable)
- **Network**: Provider-specific networking with port forwarding
- **Storage**: Dynamic disk allocation

## Post-Installation

Installation takes approximately 10-15 minutes:

1. Access Kibana at http://localhost:5601
2. Login with `elastic` / `elastic`
3. Navigate to **Analytics → Dashboard** to view pre-built dashboards
4. Navigate to **Analytics → Discover** to explore raw log data
5. Check **Management → Stack Management → Index Management** to verify data ingestion

## Basic Troubleshooting

**Kibana Not Accessible:**
```bash
# Check VM status and SSH in to check services
vagrant ssh {{lab_name}}-ELASTIC  # or provider equivalent
sudo systemctl status elasticsearch kibana
```

**No Data in Dashboards:**
```bash
# Check Windows agents (run as Administrator on Windows machines)
"C:\Program Files\Elastic\Agent\elastic-agent.exe" status

# Check Elasticsearch indices
curl -u elastic:elastic "http://localhost:9200/_cat/indices?v"
```

**Performance Issues:**
- Consider reducing VM resources if host system is constrained
- Monitor system resources during operation
- Check logs: `sudo journalctl -u elasticsearch -f`

## Log Retention
- **Hot tier**: 7 days (immediate search and analysis)
- **Warm tier**: 7-30 days (reduced replicas, slower search)  
- **Cold tier**: 30-90 days (minimal resources)
- **Delete**: After 90 days (configurable)

## Integration with GOAD Labs
This extension automatically integrates with all GOAD lab configurations and provides real-time security monitoring for:
- Domain controller activities
- Member server events
- Workstation security events
- Cross-domain trust relationships
- Service account activities