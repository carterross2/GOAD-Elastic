# ELASTIC EDR extension

- Extension Name: elastic
- Description: Add Elastic EDR (Endpoint Detection and Response) server and Elastic EDR agents on Windows domain computers
- Machine name: {{lab_name}}-ELASTIC  
- Compatible with labs: *
- Provider: VirtualBox, VMware, AWS, Azure, Ludus

## Prerequisites

- Ensure you have sufficient system resources (8GB RAM will be allocated to the Elastic VM by default)
- Network connectivity configured for your chosen provider
- Ubuntu 22.04 template available (will be downloaded automatically)

## Install
```bash
./goad.sh -t install -l <your_lab> -p <provider> -e elastic
```

## Configuration

You can customize resource allocation by setting variables before installation:

```bash
# For smaller environments (6GB VM, 2 CPUs)
export ELASTIC_VM_MEMORY_GB=6
export ELASTIC_VM_CPUS=2

# For larger environments (12GB VM, 6 CPUs) 
export ELASTIC_VM_MEMORY_GB=12
export ELASTIC_VM_CPUS=6
```

**Default Resources:** 4 CPU cores, 8GB RAM (heap automatically set to 40% of total RAM)

## Access

### From Host Machine (Port Forwarding)
- Kibana EDR Console: http://localhost:5601
- Elasticsearch API: http://localhost:9200

### From Lab Network
- Kibana EDR Console: http://192.168.56.52:5601 (or your configured IP range)
- Elasticsearch API: http://192.168.56.52:9200

### Credentials
- Username: `elastic`
- Password: `elastic`

## Features

### Core EDR Components
- **Elasticsearch 8.11.0**: EDR data storage and search engine
- **Kibana 8.11.0**: EDR management console and investigation interface
- **Fleet Server**: Centralized agent management for EDR endpoints
- **Elastic EDR Agents**: Deployed on all Windows domain machines

### Endpoint Protection
- **Malware Protection**: Real-time malware detection and prevention
- **Ransomware Protection**: Behavioral analysis and ransomware blocking
- **Memory Protection**: Protection against memory-based attacks
- **Behavior Protection**: Detection of suspicious process behavior
- **Attack Surface Reduction**: Credential hardening and exploit prevention

### EDR Capabilities
- **Real-time Process Monitoring**: Track process creation and execution
- **File System Monitoring**: Monitor file changes and access
- **Network Connection Tracking**: Analyze network communications
- **Registry Monitoring**: Windows registry change detection
- **Threat Hunting**: Advanced search and investigation capabilities
- **Incident Response**: Case management and response workflows

### Pre-built EDR Dashboards
- **EDR Overview Dashboard**: High-level endpoint security status
- **Endpoint Security Dashboard**: Detailed endpoint protection metrics  
- **Malware Detection Dashboard**: Malware and threat analysis
- **Process Monitoring Dashboard**: Process behavior and execution tracking

### Detection and Response
- **Real-time Threat Detection**: Immediate alert on threats
- **Behavioral Analysis**: Machine learning-based anomaly detection
- **MITRE ATT&CK Mapping**: Techniques and tactics correlation
- **Automated Response**: Configurable response actions
- **Forensic Timeline**: Detailed attack progression analysis

## VM Specifications
- **Operating System**: Ubuntu 22.04 LTS
- **Default Resources**: 4 CPU cores, 8GB RAM (configurable)
- **Network**: Provider-specific networking with port forwarding
- **Storage**: Dynamic disk allocation

## Post-Installation

Installation takes approximately 8-12 minutes:

1. Access Kibana EDR Console at http://localhost:5601
2. Login with `elastic` / `elastic`
3. Navigate to **Fleet → Agents** to verify Windows agents enrollment
4. Navigate to **Security → Explore** for endpoint investigation
5. Navigate to **Security → Detections** to configure detection rules
6. Navigate to **Security → Cases** for incident management

## EDR Management

**Fleet Management:**
```bash
# Check agent status from Kibana
Fleet → Agents → View enrolled Windows machines
```

**Endpoint Investigation:**
```bash
# Access Security app for threat hunting
Security → Explore → Hosts → Select endpoint for detailed analysis
```

**Detection Rules:**
```bash
# Install and configure detection rules
Security → Detections → Manage detection rules → Add Elastic rules
```

## Basic Troubleshooting

**Kibana Not Accessible:**
```bash
# Check VM status and SSH in to check services
vagrant ssh {{lab_name}}-ELASTIC  # or provider equivalent
sudo systemctl status elasticsearch kibana
```

**EDR Agents Not Enrolled:**
```bash
# Check Windows agents (run as Administrator on Windows machines)
"C:\Program Files\Elastic\Agent\elastic-agent.exe" status

# Check Fleet Server status
sudo systemctl status elastic-agent
```

**No EDR Data in Dashboards:**
```bash
# Check Elasticsearch indices
curl -u elastic:elastic "http://localhost:9200/_cat/indices?v"

# Look for logs-endpoint.* indices
curl -u elastic:elastic "http://localhost:9200/logs-endpoint.*/_search?size=1"
```

**Performance Issues:**
- Consider adjusting VM resources based on endpoint count
- Monitor CPU and memory usage during active monitoring
- Check logs: `sudo journalctl -u elasticsearch -f`

## Data Retention
- **Hot tier**: 30 days (immediate search and analysis)
- **Warm tier**: 30-90 days (reduced resources)  
- **Cold tier**: 90-365 days (minimal resources)
- **Delete**: After 365 days (configurable for compliance)

## EDR Policy Configuration

The Windows EDR policy includes:
- **Malware Prevention**: Real-time scanning and blocking
- **Ransomware Protection**: Behavioral detection and prevention
- **Memory Protection**: Exploit prevention techniques  
- **Behavior Protection**: Suspicious activity detection
- **Credential Hardening**: Attack surface reduction
- **Antivirus Registration**: Integration with Windows Security Center

## Integration with GOAD Labs

This extension automatically integrates with all GOAD lab configurations and provides:
- **Endpoint Protection**: Real-time protection for all Windows domain machines
- **Threat Detection**: Advanced persistent threat (APT) detection
- **Attack Simulation Detection**: Monitors for common AD attack techniques
- **Forensic Analysis**: Detailed investigation capabilities for security incidents
- **Compliance Monitoring**: Security posture assessment and reporting

## Security Considerations

- EDR agents run with SYSTEM privileges for comprehensive monitoring
- All communication is encrypted between agents and Fleet Server
- Malware samples are automatically submitted to Elastic for analysis (configurable)
- Network traffic analysis may impact performance on busy networks
- Consider firewall rules for Fleet Server communication (port 8220)

## Advanced Configuration

For advanced EDR configuration:
1. Navigate to **Fleet → Agent policies → Windows EDR Policy**
2. Modify **Endpoint Security** integration settings
3. Adjust protection levels (Detect vs Prevent mode)
4. Configure advanced behavioral protection rules
5. Set up custom detection rules in **Security → Detections**
