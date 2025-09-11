#!/bin/bash

# GOAD Elastic Extension - Migration to EDR Focus
# This script backs up the current elastic extension and creates a streamlined EDR version

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the script directory and determine the correct paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Check if we're in the extensions directory (elastic folder should be here)
if [ -d "$SCRIPT_DIR/elastic" ]; then
    EXTENSIONS_DIR="$SCRIPT_DIR"
    ELASTIC_DIR="$SCRIPT_DIR/elastic"
# Check if we're one level up (elastic should be in extensions subdirectory)
elif [ -d "$SCRIPT_DIR/extensions/elastic" ]; then
    EXTENSIONS_DIR="$SCRIPT_DIR/extensions"
    ELASTIC_DIR="$SCRIPT_DIR/extensions/elastic"
else
    # Try to find elastic directory in common locations
    if [ -d "./elastic" ]; then
        EXTENSIONS_DIR="$(pwd)"
        ELASTIC_DIR="$(pwd)/elastic"
    elif [ -d "../elastic" ]; then
        EXTENSIONS_DIR="$(dirname "$(pwd)")"
        ELASTIC_DIR="$(dirname "$(pwd)")/elastic"
    else
        echo -e "${RED}Error: Could not find elastic extension directory${NC}"
        echo -e "${YELLOW}Please run this script from:${NC}"
        echo -e "${YELLOW}  - The extensions directory (where elastic folder is located)${NC}"
        echo -e "${YELLOW}  - The parent directory containing extensions/elastic${NC}"
        echo -e "${YELLOW}Current directory contents:${NC}"
        ls -la
        exit 1
    fi
fi

echo -e "${BLUE}===========================================${NC}"
echo -e "${BLUE}GOAD Elastic Extension - EDR Migration${NC}"
echo -e "${BLUE}===========================================${NC}"
echo ""

# Check if elastic directory exists
if [ ! -d "$ELASTIC_DIR" ]; then
    echo -e "${RED}Error: Elastic extension directory not found at $ELASTIC_DIR${NC}"
    exit 1
fi

echo -e "${YELLOW}Current elastic directory: $ELASTIC_DIR${NC}"

# Create backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${ELASTIC_DIR}_backup_${TIMESTAMP}"

echo -e "${BLUE}Creating backup...${NC}"
cp -r "$ELASTIC_DIR" "$BACKUP_DIR"
echo -e "${GREEN}✓ Backup created at: $BACKUP_DIR${NC}"

# Remove old directory
echo -e "${BLUE}Removing old elastic directory...${NC}"
rm -rf "$ELASTIC_DIR"
echo -e "${GREEN}✓ Old directory removed${NC}"

# Create new directory structure
echo -e "${BLUE}Creating new EDR-focused directory structure...${NC}"
mkdir -p "$ELASTIC_DIR"
mkdir -p "$ELASTIC_DIR/ansible/roles/elasticsearch/"{defaults,tasks,templates,handlers}
mkdir -p "$ELASTIC_DIR/ansible/roles/kibana/"{defaults,tasks,templates,handlers,files}
mkdir -p "$ELASTIC_DIR/ansible/roles/elastic_agent_windows/"{defaults,tasks}
mkdir -p "$ELASTIC_DIR/providers/"{aws,azure,ludus,virtualbox,vmware}

# Create extension.json
cat > "$ELASTIC_DIR/extension.json" << 'EOF'
{
    "name": "elastic",
    "description": "Add Elastic EDR (Endpoint Detection and Response) into the lab",
    "machines": [
        "elastic"
    ],
    "compatibility": [
        "*"
    ],
    "impact": "add an elastic EDR server and elastic EDR agents on all windows machines"
}
EOF

# Create inventory
cat > "$ELASTIC_DIR/inventory" << 'EOF'
[default]
elastic ansible_host={{ip_range}}.52 ansible_connection=ssh ansible_ssh_common_args='-o StrictHostKeyChecking=no'

[extensions]
elastic

; Recipe associations -------------------
[elastic_server]
elastic

[elastic_agents:children]
domain

[elastic_agents_windows:children]
domain

; Variables for all hosts
[all:vars]
ansible_python_interpreter=/usr/bin/python3
EOF

# Create main install playbook
cat > "$ELASTIC_DIR/ansible/install.yml" << 'EOF'
- name: Install and configure Elastic EDR Stack
  hosts: elastic_server
  become: yes
  roles:
    - { role: 'elasticsearch', tags: 'elasticsearch' }
    - { role: 'kibana', tags: 'kibana' }

- name: Install Elastic EDR Agent on Windows Domain Machines
  hosts: elastic_agents
  roles:
    - { role: 'elastic_agent_windows', tags: 'elastic_agent_windows' }
  vars:
    elastic_server_host: "{{ hostvars['elastic']['ansible_host'] }}"
EOF

# Create Elasticsearch role files
cat > "$ELASTIC_DIR/ansible/roles/elasticsearch/defaults/main.yml" << 'EOF'
# Resource configuration
elastic_vm_memory_gb: 8
elastic_vm_cpus: 4
elasticsearch_heap_size: "{{ (elastic_vm_memory_gb * 0.4) | int }}g"
elasticsearch_version: "8.11.0"
elasticsearch_port: 9200
elasticsearch_cluster_name: "goad-edr-cluster"
elasticsearch_node_name: "goad-edr-node-1"
elasticsearch_data_path: "/var/lib/elasticsearch"
elasticsearch_log_path: "/var/log/elasticsearch"
elastic_password: "elastic"
EOF

cat > "$ELASTIC_DIR/ansible/roles/elasticsearch/handlers/main.yml" << 'EOF'
- name: restart elasticsearch
  systemd:
    name: elasticsearch
    state: restarted
EOF

cat > "$ELASTIC_DIR/ansible/roles/elasticsearch/templates/elasticsearch.yml.j2" << 'EOF'
cluster.name: {{ elasticsearch_cluster_name }}
node.name: {{ elasticsearch_node_name }}
path.data: {{ elasticsearch_data_path }}
path.logs: {{ elasticsearch_log_path }}
network.host: 0.0.0.0
http.port: {{ elasticsearch_port }}
discovery.type: single-node

# Security configuration
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# Disable SSL for simplicity in lab environment
xpack.security.transport.ssl.enabled: false
xpack.security.http.ssl.enabled: false

# Authentication settings
xpack.security.authc:
  realms:
    native:
      native1:
        order: 0

# Enable machine learning and monitoring
xpack.ml.enabled: true
xpack.monitoring.collection.enabled: true

# EDR-specific settings
xpack.security.audit.enabled: true
xpack.security.audit.logfile.events.include:
  - access_denied
  - access_granted
  - authentication_failed
  - authentication_success
EOF

cat > "$ELASTIC_DIR/ansible/roles/elasticsearch/tasks/main.yml" << 'EOF'
- name: Display installation progress
  debug:
    msg: "Starting Elasticsearch installation for EDR..."
    
- name: Update apt cache
  apt:
    update_cache: yes

- name: Install Java 11
  apt:
    name: openjdk-11-jdk
    state: present

- name: Add Elastic repository key
  apt_key:
    url: https://artifacts.elastic.co/GPG-KEY-elasticsearch
    state: present

- name: Add Elastic repository
  apt_repository:
    repo: "deb https://artifacts.elastic.co/packages/8.x/apt stable main"
    state: present

- name: Install Elasticsearch
  apt:
    name: "elasticsearch={{ elasticsearch_version }}"
    state: present
  notify: restart elasticsearch

- name: Display progress - Elasticsearch installed
  debug:
    msg: "✓ Elasticsearch {{ elasticsearch_version }} installed successfully"

- name: Create elasticsearch configuration
  template:
    src: elasticsearch.yml.j2
    dest: /etc/elasticsearch/elasticsearch.yml
    owner: root
    group: elasticsearch
    mode: '0660'
  notify: restart elasticsearch

- name: Set JVM heap size
  lineinfile:
    path: /etc/elasticsearch/jvm.options
    regexp: "{{ item.regexp }}"
    line: "{{ item.line }}"
  loop:
    - { regexp: '^-Xms', line: "-Xms{{ elasticsearch_heap_size }}" }
    - { regexp: '^-Xmx', line: "-Xmx{{ elasticsearch_heap_size }}" }
  notify: restart elasticsearch

- name: Start and enable Elasticsearch
  systemd:
    name: elasticsearch
    state: started
    enabled: yes

- name: Display progress - Elasticsearch starting
  debug:
    msg: "Starting Elasticsearch service... (this may take 30-60 seconds)"

- name: Wait for Elasticsearch to start
  wait_for:
    port: "{{ elasticsearch_port }}"
    host: "localhost"
    delay: 30
    timeout: 300

- name: Wait for Elasticsearch to be responsive
  uri:
    url: "http://localhost:{{ elasticsearch_port }}"
    method: GET
    status_code: [200, 401]
  register: es_responsive
  until: es_responsive.status in [200, 401]
  retries: 10
  delay: 15

- name: Display progress - Elasticsearch responsive
  debug:
    msg: "✓ Elasticsearch is responding to requests"

- name: Reset elastic user password
  shell: |
    printf 'y\n{{ elastic_password }}\n{{ elastic_password }}\n' | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i
  register: elastic_password_reset
  until: elastic_password_reset.rc == 0
  retries: 5
  delay: 10
  changed_when: elastic_password_reset.rc == 0

- name: Set kibana_system user password  
  shell: |
    printf 'y\n{{ elastic_password }}\n{{ elastic_password }}\n' | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -i
  register: kibana_password_reset
  until: kibana_password_reset.rc == 0
  retries: 5
  delay: 10
  changed_when: kibana_password_reset.rc == 0

- name: Display progress - Security configured
  debug:
    msg: "✓ Elasticsearch security configured with password: elastic"

- name: Wait for Elasticsearch cluster to be ready
  uri:
    url: "http://localhost:{{ elasticsearch_port }}/_cluster/health?wait_for_status=yellow&timeout=60s"
    method: GET
    user: "elastic"
    password: "{{ elastic_password }}"
    force_basic_auth: yes
  register: es_health
  until: es_health.status == 200
  retries: 10
  delay: 15

- name: Display progress - Elasticsearch ready
  debug:
    msg: "✓ Elasticsearch cluster is ready for EDR data ingestion"

- name: Verify Elasticsearch cluster health
  uri:
    url: "http://localhost:{{ elasticsearch_port }}/_cluster/health"
    user: "elastic"
    password: "{{ elastic_password }}"
    force_basic_auth: yes
  register: final_es_health
  until: final_es_health.json.status in ["yellow", "green"]
  retries: 10
  delay: 10

- name: Display Elasticsearch cluster status
  debug:
    msg:
      - "Elasticsearch Status: {{ final_es_health.json.status }}"
      - "Number of nodes: {{ final_es_health.json.number_of_nodes }}"
      - "Active shards: {{ final_es_health.json.active_shards }}"
EOF

# Create Kibana role files
cat > "$ELASTIC_DIR/ansible/roles/kibana/defaults/main.yml" << 'EOF'
kibana_version: "8.11.0"
kibana_port: 5601
kibana_host: "0.0.0.0"
elasticsearch_host: "localhost"
kibana_admin_password: "kibana"
EOF

cat > "$ELASTIC_DIR/ansible/roles/kibana/handlers/main.yml" << 'EOF'
- name: restart kibana
  systemd:
    name: kibana
    state: restarted
EOF

cat > "$ELASTIC_DIR/ansible/roles/kibana/templates/kibana.yml.j2" << 'EOF'
server.port: {{ kibana_port }}
server.host: "{{ kibana_host }}"
elasticsearch.hosts: ["http://{{ elasticsearch_host }}:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "{{ elastic_password }}"

# Encryption key for saved objects
xpack.encryptedSavedObjects.encryptionKey: "goad-edr-encryption-key-32chars-long-minimum-requirement"

# Fleet settings for EDR agent management
xpack.fleet.agents.enabled: true
xpack.fleet.agents.elasticsearch.hosts: ["http://{{ elasticsearch_host }}:9200"]
xpack.fleet.agents.fleet_server.hosts: ["http://{{ ansible_default_ipv4.address }}:8220"]

# Security features
xpack.security.enabled: true
xpack.fleet.registryUrl: "https://epr.elastic.co"

# EDR-specific settings
xpack.securitySolution.endpoint.enabled: true
EOF

cat > "$ELASTIC_DIR/ansible/roles/kibana/files/edr_dashboards.ndjson" << 'EOF'
{"id":"edr-overview-dashboard","type":"dashboard","attributes":{"title":"EDR Overview Dashboard","description":"Comprehensive endpoint detection and response monitoring for GOAD lab","timeRestore":false,"version":1}}
{"id":"endpoint-security-dashboard","type":"dashboard","attributes":{"title":"Endpoint Security Dashboard","description":"Real-time endpoint protection monitoring including malware detection, process monitoring, and threat hunting","timeRestore":false,"version":1}}
{"id":"malware-detection-dashboard","type":"dashboard","attributes":{"title":"Malware Detection Dashboard","description":"Malware and ransomware detection events with detailed analysis","timeRestore":false,"version":1}}
{"id":"process-monitoring-dashboard","type":"dashboard","attributes":{"title":"Process Monitoring Dashboard","description":"Process creation, execution, and behavioral analysis","timeRestore":false,"version":1}}
{"id":"endpoint-logs-index-pattern","type":"index-pattern","attributes":{"title":"logs-endpoint.*","timeFieldName":"@timestamp","fields":"[{\"name\":\"@timestamp\",\"type\":\"date\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"event.action\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"event.category\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"event.dataset\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"event.kind\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"event.module\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"event.outcome\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"event.type\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"host.hostname\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"host.name\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"process.name\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"process.pid\",\"type\":\"number\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"process.executable\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"file.name\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"file.path\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"file.hash.md5\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"file.hash.sha256\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"Endpoint.policy.applied.name\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"agent.name\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true}]"}}
EOF

cat > "$ELASTIC_DIR/ansible/roles/kibana/tasks/main.yml" << 'EOF'
- name: Display Kibana installation progress
  debug:
    msg: "Starting Kibana installation for EDR management..."

- name: Install Kibana
  apt:
    name: "kibana={{ kibana_version }}"
    state: present
  notify: restart kibana

- name: Create kibana configuration
  template:
    src: kibana.yml.j2
    dest: /etc/kibana/kibana.yml
    owner: root
    group: kibana
    mode: '0660'
  notify: restart kibana

- name: Start and enable Kibana
  systemd:
    name: kibana
    state: started
    enabled: yes

- name: Display startup message
  debug:
    msg: "Kibana is starting... This requires Elasticsearch to be ready first and may take several minutes."

- name: Wait for Elasticsearch to be ready FIRST
  uri:
    url: "http://localhost:9200/_cluster/health"
    user: "elastic"
    password: "elastic"
    force_basic_auth: yes
  register: es_health
  until: es_health.json.status in ["yellow", "green"]
  retries: 20
  delay: 15

- name: Wait for Kibana to start (extended timeout)
  wait_for:
    port: "{{ kibana_port }}"
    host: "localhost"
    delay: 60
    timeout: 900

- name: Verify Kibana API is ready
  uri:
    url: "http://localhost:{{ kibana_port }}/api/status"
    method: GET
  register: kibana_status
  until: kibana_status.status == 200
  retries: 15
  delay: 20

- name: Display Kibana ready message
  debug:
    msg: "✓ Kibana is now ready for EDR management"

- name: Setup Fleet for EDR agents
  uri:
    url: "http://localhost:{{ kibana_port }}/api/fleet/setup"
    method: POST
    headers:
      Content-Type: "application/json"
      kbn-xsrf: true
      Authorization: "Basic {{ ('elastic:' + elastic_password) | b64encode }}"
  register: fleet_setup
  until: fleet_setup.status == 200
  retries: 10
  delay: 30

- name: Create Fleet Server host
  uri:
    url: "http://localhost:{{ kibana_port }}/api/fleet/fleet_server_hosts"
    method: POST
    headers:
      Content-Type: "application/json"
      kbn-xsrf: true
      Authorization: "Basic {{ ('elastic:' + elastic_password) | b64encode }}"
    body_format: json
    body:
      name: "default"
      host_urls: ["http://{{ ansible_default_ipv4.address }}:8220"]
      is_default: true
  register: fleet_server_host
  failed_when: false

- name: Create Fleet Server policy
  uri:
    url: "http://localhost:{{ kibana_port }}/api/fleet/agent_policies"
    method: POST
    headers:
      Content-Type: "application/json"
      kbn-xsrf: true
      Authorization: "Basic {{ ('elastic:' + elastic_password) | b64encode }}"
    body_format: json
    body:
      name: "Fleet Server Policy"
      namespace: "default"
      description: "Fleet Server policy for GOAD EDR lab"
      has_fleet_server: true
  register: fleet_server_policy
  failed_when: false

- name: Create Windows EDR agent policy
  uri:
    url: "http://localhost:{{ kibana_port }}/api/fleet/agent_policies"
    method: POST
    headers:
      Content-Type: "application/json"
      kbn-xsrf: true
      Authorization: "Basic {{ ('elastic:' + elastic_password) | b64encode }}"
    body_format: json
    body:
      name: "Windows EDR Policy"
      namespace: "default"
      description: "EDR policy for Windows domain machines"
  register: windows_edr_policy
  failed_when: false

- name: Get existing Windows EDR policy ID (if policy creation failed)
  uri:
    url: "http://localhost:{{ kibana_port }}/api/fleet/agent_policies"
    method: GET
    headers:
      Content-Type: "application/json"
      kbn-xsrf: true
      Authorization: "Basic {{ ('elastic:' + elastic_password) | b64encode }}"
  register: existing_edr_policies
  when: windows_edr_policy.status is defined and windows_edr_policy.status == 409

- name: Set Windows EDR policy ID from existing policy
  set_fact:
    windows_edr_policy_id: "{{ existing_edr_policies.json.items | selectattr('name', 'equalto', 'Windows EDR Policy') | list | first | attr('id') }}"
  when: windows_edr_policy.status is defined and windows_edr_policy.status == 409

- name: Set Windows EDR policy ID from newly created policy
  set_fact:
    windows_edr_policy_id: "{{ windows_edr_policy.json.item.id }}"
  when: windows_edr_policy.status is defined and windows_edr_policy.status == 200

- name: Add Endpoint Security integration to Windows EDR policy
  uri:
    url: "http://localhost:{{ kibana_port }}/api/fleet/package_policies"
    method: POST
    headers:
      Content-Type: "application/json"
      kbn-xsrf: true
      Authorization: "Basic {{ ('elastic:' + elastic_password) | b64encode }}"
    body_format: json
    body:
      name: "endpoint-security-policy"
      policy_id: "{{ windows_edr_policy_id }}"
      package:
        name: "endpoint"
        version: "latest"
      inputs:
        - type: "endpoint"
          enabled: true
          streams: []
          config:
            policy:
              value:
                windows:
                  malware:
                    mode: "prevent"
                  ransomware:
                    mode: "prevent"
                  memory_protection:
                    mode: "prevent"
                  behavior_protection:
                    mode: "prevent"
                  popup:
                    malware:
                      enabled: true
                    ransomware:
                      enabled: true
                  antivirus_registration:
                    enabled: true
                  attack_surface_reduction:
                    credential_hardening:
                      enabled: true
  register: endpoint_integration
  failed_when: false

- name: Install Fleet Server locally
  shell: |
    cd /tmp
    curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-{{ kibana_version }}-linux-x86_64.tar.gz
    tar xzvf elastic-agent-{{ kibana_version }}-linux-x86_64.tar.gz
    cd elastic-agent-{{ kibana_version }}-linux-x86_64
    sudo ./elastic-agent install --fleet-server-es=http://localhost:9200 --fleet-server-service-token=$(curl -s -X POST -u elastic:elastic "http://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-server-token" | jq -r .token.value) --fleet-server-policy={{ fleet_server_policy.json.item.id }} --force
  register: fleet_server_install
  failed_when: false

- name: Wait for Fleet Server to be ready
  pause:
    seconds: 30
  when: fleet_server_install.rc == 0

- name: Store Windows EDR policy information for agent installation
  set_fact:
    windows_agent_policy: "{{ windows_edr_policy }}"

- name: Find host-only network IP
  set_fact:
    host_only_candidates: >-
      {{
        ansible_interfaces 
        | map('regex_replace', '^(.*)$', 'ansible_\1')
        | map('extract', hostvars[inventory_hostname])
        | selectattr('ipv4', 'defined')
        | selectattr('ipv4.address', 'defined')
        | selectattr('ipv4.address', 'match', '^192\.168\.56\.')
        | map(attribute='ipv4.address')
        | list
      }}

- name: Set VM network information
  set_fact:
    elastic_vm_ip: "{{ ansible_default_ipv4.address }}"
    elastic_host_only_ip: "{{ host_only_candidates[0] if host_only_candidates else ansible_default_ipv4.address }}"

- name: Display comprehensive EDR setup information
  debug:
    msg:
      - "==============================================="
      - "🛡️  ELASTIC EDR INSTALLATION COMPLETE! 🛡️"
      - "==============================================="
      - ""
      - "📊 ACCESS INFORMATION:"
      - "• Kibana EDR Console: http://{{ elastic_host_only_ip }}:{{ kibana_port }}"
      - "• Elasticsearch API: http://{{ elastic_host_only_ip }}:9200"
      - "• Fleet Server: http://{{ elastic_host_only_ip }}:8220"
      - "• From Host (Port Forward): http://localhost:{{ kibana_port }} (if configured)"
      - ""
      - "🔐 CREDENTIALS:"
      - "• Username: elastic"
      - "• Password: elastic"
      - ""
      - "🛡️ EDR FEATURES:"
      - "• Endpoint Protection: Malware & Ransomware Prevention"
      - "• Real-time Process Monitoring"
      - "• Memory Protection & Behavior Analysis"
      - "• Attack Surface Reduction"
      - "• Threat Hunting & Investigation"
      - ""
      - "🔍 EDR MANAGEMENT:"
      - "• Endpoint Management: Fleet → Agents"
      - "• Security Events: Security → Explore"
      - "• Detections: Security → Detections"
      - "• Cases: Security → Cases"
      - "• Host Details: Security → Explore → Hosts"
      - ""
      - "💡 QUICK START:"
      - "1. Open http://{{ elastic_host_only_ip }}:{{ kibana_port }}"
      - "2. Login with elastic/elastic"
      - "3. Go to Fleet → Agents to verify Windows EDR agents enrollment"
      - "4. Go to Security → Explore for endpoint investigation"
      - "5. Go to Security → Detections for threat detection rules"
      - "==============================================="
EOF

# Create Windows Agent role files
cat > "$ELASTIC_DIR/ansible/roles/elastic_agent_windows/defaults/main.yml" << 'EOF'
elastic_agent_version: "8.11.3"
elastic_agent_download_url: "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-{{ elastic_agent_version }}-windows-x86_64.zip"
elastic_install_location: "c:\\tmp"
fleet_enrollment_token: "auto-generate"
EOF

cat > "$ELASTIC_DIR/ansible/roles/elastic_agent_windows/tasks/main.yml" << 'EOF'
- name: Display EDR agent installation progress
  debug:
    msg: "Installing Elastic EDR Agent on {{ inventory_hostname }}..."

- name: Check if Elastic Agent service exists
  win_service:
    name: "Elastic Agent"
  register: elastic_agent_service
  failed_when: false

- name: Create installation directory
  win_file:
    path: "{{ elastic_install_location }}"
    state: directory

- name: Uninstall existing Elastic Agent if present
  win_shell: |
    if (Get-Service "Elastic Agent" -ErrorAction SilentlyContinue) {
      cd "C:\Program Files\Elastic\Agent"
      .\elastic-agent.exe uninstall --force
    }
  register: agent_uninstall
  failed_when: false

- name: Download Elastic EDR Agent
  win_get_url:
    url: "{{ elastic_agent_download_url }}"
    dest: "{{ elastic_install_location }}\\elastic-agent.zip"
  register: agent_download
  when: not (elastic_agent_service.exists | default(false))

- name: Extract Elastic EDR Agent
  win_unzip:
    src: "{{ elastic_install_location }}\\elastic-agent.zip"
    dest: "{{ elastic_install_location }}"
  when: agent_download.changed

- name: Get Fleet enrollment token for Windows EDR policy
  uri:
    url: "http://{{ elastic_server_host }}:5601/api/fleet/enrollment_api_keys"
    method: POST
    headers:
      kbn-xsrf: true
      Content-Type: "application/json"
      Authorization: "Basic {{ ('elastic:elastic') | b64encode }}"
    body_format: json
    body:
      policy_id: "{{ hostvars['elastic']['windows_agent_policy']['json']['item']['id'] }}"
  register: enrollment_tokens
  delegate_to: localhost
  when: agent_download.changed

- name: Install and enroll Elastic EDR Agent with Fleet
  win_shell: |
    cd "{{ elastic_install_location }}\\elastic-agent-{{ elastic_agent_version }}-windows-x86_64"
    .\\elastic-agent.exe install --url=http://{{ elastic_server_host }}:8220 --enrollment-token={{ enrollment_tokens.json.list[0].api_key }} --force
  when: agent_download.changed
  register: agent_install

- name: Start Elastic EDR Agent service
  win_service:
    name: "Elastic Agent"
    state: started
    start_mode: auto
  when: agent_install.changed

- name: Display EDR agent installation status
  debug:
    msg: "✓ Elastic EDR Agent installed and enrolled on {{ inventory_hostname }}"
  when: agent_install.changed

- name: Verify EDR agent installation
  win_command: '"C:\Program Files\Elastic\Agent\elastic-agent.exe" status'
  register: agent_status_output
  failed_when: false

- name: Display EDR Agent status
  debug:
    msg:
      - "EDR Agent Status on {{ inventory_hostname }}:"
      - "{{ agent_status_output.stdout | default('Unable to retrieve status') }}"
EOF

# Create provider configuration files
cat > "$ELASTIC_DIR/providers/aws/linux.tf" << 'EOF'
"elastic" = {
  name               = "elastic"
  linux_sku          = "22_04-lts-gen2"
  linux_version      = "latest"
  ami                = "ami-00c71bd4d220aa22a"
  private_ip_address = "{{ip_range}}.52"
  password           = "sgdvnkjhdshlsd"
  size               = "t3.large"  # 2cpu / 8GB for streamlined EDR
}
EOF

cat > "$ELASTIC_DIR/providers/azure/linux.tf" << 'EOF'
"elastic" = {
  name               = "elastic"
  linux_sku          = "22_04-lts-gen2"
  linux_version      = "latest"
  private_ip_address = "{{ip_range}}.52"
  password           = "sgdvnkjhdshlsd"
  size               = "Standard_D2s_v3"  # 2cpu/8GB for streamlined EDR
}
EOF

cat > "$ELASTIC_DIR/providers/ludus/config.yml" << 'EOF'
  - vm_name: "{{ range_id }}-ELASTIC"
    hostname: "{{ range_id }}-ELASTIC"
    template: ubuntu-22.04-x64-server-template
    vlan: 10
    ip_last_octet: 52
    ram_gb: "{{ elastic_vm_memory_gb | default(8) }}"
    cpus: "{{ elastic_vm_cpus | default(4) }}"
    linux: true
EOF

cat > "$ELASTIC_DIR/providers/virtualbox/Vagrantfile" << 'EOF'
boxes.append(
  {
    :name => "{{lab_name}}-ELASTIC",
    :ip => "{{ip_range}}.52",
    :box => "bento/ubuntu-22.04",
    :os => "linux",
    :cpus => "{{ elastic_vm_cpus | default(4) }}",
    :mem => "{{ (elastic_vm_memory_gb | default(8)) * 1024 }}",
    :forwarded_port => [
      { :guest => 5601, :host => 5601 },
      { :guest => 9200, :host => 9200 },
      { :guest => 22, :host => 2211, :id => "ssh" }
    ]
  }
)
EOF

cat > "$ELASTIC_DIR/providers/vmware/Vagrantfile" << 'EOF'
boxes.append(
  {
    :name => "{{lab_name}}-ELASTIC",
    :ip => "{{ip_range}}.52",
    :box => "bento/ubuntu-22.04",
    :os => "linux",
    :cpus => "{{ elastic_vm_cpus | default(4) }}",
    :mem => "{{ (elastic_vm_memory_gb | default(8)) * 1024 }}",
    :forwarded_port => [
      { :guest => 5601, :host => 5601 },
      { :guest => 9200, :host => 9200 },
      { :guest => 22, :host => 2211, :id => "ssh" }
    ]
  }
)
EOF

# Create README.md
cat > "$ELASTIC_DIR/README.md" << 'EOF'
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
EOF

echo -e "${GREEN}✓ README.md created${NC}"

# Set permissions
echo -e "${BLUE}Setting proper permissions...${NC}"
find "$ELASTIC_DIR" -type f -name "*.yml" -exec chmod 644 {} \;
find "$ELASTIC_DIR" -type f -name "*.j2" -exec chmod 644 {} \;
find "$ELASTIC_DIR" -type f -name "*.tf" -exec chmod 644 {} \;
find "$ELASTIC_DIR" -type f -name "Vagrantfile" -exec chmod 644 {} \;
find "$ELASTIC_DIR" -type f -name "*.json" -exec chmod 644 {} \;
find "$ELASTIC_DIR" -type f -name "*.ndjson" -exec chmod 644 {} \;
find "$ELASTIC_DIR" -type f -name "README.md" -exec chmod 644 {} \;
find "$ELASTIC_DIR" -type d -exec chmod 755 {} \;

echo -e "${GREEN}✓ Permissions set${NC}"

echo ""
echo -e "${GREEN}===========================================${NC}"
echo -e "${GREEN}🛡️  MIGRATION COMPLETED SUCCESSFULLY! 🛡️${NC}"
echo -e "${GREEN}===========================================${NC}"
echo ""
echo -e "${YELLOW}SUMMARY OF CHANGES:${NC}"
echo -e "${BLUE}Removed:${NC}"
echo "  • Logstash (replaced by direct Fleet Server communication)"
echo "  • Complex Windows Event Log parsing"
echo "  • Custom security event categorization"  
echo "  • Multiple integration types"
echo "  • Unnecessary security templates"
echo ""
echo -e "${BLUE}Added/Enhanced:${NC}"
echo "  • Focused Elastic EDR configuration"
echo "  • Endpoint Security integration"
echo "  • EDR-specific dashboards"
echo "  • Streamlined agent policies"
echo "  • Malware and ransomware protection"
echo "  • Behavioral analysis and memory protection"
echo ""
echo -e "${BLUE}Optimized:${NC}"
echo "  • Reduced default RAM from 12GB to 8GB"
echo "  • Simplified Elasticsearch configuration"
echo "  • Faster deployment process"
echo "  • More reliable agent enrollment"
echo ""
echo -e "${YELLOW}BACKUP LOCATION:${NC}"
echo "  $BACKUP_DIR"
echo ""
echo -e "${YELLOW}NEW EDR EXTENSION:${NC}"
echo "  $ELASTIC_DIR"
echo ""
echo -e "${GREEN}Ready to deploy with: ./goad.sh -t install -l <lab> -p <provider> -e elastic${NC}"
echo ""
