#!/bin/bash

# Navigate to the elk extension directory  
cd elk

# Remove old role directories
echo "🧹 Cleaning old roles..."
rm -rf ansible/roles/elk
rm -rf ansible/roles/logs_windows

# Create new directory structure
echo "📁 Creating new directory structure..."
mkdir -p ansible/roles/elastic_stack/{defaults,files,tasks}
mkdir -p ansible/roles/elastic_defend_windows/{defaults,tasks}

# Create elastic_stack role files
echo "⚙️ Creating Elastic Stack role configuration..."
cat > ansible/roles/elastic_stack/defaults/main.yml << 'EOF'
elasticsearch_version: '8.11.0'
elastic_password: 'changeme'
kibana_password: 'changeme'

# Fleet Server Configuration
fleet_server_host: '0.0.0.0'
fleet_server_port: '8220'

# Network Configuration  
elasticsearch_host: '0.0.0.0'
elasticsearch_port: '9200'
kibana_host: '0.0.0.0'
kibana_port: '5601'

# Disk and Performance Settings
elasticsearch_heap_size: '3g'
minimum_disk_space_gb: 20
EOF

cat > ansible/roles/elastic_stack/files/elasticsearch.yml << 'EOF'
cluster.name: elastic-edr-cluster
node.name: elk-edr-node
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node

# Security Configuration (simplified for lab environment)
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
xpack.security.http.ssl:
  enabled: false  # Disabled for simplicity in lab environment
xpack.security.transport.ssl:
  enabled: false

# Fleet Integration
action.auto_create_index: ".fleet-*,.logs-*,.metrics-*,.traces-*,.transform-*,logs-*,metrics-*,synthetics-*"

# Performance Settings for Lab
indices.memory.index_buffer_size: 256mb
thread_pool.write.queue_size: 1000
EOF

cat > ansible/roles/elastic_stack/files/kibana.yml << 'EOF'
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
elasticsearch.username: "kibana_system" 
elasticsearch.password: "changeme"

# Fleet Configuration for VirtualBox
xpack.fleet.agents.elasticsearch.hosts: ["http://localhost:9200"]
xpack.fleet.agents.fleet_server.hosts: ["http://{{ip_range}}.50:8220"]

# Simple encryption key for lab
xpack.encryptedSavedObjects.encryptionKey: "a7a6311933d3503b89bc2dbc36572c33a6c10925682e591bffcab6911c06786d"

# Performance Settings
elasticsearch.requestTimeout: 60000
elasticsearch.pingTimeout: 30000
EOF

echo "📝 Creating main installation tasks with all fixes..."
cat > ansible/roles/elastic_stack/tasks/main.yml << 'EOF'
- name: Check available disk space
  shell: df / | tail -1 | awk '{print $4}'
  register: available_space
  
- name: Fail if insufficient disk space
  fail:
    msg: "Insufficient disk space. Need at least {{ minimum_disk_space_gb }}GB, available: {{ (available_space.stdout|int / 1024 / 1024) | round(1) }}GB"
  when: (available_space.stdout|int / 1024 / 1024) < minimum_disk_space_gb

- name: Update apt cache
  apt:
    update_cache: true
    cache_valid_time: 86400

- name: Install required dependencies
  apt:
    name:
      - apt-transport-https
      - ca-certificates
      - curl
      - gnupg
      - unzip
      - ufw
    state: present

- name: Add Elastic GPG key
  apt_key:
    url: https://artifacts.elastic.co/GPG-KEY-elasticsearch
    state: present

- name: Add Elastic repository
  apt_repository:
    repo: 'deb https://artifacts.elastic.co/packages/8.x/apt stable main'
    state: present
    update_cache: true

- name: Install Elasticsearch
  apt:
    name: elasticsearch
    state: present

- name: Copy Elasticsearch configuration
  copy:
    src: elasticsearch.yml
    dest: /etc/elasticsearch/elasticsearch.yml
    owner: root
    group: elasticsearch
    mode: '0660'
    backup: yes

- name: Set Elasticsearch heap size (3GB for 8GB total RAM)
  lineinfile:
    path: /etc/elasticsearch/jvm.options.d/heap.options
    line: "{{ item }}"
    create: yes
  loop:
    - '-Xms{{ elasticsearch_heap_size }}'
    - '-Xmx{{ elasticsearch_heap_size }}'

- name: Enable and start Elasticsearch
  systemd:
    name: elasticsearch
    enabled: yes
    state: started
    daemon_reload: yes

- name: Wait for Elasticsearch to be ready
  uri:
    url: "http://localhost:9200/_cluster/health"
    method: GET
    status_code: 200
  register: elasticsearch_health
  until: elasticsearch_health.status == 200
  retries: 60
  delay: 10

- name: Set built-in user passwords
  uri:
    url: "http://localhost:9200/_security/user/{{ item.user }}/_password"
    method: PUT
    body_format: json
    body:
      password: "{{ item.password }}"
    status_code: 200
  loop:
    - { user: "elastic", password: "{{ elastic_password }}" }
    - { user: "kibana_system", password: "{{ kibana_password }}" }

- name: Install Kibana
  apt:
    name: kibana
    state: present

- name: Copy Kibana configuration
  copy:
    src: kibana.yml  
    dest: /etc/kibana/kibana.yml
    owner: root
    group: kibana
    mode: '0660'
    backup: yes

- name: Enable and start Kibana
  systemd:
    name: kibana
    enabled: yes
    state: started
    daemon_reload: yes

- name: Wait for Kibana to be ready
  uri:
    url: "http://localhost:5601/status"
    method: GET
    status_code: 200
  register: kibana_health
  until: kibana_health.status == 200
  retries: 60
  delay: 15

# Fleet Server Setup with proper sequencing
- name: Setup Fleet in Kibana
  uri:
    url: "http://localhost:5601/api/fleet/setup"
    method: POST
    user: "elastic"
    password: "{{ elastic_password }}"
    headers:
      Content-Type: "application/json"
      kbn-xsrf: "true"
    body_format: json
    body: {}
    status_code: [200, 409]

- name: Wait for Fleet setup to complete
  uri:
    url: "http://localhost:5601/api/fleet/agent_policies"
    method: GET
    user: "elastic"
    password: "{{ elastic_password }}"
    headers:
      kbn-xsrf: "true"
    status_code: 200
  register: fleet_ready
  until: fleet_ready.status == 200
  retries: 30
  delay: 10

- name: Create Fleet Server policy FIRST
  uri:
    url: "http://localhost:5601/api/fleet/agent_policies"
    method: POST
    user: "elastic"
    password: "{{ elastic_password }}"
    headers:
      Content-Type: "application/json"
      kbn-xsrf: "true"
    body_format: json
    body:
      name: "Fleet Server Policy"
      description: "Policy for Fleet Server"
      namespace: "default"
      monitoring_enabled: 
        - "logs"
        - "metrics"
    status_code: [200, 409]
  register: fleet_server_policy_response

- name: Add Fleet Server integration to policy
  uri:
    url: "http://localhost:5601/api/fleet/package_policies"
    method: POST
    user: "elastic"
    password: "{{ elastic_password }}"
    headers:
      Content-Type: "application/json"
      kbn-xsrf: "true"
    body_format: json
    body:
      name: "fleet-server-policy"
      description: "Fleet Server integration"
      namespace: "default"  
      policy_id: "{{ fleet_server_policy_response.json.item.id }}"
      enabled: true
      package:
        name: "fleet_server"
        version: "latest"
      inputs:
        - type: "fleet-server"
          enabled: true
          streams: []
          vars:
            host:
              value: ["0.0.0.0:8220"]
            port:
              value: [8220]
    status_code: [200, 409]
  when: fleet_server_policy_response.json.item.id is defined

- name: Download Elastic Agent
  get_url:
    url: "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-{{ elasticsearch_version }}-linux-x86_64.tar.gz"
    dest: /tmp/elastic-agent.tar.gz
    mode: '0644'

- name: Create elastic-agent directory
  file:
    path: /opt/elastic-agent
    state: directory
    mode: '0755'

- name: Extract Elastic Agent
  unarchive:
    src: /tmp/elastic-agent.tar.gz
    dest: /opt/elastic-agent
    remote_src: yes
    extra_opts: [--strip-components=1]

- name: Generate service token for Fleet Server
  uri:
    url: "http://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-server-token"
    method: POST
    user: "elastic"
    password: "{{ elastic_password }}"
    body_format: json
    body: {}
    status_code: 200
  register: service_token_response

- name: Install Fleet Server with proper flags and policy
  shell: |
    ./elastic-agent install --fleet-server-es=http://localhost:9200 \
    --fleet-server-service-token={{ service_token_response.json.token.value }} \
    --fleet-server-policy={{ fleet_server_policy_response.json.item.id }} \
    --fleet-server-host={{ fleet_server_host }} \
    --fleet-server-port={{ fleet_server_port }} \
    --fleet-server-es-insecure \
    --force --insecure
  args:
    chdir: /opt/elastic-agent
  when: fleet_server_policy_response.json.item.id is defined

- name: Wait for Fleet Server to be fully ready
  uri:
    url: "http://localhost:{{ fleet_server_port }}/api/status"
    method: GET
    status_code: 200
  register: fleet_server_health
  until: fleet_server_health.status == 200
  retries: 60
  delay: 10

- name: Wait additional time for Fleet Server initialization
  pause:
    seconds: 30

- name: Configure Fleet Server hosts in Kibana
  uri:
    url: "http://localhost:5601/api/fleet/fleet_server_hosts"
    method: POST
    user: "elastic"
    password: "{{ elastic_password }}"
    headers:
      Content-Type: "application/json"
      kbn-xsrf: "true"
    body_format: json
    body:
      name: "default"
      host_urls: ["http://{{ ansible_default_ipv4.address }}:{{ fleet_server_port }}"]
      is_default: true
    status_code: [200, 409]

- name: Create Agent Policy with Elastic Defend
  uri:
    url: "http://localhost:5601/api/fleet/agent_policies"
    method: POST
    user: "elastic"
    password: "{{ elastic_password }}"
    headers:
      Content-Type: "application/json"
      kbn-xsrf: "true"
    body_format: json
    body:
      name: "Windows EDR Policy"
      description: "Policy for Windows machines with Elastic Defend"
      namespace: "default"
      monitoring_enabled: 
        - "logs"
        - "metrics"
    status_code: [200, 409]
  register: agent_policy_response

- name: Add Elastic Defend integration to policy
  uri:
    url: "http://localhost:5601/api/fleet/package_policies"
    method: POST
    user: "elastic"
    password: "{{ elastic_password }}"
    headers:
      Content-Type: "application/json"
      kbn-xsrf: "true"
    body_format: json
    body:
      name: "elastic-defend-policy"
      description: "Elastic Defend integration for Windows machines"
      namespace: "default"
      policy_id: "{{ agent_policy_response.json.item.id }}"
      enabled: true
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
                  events:
                    process: true
                    file: true
                    network: true
                    registry: true
                  malware:
                    mode: "prevent"
                  ransomware:
                    mode: "prevent"
    status_code: [200, 409]
  when: agent_policy_response.json.item.id is defined

- name: Generate enrollment token (with retry)
  uri:
    url: "http://localhost:5601/api/fleet/enrollment_api_keys"
    method: POST
    user: "elastic"
    password: "{{ elastic_password }}"
    headers:
      Content-Type: "application/json"
      kbn-xsrf: "true"
    body_format: json
    body:
      policy_id: "{{ agent_policy_response.json.item.id }}"
      name: "Windows EDR Token"
    status_code: [200, 409]
  register: enrollment_token_response
  until: enrollment_token_response.status == 200
  retries: 10
  delay: 15
  when: agent_policy_response.json.item.id is defined

- name: Create web-accessible directory for tokens
  file:
    path: /var/www/html
    state: directory
    mode: '0755'

- name: Install nginx for token sharing
  apt:
    name: nginx
    state: present

- name: Enable nginx
  systemd:
    name: nginx
    enabled: yes
    state: started

- name: Open firewall for Fleet Server port
  ufw:
    rule: allow
    port: "{{ fleet_server_port }}"
    proto: tcp
  ignore_errors: yes

- name: Open firewall for Kibana port
  ufw:
    rule: allow
    port: "{{ kibana_port }}"
    proto: tcp
  ignore_errors: yes

- name: Open firewall for Elasticsearch port
  ufw:
    rule: allow
    port: "{{ elasticsearch_port }}"
    proto: tcp
  ignore_errors: yes

- name: Save enrollment token to web directory
  copy:
    content: "{{ enrollment_token_response.json.item.api_key }}"
    dest: /var/www/html/enrollment_token
    mode: '0644'
  when: enrollment_token_response.json.item.api_key is defined

- name: Save Fleet Server URL to web directory
  copy:
    content: "http://{{ ansible_default_ipv4.address }}:{{ fleet_server_port }}"
    dest: /var/www/html/fleet_server_url
    mode: '0644'

- name: Display installation summary
  debug:
    msg: |
      ✅ EDR Installation Complete!
      📊 Kibana: http://{{ ansible_default_ipv4.address }}:5601 (elastic/changeme)
      🔍 Elasticsearch: http://{{ ansible_default_ipv4.address }}:9200
      🚀 Fleet Server: http://{{ ansible_default_ipv4.address }}:8220
      📝 Enrollment Token: Available at http://{{ ansible_default_ipv4.address }}/enrollment_token
EOF

# Create elastic_defend_windows role files
echo "🪟 Creating Windows EDR agent role..."
cat > ansible/roles/elastic_defend_windows/defaults/main.yml << 'EOF'
elasticsearch_version: '8.11.0'
temp_download_path: 'C:\temp'
fleet_server_host: "{{ hostvars['ELK-EDR'].ansible_host }}"
max_install_retries: 3
EOF

cat > ansible/roles/elastic_defend_windows/tasks/main.yml << 'EOF'
- name: Create temporary directory
  win_file:
    path: "{{ temp_download_path }}"
    state: directory

- name: Get enrollment token from Fleet Server (with retry)
  win_get_url:
    url: "http://{{ fleet_server_host }}/enrollment_token"
    dest: "{{ temp_download_path }}\\enrollment_token"
  register: enrollment_token_download
  retries: 10
  delay: 30

- name: Get Fleet Server URL (with retry)
  win_get_url:
    url: "http://{{ fleet_server_host }}/fleet_server_url"
    dest: "{{ temp_download_path }}\\fleet_server_url"
  register: fleet_url_download
  retries: 5
  delay: 15

- name: Verify enrollment token was retrieved
  win_stat:
    path: "{{ temp_download_path }}\\enrollment_token"
  register: token_file
  failed_when: not token_file.stat.exists

- name: Verify Fleet Server URL was retrieved
  win_stat:
    path: "{{ temp_download_path }}\\fleet_server_url"
  register: url_file
  failed_when: not url_file.stat.exists

- name: Read enrollment token
  win_shell: Get-Content "{{ temp_download_path }}\\enrollment_token"
  register: enrollment_token

- name: Read Fleet Server URL
  win_shell: Get-Content "{{ temp_download_path }}\\fleet_server_url"
  register: fleet_server_url

- name: Validate token and URL are not empty
  fail:
    msg: "Enrollment token or Fleet Server URL is empty"
  when: enrollment_token.stdout | trim == "" or fleet_server_url.stdout | trim == ""

- name: Download Elastic Agent for Windows
  win_get_url:
    url: "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-{{ elasticsearch_version }}-windows-x86_64.zip"
    dest: "{{ temp_download_path }}\\elastic-agent.zip"
  register: agent_download
  retries: 3
  delay: 10

- name: Extract Elastic Agent
  win_unzip:
    src: "{{ temp_download_path }}\\elastic-agent.zip"
    dest: "{{ temp_download_path }}\\"
    delete_archive: no

- name: Check if Elastic Agent is already installed
  win_service:
    name: "Elastic Agent"
  register: existing_agent
  ignore_errors: yes

- name: Uninstall existing Elastic Agent if present
  win_shell: |
    cd "C:\Program Files\Elastic\Agent"
    .\elastic-agent.exe uninstall --force
  when: existing_agent.exists is defined and existing_agent.exists
  ignore_errors: yes

- name: Install Elastic Agent with Fleet enrollment
  win_shell: |
    cd "{{ temp_download_path }}\\elastic-agent-{{ elasticsearch_version }}-windows-x86_64"
    .\\elastic-agent.exe install --url="{{ fleet_server_url.stdout | trim }}" --enrollment-token="{{ enrollment_token.stdout | trim }}" --insecure --force --non-interactive
  register: agent_install_result
  failed_when: agent_install_result.rc != 0
  retries: "{{ max_install_retries }}"
  delay: 30

- name: Wait for Elastic Agent service to start
  win_service:
    name: "Elastic Agent"
    state: started
  register: agent_service_status
  retries: 15
  delay: 20
  until: agent_service_status.state == "running"

- name: Verify agent enrollment
  win_shell: |
    cd "C:\Program Files\Elastic\Agent"
    .\elastic-agent.exe status
  register: agent_status
  retries: 5
  delay: 10

- name: Display agent status
  debug:
    msg: "✅ Elastic Agent Status: {{ agent_status.stdout }}"

- name: Clean up temporary files
  win_file:
    path: "{{ item }}"
    state: absent
  loop:
    - "{{ temp_download_path }}\\elastic-agent.zip"
    - "{{ temp_download_path }}\\enrollment_token"
    - "{{ temp_download_path }}\\fleet_server_url"
  ignore_errors: yes
EOF

# Update existing configuration files
echo "📋 Updating configuration files..."
cat > extension.json << 'EOF'
{
    "name": "elastic-edr",
    "description": "Add Elastic EDR with Fleet Server and Windows agents",
    "machines": [
        "ELK-EDR"
    ],
    "compatibility": [
        "*"
    ],
    "impact": "add a linux machine with Elastic Stack + Fleet Server and install EDR agents on all windows machines"
}
EOF

cat > inventory << 'EOF'
; EXTENSION : Elastic EDR ------------------------------------------
[default]
ELK-EDR ansible_host={{ip_range}}.50 ansible_connection=ssh ansible_ssh_common_args='-o StrictHostKeyChecking=no'

; Recipe associations -------------------
[elastic_stack]
ELK-EDR

; add EDR agents for all Windows domain machines
[edr_agents:children]
domain
EOF

cat > ansible/install.yml << 'EOF'
# Elastic Stack and Fleet Server Installation
- name: Install Elastic Stack and Fleet Server
  hosts: elastic_stack
  become: yes
  roles:
    - { role: 'elastic_stack', tags: 'elastic' }

# Install EDR agents on Windows VMs
- name: Install Elastic Defend agents on Windows VMs
  hosts: edr_agents
  roles:
    - { role: 'elastic_defend_windows', tags: 'edr-agent' }
EOF

cat > providers/virtualbox/Vagrantfile << 'EOF'
boxes.append(
    { :name => "ELK-EDR",
      :ip => "{{ip_range}}.50",
      :box => "bento/ubuntu-22.04",
      :os => "linux",
      :cpus => 4,                    # Increased for Elastic Stack + Fleet
      :mem => 8192,                  # 8GB RAM for Elastic Stack + Fleet Server
      :forwarded_port => [ 
        {:guest => 22, :host => 2210, :id => "ssh"},
        {:guest => 5601, :host => 5601, :id => "kibana"},      # Kibana Web UI
        {:guest => 9200, :host => 9200, :id => "elasticsearch"}, # Elasticsearch API
        {:guest => 8220, :host => 8220, :id => "fleet"}         # Fleet Server
      ]
    }
)
EOF

echo ""
echo "🎉 =============================================="
echo "   EDR Extension Setup Complete!"
echo "🎉 =============================================="
echo ""
echo "✅ Created backup at: ../elk-backup"
echo "✅ New roles: elastic_stack, elastic_defend_windows"
echo "✅ Updated: extension.json, inventory, install.yml, Vagrantfile"
echo "✅ Added disk space checks and error handling"
echo "✅ Fixed Fleet Server installation sequence"
echo "✅ Added proper timing and retry logic"
echo "✅ Included firewall configuration"
echo "✅ Enhanced Windows agent error handling"
echo ""
echo "🚀 Ready for installation!"
echo "🌐 After install, access Kibana at: http://localhost:5601"
echo "🔐 Default credentials: elastic/changeme"
echo ""
echo "⚠️  IMPORTANT: Ensure your host has at least 12GB RAM"
echo "    (8GB for VM + 4GB for host OS and VirtualBox)"
