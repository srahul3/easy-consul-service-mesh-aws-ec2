# consul-up-and-running-ec2
Easy way to make consul up and running using few CLI steps. Includes the API Gateway setup and demo API service.


```sh
#!/bin/bash

#_________________________AWS SECURITY GRP CONFIGURATION________________________________

IPv4  Custom TCP  TCP 22000 0.0.0.0/0 sidecar port
IPv4  Custom TCP  TCP 8300  0.0.0.0/0 –
IPv4  Custom TCP  TCP 8500  0.0.0.0/0 UI
IPv4  HTTP  TCP 80  0.0.0.0/0 –
IPv4  Custom TCP  TCP 19000 0.0.0.0/0 envoy
IPv4  Custom TCP  TCP 8503  0.0.0.0/0 gRPC
IPv4  Custom TCP  TCP 8443  0.0.0.0/0 api-gw
IPv4  SSH TCP 22  0.0.0.0/0 –
IPv4  Custom TCP  TCP 8301  0.0.0.0/0 –
IPv4  Custom TCP  TCP 8302  0.0.0.0/0 –

#______________________________SEVER AGENT___________________________

#Create EC2 instance with RSA, amazon linux, public-api, a dedicated VPC with IGW, Pub/Pvt key, security group
chmod 400 "ec2-keys-consul-hardway.pem"
ssh -i "ec2-keys-consul-hardway.pem" ec2-user@ec2-54-245-13-56.us-west-2.compute.amazonaws.com

# installing consul
sudo yum install -y yum-utils shadow-utils && \
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo && \
sudo yum -y install consul

cd /etc/consul.d/ && sudo mkdir ./certs && cd ./certs
sudo consul tls ca create
sudo consul tls cert create -server -dc dc1

[ec2-user@ip-10-0-17-253 certs]$ ls
consul-agent-ca-key.pem  consul-agent-ca.pem  dc1-server-consul-0-key.pem  dc1-server-consul-0.pem

# generating time based UUID which can be used as root secret-id/token
[ec2-user@ip-10-0-17-253 ~]$ uuidgen
a234daab-bfd1-cbd3-1f83-abf24e094b39

cd /etc/consul.d/ && sudo rm ./consul.hcl
sudo tee ./consul.hcl<<EOF
datacenter = "dc1"
bootstrap_expect=1
data_dir = "/opt/consul"
log_level = "INFO"
node_name = "server-hardway"
client_addr = "0.0.0.0"
server = true
advertise_addr = "{{ GetInterfaceIP \"enX0\" }}"
ui_config{
  enabled = true
}
enable_central_service_config = true

connect {
    enabled = true
}

ca_file = "/etc/consul.d/certs/consul-agent-ca.pem"

cert_file = "/etc/consul.d/certs/dc1-server-consul-0.pem"
key_file = "/etc/consul.d/certs/dc1-server-consul-0-key.pem"

auto_encrypt = {
    allow_tls = true
}

ports {
    https = 8501
    grpc_tls = 8503
}

verify_incoming_rpc = true
verify_outgoing = true
verify_server_hostname = true
acl {
    enabled = true
    default_policy = "deny"
    down_policy = "extend-cache"
    enable_token_persistence = true
    tokens = {
        master = "a234daab-bfd1-cbd3-1f83-abf24e094b39"
        agent = "a234daab-bfd1-cbd3-1f83-abf24e094b39"
    }
}
EOF

# start the server
sudo systemctl start consul

# ACL token or secret id
export CONSUL_HTTP_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39

# After client is setup
[ec2-user@ip-10-0-22-216 consul.d]$ consul members
Node            Address           Status  Type    Build   Protocol  DC   Partition  Segment
server-hardway  10.0.22.216:8301  alive   server  1.17.3  2         dc1  default    <all>
client-hardway  10.0.19.172:8301  alive   client  1.17.3  2         dc1  default    <default>

#consul acl token create -description "client-hardway agent token" \
#  -node-identity "client-hardway:dc1"


#______________________________CLIENT AGENT___________________________
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list && \
sudo apt update && sudo apt install consul

echo -e "CONSUL_HTTP_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39
CONSUL_AGENT_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39
CONSUL_DNS_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39" | sudo tee -a /etc/consul.d/consul.env

cd /etc/consul.d/ && sudo rm ./consul.hcl
sudo tee ./consul.hcl<<EOF
datacenter = "dc1"
data_dir = "/opt/consul"
log_level = "INFO"
node_name = "client-hardway"
client_addr = "0.0.0.0"
server = false
advertise_addr = "{{ GetInterfaceIP \"eth0\" }}"
advertise_reconnect_timeout = "15m"
retry_join = ["10.0.17.253"]
acl {
  enabled = true
  default_policy = "deny"
  down_policy = "async-cache"
  tokens {
    agent  = "a234daab-bfd1-cbd3-1f83-abf24e094b39"
  }
  enable_token_replication = false
}
ports {
    grpc = 8502
}
connect {
    enabled = true
}

addresses = {
  dns = "127.0.0.1"
  grpc = "127.0.0.1"
  http = "127.0.0.1"
}

enable_central_service_config = true
leave_on_terminate = true
auto_encrypt = {
  tls = true
  ip_san = ["{{ GetInterfaceIP \"eth0\" }}"]
}
ca_file = "/etc/consul.d/consul/consul-agent-ca.pem"
verify_outgoing = true
EOF

export CONSUL_HTTP_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39


# start the server
sudo systemctl start consul

#____________________________STARTING API SERVICE______________________
#use same EC2 instance as above

sudo curl -LO https://github.com/nicholasjackson/fake-service/releases/download/v0.26.2/fake_service_linux_amd64.zip


# Optional step if unzip is not available
sudo apt install unzip

# unzip the application
unzip fake_service_linux_amd64.zip


sudo mv ./fake-service /usr/local/bin/ && \
chmod a+x /usr/local/bin/fake-service && \
which fake-service
/usr/local/bin/fake-service


# test and terminate the process
ubuntu@ip-10-0-25-28:~$ NAME=api fake-service
2024-02-17T08:50:30.670Z [INFO]  Using seed: seed=1708159830
2024-02-17T08:50:30.670Z [INFO]  Adding handler for UI static files
2024-02-17T08:50:30.670Z [INFO]  Settings CORS options: allow_creds=false allow_headers="Accept,Accept-Language,Content-Language,Origin,Content-Type" allow_origins="*"
2024-02-17T08:50:30.671Z [INFO]  Started service: name=api upstreamURIs="" upstreamWorkers=1 listenAddress=0.0.0.0:9090
^C2024/02/17 08:50:40 Graceful shutdown, got signal: interrupt
ubuntu@ip-10-0-25-28:~$

# lets move this false service to systemd
sudo tee /etc/systemd/system/api.service<<EOF
[Unit]
Description=API
After=syslog.target network.target

[Service]
Environment="MESSAGE=Hello from api!"
Environment="NAME=api"
ExecStart=/usr/local/bin/fake-service
ExecStop=/bin/sleep 5
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl start api && \
sudo systemctl status api
● api.service - API
     Loaded: loaded (/etc/systemd/system/api.service; disabled; vendor preset: enabled)
     Active: active (running) since Sat 2024-02-17 09:07:55 UTC; 6s ago
   Main PID: 2522 (fake-service)
      Tasks: 6 (limit: 1121)
     Memory: 1.7M
        CPU: 4ms
     CGroup: /system.slice/api.service
             └─2522 /usr/local/bin/fake-service

Feb 17 09:07:55 ip-10-0-25-28 systemd[1]: Started API.
Feb 17 09:07:55 ip-10-0-25-28 fake-service[2522]: 2024-02-17T09:07:55.634Z [INFO]  Using seed: seed=1708160875
Feb 17 09:07:55 ip-10-0-25-28 fake-service[2522]: 2024-02-17T09:07:55.634Z [INFO]  Adding handler for UI static files
Feb 17 09:07:55 ip-10-0-25-28 fake-service[2522]: 2024-02-17T09:07:55.635Z [INFO]  Settings CORS options: allow_creds=false allow_headers="Accept,Accept-Language,Content-Language,Origin,Content-Type" allow_origins="*"
Feb 17 09:07:55 ip-10-0-25-28 fake-service[2522]: 2024-02-17T09:07:55.635Z [INFO]  Started service: name=api upstreamURIs="" upstreamWorkers=1 listenAddress=0.0.0.0:9090

ubuntu@ip-10-0-25-28:~$ curl localhost:9090
{
  "name": "api",
  "uri": "/",
  "type": "HTTP",
  "ip_addresses": [
    "10.0.25.28"
  ],
  "start_time": "2024-02-17T09:09:59.839627",
  "end_time": "2024-02-17T09:09:59.839860",
  "duration": "232.885µs",
  "body": "Hello from api!",
  "code": 200
}

#----------------------------REGISTERING THE API SERVICE---------------------
cd /etc/consul.d/ && \
sudo tee ./api.hcl<<EOF
service {
   name = "api"
   port = 9090

   connect {
      sidecar_service {
        port = 22000
      }
   }
}
EOF

consul reload && \
consul services register ./api.hcl

# installing envoy
sudo mkdir /tmp/envoy && cd /tmp/envoy && \
sudo wget https://archive.tetratelabs.io/envoy/download/v1.27.2/envoy-v1.27.2-linux-amd64.tar.xz && \
sudo tar -xf envoy-v1.27.2-linux-amd64.tar.xz && \
sudo chmod +x envoy-v1.27.2-linux-amd64/bin/envoy && \
sudo mv envoy-v1.27.2-linux-amd64/bin/envoy /usr/bin/envoy && \
sudo rm -rf envoy-v1.27.2-linux-amd64.tar.xz envoy-v1.27.2-linux-amd64


consul connect envoy -sidecar-for api -admin-bind 127.0.0.1:19001 -token a234daab-bfd1-cbd3-1f83-abf24e094b39 >envoy.log 2>&1 &


#----------------------------REGISTERING THE API GATEWAY NEW---------------------
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list && \
sudo apt update && sudo apt install consul

echo -e "CONSUL_HTTP_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39
CONSUL_AGENT_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39
CONSUL_DNS_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39" | sudo tee -a /etc/consul.d/consul.env

export CONSUL_HTTP_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39

cd /etc/consul.d/ && sudo rm ./consul.hcl
sudo tee ./consul.hcl<<EOF
datacenter = "dc1"
data_dir = "/opt/consul"
log_level = "INFO"
node_name = "gw-hardway"
client_addr = "0.0.0.0"
server = false
advertise_addr = "{{ GetInterfaceIP \"eth0\" }}"
advertise_reconnect_timeout = "15m"
retry_join = ["10.0.17.253"]
acl {
  enabled = true
  default_policy = "deny"
  down_policy = "async-cache"
  tokens {
    agent  = "a234daab-bfd1-cbd3-1f83-abf24e094b39"
  }
  enable_token_replication = false
}
ports {
    grpc = 8502
}
connect {
    enabled = true
}

addresses = {
  dns = "127.0.0.1"
  grpc = "127.0.0.1"
  http = "127.0.0.1"
}

enable_central_service_config = true
leave_on_terminate = true
auto_encrypt = {
  tls = true
  ip_san = ["{{ GetInterfaceIP \"eth0\" }}"]
}
ca_file = "/etc/consul.d/certs/consul-agent-ca.pem"
verify_outgoing = true
EOF

ubuntu@ip-10-0-19-172:/etc/consul.d$ sudo systemctl start consul

sudo mkdir /tmp/envoy && cd /tmp/envoy && \
sudo wget https://archive.tetratelabs.io/envoy/download/v1.27.2/envoy-v1.27.2-linux-amd64.tar.xz && \
sudo tar -xf envoy-v1.27.2-linux-amd64.tar.xz && \
sudo chmod +x envoy-v1.27.2-linux-amd64/bin/envoy && \
sudo mv envoy-v1.27.2-linux-amd64/bin/envoy /usr/bin/envoy && \
sudo rm -rf envoy-v1.27.2-linux-amd64.tar.xz envoy-v1.27.2-linux-amd64

# creating proxy default
sudo tee ./proxy-default.hcl<<EOF
Kind      = "proxy-defaults"
Name      = "global"
Config {
  protocol = "http"
}
EOF
consul config write proxy-default.hcl

# https://developer.hashicorp.com/consul/docs/connect/gateways/api-gateway/deploy/listeners-vms
sudo tee ./gateway.hcl<<EOF
Kind = "api-gateway"
Name = "my-api-gateway"

// Each listener configures a port which can be used to access the Consul cluster
Listeners = [
    {
        Port = 8443
        Name = "my-http-listener"
        Protocol = "http"
    }
]
EOF

consul config write gateway.hcl


sudo tee ./my-http-route.hcl<<EOF
Kind = "http-route"
Name = "my-http-route"

// Rules define how requests will be routed
Rules = [
  // Send all requests that start with the path `/api` to the API service
  {
    Matches = [
      {
        Path = {
          Match = "prefix"
          Value = "/api"
        }
      }
    ]
    Services = [
      {
        Name = "api"
      }
    ]
  }
]

Parents = [
  {
    Kind = "api-gateway"
    Name = "my-api-gateway"
    SectionName = "my-http-listener"
  }
]
EOF

consul config write my-http-route.hcl

# Setup intentions
Use intentions UI to allow the traffic from api-gw to api

# start API GW
sudo consul connect envoy -gateway api -register -service my-api-gateway -admin-bind 0.0.0.0:19000 -token a234daab-bfd1-cbd3-1f83-abf24e094b39 -- --log-level debug >envoy.log 2>&1 &
# API gw Envoy config page
http://ec2-52-32-143-55.us-west-2.compute.amazonaws.com:19000/

# Accessing API via API gateway
http://ec2-52-32-143-55.us-west-2.compute.amazonaws.com:8443/api
{
  "name": "api",
  "uri": "/api",
  "type": "HTTP",
  "ip_addresses": [
    "10.0.21.44"
  ],
  "start_time": "2024-02-21T12:56:35.978390",
  "end_time": "2024-02-21T12:56:35.978497",
  "duration": "106.539µs",
  "body": "Hello from api!",
  "code": 200
}
```
