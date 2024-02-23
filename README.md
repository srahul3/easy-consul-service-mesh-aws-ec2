# Consul Service Mesh up-and-running

![alt text](https://skillicons.dev/icons?i=aws) <img src="https://github.com/srahul3/easy-consul-service-mesh-aws-ec2/assets/17195847/993748ef-06c6-461b-b514-87126772694a" width="40" height="40"> <img src="https://github.com/srahul3/easy-consul-service-mesh-aws-ec2/assets/17195847/13fa5e4d-f7dd-4140-9c76-3b8a84d997dd" width="40" height="40"> 

Easy step by step guide to setup the **Consul Service Mesh** on AWS EC2 instance(VM). For demo purpose we will also setup the folowing workload
- `Consul API Gateway` Read more [here](https://developer.hashicorp.com/consul/docs/connect/gateways/api-gateway).
- `API Service` A JSON API service, which makes upstream call to the `Payment` service and returns the JSON response.
- `Payment Service`. A JSON API service which return JSON response. 

## Topology

```mermaid
flowchart LR

A[User] -->|http://public-ip-or-dns:8443/api| B(API-Gateway:8443)
B --> C{HTTP Route}
C -->|/api| D[API-Service-Proxy:22000]
C -->|/| E[Not Handed]
D --> F[API Service]
F --> G[Payment-Service-Proxy:22000]
G --> H[Payment Service]
```

User calls the public address of API Gateway running on port 8443, the API API Gateway is consfigured with HTTP Routes which routes the `http://<public-ip-or-dns>:8443/api` to `API Service` and later `API Service` calls `Payment Service`.

### Prerequisite
- VPC : A dedicated VPC with public subnets configured with IGW.
- Security Group : A dedicated EC2 security group with below inbound rules
- EC2 Instance :
  - One instances(Amazon Linux, Above mentioned VPC and Security group, Public IP). I named the instances as `consul-server`
  - Three instances(Ubuntu, Above mentioned VPC and Security group, Public IP).. I named the instances as follows `consul-api`, `consul-payment`, `consul-api-gw`

Inbound port rules
```
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
```

#### Setup Consul Server
For this demo we will ignore the redundancy and high-availablity and work with one server instance only.

```sh
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

# generating root token/secret id
sudo uuidgen
a234daab-bfd1-cbd3-1f83-abf24e094b39

[ec2-user@ip-10-0-17-253 certs]$ ls
consul-agent-ca-key.pem  consul-agent-ca.pem  dc1-server-consul-0-key.pem  dc1-server-consul-0.pem

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

#consul acl token create -description "client-hardway agent token" \
#  -node-identity "client-hardway:dc1"
```

#### Payment Service
```sh
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list && \
sudo apt update && sudo apt install consul

echo -e "CONSUL_HTTP_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39
CONSUL_AGENT_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39
CONSUL_DNS_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39" | sudo tee -a /etc/consul.d/consul.env

# Note tag base retry join is recommened but required additional AWS permission of ec2 instance describe, hence for beginners lets hardcode the server IP for now
#retry_join = ["provider=aws tag_key=Name tag_value=consul-server-hardway"]

cd /etc/consul.d/ && sudo rm ./consul.hcl
sudo tee ./consul.hcl<<EOF
datacenter = "dc1"
data_dir = "/opt/consul"
log_level = "INFO"
node_name = "client-payment-hardway"
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

export CONSUL_HTTP_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39

sudo mkdir certs && cd certs && sudo vi consul-agent-ca.pem
# paste the ca certificate

# start the server
sudo systemctl start consul

# Payment Service: STEP 2
cd /tmp && \
sudo curl -LO https://github.com/nicholasjackson/fake-service/releases/download/v0.26.2/fake_service_linux_amd64.zip


# Optional step if unzip is not available
sudo apt install unzip

# unzip the application
unzip fake_service_linux_amd64.zip


sudo mv ./fake-service /usr/local/bin/ && \
sudo chmod a+x /usr/local/bin/fake-service && \
which fake-service
/usr/local/bin/fake-service

# lets move this false service to systemd
sudo tee /etc/systemd/system/payment.service<<EOF
[Unit]
Description=PAYMENT
After=syslog.target network.target

[Service]
Environment="MESSAGE=Hello from payment!"
Environment="NAME=payment"
ExecStart=/usr/local/bin/fake-service
ExecStop=/bin/sleep 5
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl start payment && \
sudo systemctl status payment
● payment.service - PAYMENT
     Loaded: loaded (/etc/systemd/system/apyment.service; disabled; vendor preset: enabled)
     Active: active (running) since Sat 2024-02-17 09:07:55 UTC; 6s ago
   Main PID: 2522 (fake-service)
      Tasks: 6 (limit: 1121)
     Memory: 1.7M
        CPU: 4ms
     CGroup: /system.slice/payment.service
             └─2522 /usr/local/bin/fake-service

Feb 17 09:07:55 ip-10-0-25-28 systemd[1]: Started PAYMENT.
Feb 17 09:07:55 ip-10-0-25-28 fake-service[2522]: 2024-02-17T09:07:55.634Z [INFO]  Using seed: seed=1708160875
Feb 17 09:07:55 ip-10-0-25-28 fake-service[2522]: 2024-02-17T09:07:55.634Z [INFO]  Adding handler for UI static files
Feb 17 09:07:55 ip-10-0-25-28 fake-service[2522]: 2024-02-17T09:07:55.635Z [INFO]  Settings CORS options: allow_creds=false allow_headers="Accept,Accept-Language,Content-Language,Origin,Content-Type" allow_origins="*"
Feb 17 09:07:55 ip-10-0-25-28 fake-service[2522]: 2024-02-17T09:07:55.635Z [INFO]  Started service: name=api upstreamURIs="" upstreamWorkers=1 listenAddress=0.0.0.0:9090

ubuntu@ip-10-0-25-28:~$ curl localhost:9090
{
  "name": "payment",
  "uri": "/",
  "type": "HTTP",
  "ip_addresses": [
    "10.0.25.28"
  ],
  "start_time": "2024-02-17T09:09:59.839627",
  "end_time": "2024-02-17T09:09:59.839860",
  "duration": "232.885µs",
  "body": "Hello from payment!",
  "code": 200
}

# Payment Service: STEP 3
cd /etc/consul.d/ && \
sudo tee ./payment.hcl<<EOF
service {
   name = "payment"
   port = 9090

   connect {
      sidecar_service {
        port = 22000
      }
   }
}
EOF

consul reload && \
consul services register ./payment.hcl

# Payment Service: STEP 2

# installing envoy
sudo mkdir /tmp/envoy && cd /tmp/envoy && \
sudo wget https://archive.tetratelabs.io/envoy/download/v1.27.2/envoy-v1.27.2-linux-amd64.tar.xz && \
sudo tar -xf envoy-v1.27.2-linux-amd64.tar.xz && \
sudo chmod +x envoy-v1.27.2-linux-amd64/bin/envoy && \
sudo mv envoy-v1.27.2-linux-amd64/bin/envoy /usr/bin/envoy && \
sudo rm -rf envoy-v1.27.2-linux-amd64.tar.xz envoy-v1.27.2-linux-amd64

sudo tee /etc/systemd/system/payment-sidecar.service<<EOF
[Unit]
Description="Payment sidecar proxy service"
Requires=network-online.target
After=network-online.target

[Service]
ExecStart=consul connect envoy -sidecar-for payment -admin-bind 127.0.0.1:19001 -token a234daab-bfd1-cbd3-1f83-abf24e094b39
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# OR IF you want to run manually use below commented command
# consul connect envoy -sidecar-for api -admin-bind 127.0.0.1:19001 -token a234daab-bfd1-cbd3-1f83-abf24e094b39 >envoy.log 2>&1 &

sudo systemctl enable payment-sidecar
Created symlink /etc/systemd/system/multi-user.target.wants/payment-sidecar.service → /etc/systemd/system/payment-sidecar.service.

sudo systemctl start payment-sidecar

```

#### API Service
```sh

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
node_name = "api-service"
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

export CONSUL_HTTP_TOKEN=a234daab-bfd1-cbd3-1f83-abf24e094b39

sudo mkdir certs && cd certs && sudo vi consul-agent-ca.pem
# paste the ca certificate

# start the server
sudo systemctl start consul

# API service: STEP 2
sudo curl -LO https://github.com/nicholasjackson/fake-service/releases/download/v0.26.2/fake_service_linux_amd64.zip


# Optional step if unzip is not available
sudo apt install unzip

# unzip the application
unzip fake_service_linux_amd64.zip


sudo mv ./fake-service /usr/local/bin/ && \
chmod a+x /usr/local/bin/fake-service && \
which fake-service
/usr/local/bin/fake-service


# OPTIONAL: test and terminate the process
ubuntu@ip-10-0-25-28:~$ NAME=api UPSTREAM_URIS=http://<private-ip-of-payments>:9090 fake-service
2024-02-22T08:18:25.836Z [INFO]  Using seed: seed=1708589905
2024-02-22T08:18:25.837Z [INFO]  Adding handler for UI static files
2024-02-22T08:18:25.837Z [INFO]  Settings CORS options: allow_creds=false allow_headers="Accept,Accept-Language,Content-Language,Origin,Content-Type" allow_origins="*"
2024-02-22T08:18:25.837Z [INFO]  Started service: name=api upstreamURIs=http://10.0.20.173:9090 upstreamWorkers=1 listenAddress=0.0.0.0:9090
2024-02-22T08:19:11.477Z [INFO]  Handle inbound request:
  request=
  | GET / HTTP/1.1
  | Host: localhost:9090
  | user-agent: curl/7.81.0
  | accept: */*
  
2024-02-22T08:19:11.478Z [INFO]  Calling upstream service: uri=http://10.0.20.173:9090 type=HTTP
  request=
  | GET http://10.0.20.173:9090 HTTP/1.1
  | Host: 10.0.20.173:9090
  
2024-02-22T08:19:11.480Z [INFO]  Finished handling request: duration=3.333397ms


# lets move this false service to systemd
sudo tee /etc/systemd/system/api.service<<EOF
[Unit]
Description=API
After=syslog.target network.target

[Service]
Environment="MESSAGE=Hello from api!"
Environment="NAME=api"
Environment="UPSTREAM_URIS=http://localhost:6001"
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

# API service: STEP 3
cd /etc/consul.d/ && \
sudo tee ./api.hcl<<EOF
service {
   name = "api"
   port = 9090

   connect {
      sidecar_service {
        port = 22000

        proxy = {
          upstreams = [
            {
              # mapping a service to the local port so that it can be accessed via http://localhost:6001
              # proxy port 6001 to the payment service.
              destination_name = "payment"
              local_bind_port  = 6001
            }
          ]
        }
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

# adding sidecar to systemd
sudo tee /etc/systemd/system/api-sidecar.service<<EOF
[Unit]
Description="API sidecar proxy service"
Requires=network-online.target
After=network-online.target

[Service]
ExecStart=consul connect envoy -sidecar-for api -admin-bind 127.0.0.1:19001 -token a234daab-bfd1-cbd3-1f83-abf24e094b39
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# OR IF you want to run manually use below commented command
# consul connect envoy -sidecar-for api -admin-bind 127.0.0.1:19001 -token a234daab-bfd1-cbd3-1f83-abf24e094b39 >envoy.log 2>&1 &

sudo systemctl enable api-sidecar
->Created symlink /etc/systemd/system/multi-user.target.wants/api-sidecar.service → /etc/systemd/system/api-sidecar.service.
sudo systemctl start api-sidecar

# manually running the sidecar
# consul connect envoy -sidecar-for api -admin-bind 127.0.0.1:19001 -token a234daab-bfd1-cbd3-1f83-abf24e094b39 >envoy.log 2>&1 &

ubuntu@ip-10-0-25-28:~$ curl localhost:9090
{
  "name": "api",
  "uri": "/api",
  "type": "HTTP",
  "ip_addresses": [
    "10.0.23.207"
  ],
  "start_time": "2024-02-22T10:19:00.339344",
  "end_time": "2024-02-22T10:19:00.345556",
  "duration": "6.212343ms",
  "body": "Hello from api!",
  "upstream_calls": {
    "http://localhost:6001": {
      "name": "payment",
      "uri": "http://localhost:6001",
      "type": "HTTP",
      "ip_addresses": [
        "10.0.20.173"
      ],
      "start_time": "2024-02-22T10:19:00.342999",
      "end_time": "2024-02-22T10:19:00.343131",
      "duration": "131.644µs",
      "headers": {
        "Content-Length": "268",
        "Content-Type": "text/plain; charset=utf-8",
        "Date": "Thu, 22 Feb 2024 10:19:00 GMT",
        "Server": "envoy",
        "X-Envoy-Upstream-Service-Time": "3"
      },
      "body": "Hello from payment!",
      "code": 200
    }
  },
  "code": 200
}


```

#### Consul API Gateway
```sh

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
node_name = "api-gw-0"
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

sudo mkdir certs && cd certs && sudo vi consul-agent-ca.pem
# paste the ca certificate

ubuntu@ip-10-0-19-172:/etc/consul.d$ sudo systemctl start consul

sudo mkdir /tmp/envoy && cd /tmp/envoy && \
sudo wget https://archive.tetratelabs.io/envoy/download/v1.27.2/envoy-v1.27.2-linux-amd64.tar.xz && \
sudo tar -xf envoy-v1.27.2-linux-amd64.tar.xz && \
sudo chmod +x envoy-v1.27.2-linux-amd64/bin/envoy && \
sudo mv envoy-v1.27.2-linux-amd64/bin/envoy /usr/bin/envoy && \
sudo rm -rf envoy-v1.27.2-linux-amd64.tar.xz envoy-v1.27.2-linux-amd64

cd /etc/consul.d/ && sudo mkdir gw && cd gw

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

# adding sidecar to systemd
sudo tee /etc/systemd/system/api-gw.service<<EOF
[Unit]
Description="Consul API gateway"
Requires=network-online.target
After=network-online.target

[Service]
ExecStart=consul connect envoy -gateway api -register -service my-api-gateway -admin-bind 0.0.0.0:19000 -token a234daab-bfd1-cbd3-1f83-abf24e094b39
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable api-gw
sudo systemctl start api-gw

# manually starting the API GW for debugging
# sudo consul connect envoy -gateway api -register -service my-api-gateway -admin-bind 0.0.0.0:19000 -token a234daab-bfd1-cbd3-1f83-abf24e094b39 -- --log-level debug >envoy.log 2>&1 &

# API gw Envoy config page
http://ec2-52-32-143-55.us-west-2.compute.amazonaws.com:19000/

# Accessing API via API gateway
http://ec2-52-32-143-55.us-west-2.compute.amazonaws.com:8443/api
// 20240222141444
// http://ec2-52-32-143-55.us-west-2.compute.amazonaws.com:8443/api

{
  "name": "api",
  "uri": "/api",
  "type": "HTTP",
  "ip_addresses": [
    "10.0.23.207"
  ],
  "start_time": "2024-02-22T08:44:44.564314",
  "end_time": "2024-02-22T08:44:44.571113",
  "duration": "6.799286ms",
  "body": "Hello from api!",
  "upstream_calls": {
    "http://localhost:6001": {
      "name": "payment",
      "uri": "http://localhost:6001",
      "type": "HTTP",
      "ip_addresses": [
        "10.0.20.173"
      ],
      "start_time": "2024-02-22T08:44:44.568366",
      "end_time": "2024-02-22T08:44:44.568508",
      "duration": "141.563µs",
      "headers": {
        "Content-Length": "268",
        "Content-Type": "text/plain; charset=utf-8",
        "Date": "Thu, 22 Feb 2024 08:44:44 GMT",
        "Server": "envoy",
        "X-Envoy-Upstream-Service-Time": "3"
      },
      "body": "Hello from payment!",
      "code": 200
    }
  },
  "code": 200
}
```

#### Intentions expectations
```sh
ubuntu@ip-10-0-16-210:~$ consul intention list
ID  Source          Action  Destination  Precedence
    api             allow   payment      9
    my-api-gateway  allow   api          9
```

#### Useful commands
```sh
curl -H "Authorization: Bearer a234daab-bfd1-cbd3-1f83-abf24e094b39" http://localhost:8500/v1/operator/autopilot/health | jq
curl -H "Authorization: Bearer a234daab-bfd1-cbd3-1f83-abf24e094b39" http://localhost:8500/v1/agent/metrics | jq

ubuntu@ip-10-0-16-210:~$ consul members
Node                    Address           Status  Type    Build   Protocol  DC   Partition  Segment
server-hardway          10.0.17.253:8301  alive   server  1.17.3  2         dc1  default    <all>
api-gw-0                10.0.16.210:8301  alive   client  1.17.3  2         dc1  default    <default>
api-service             10.0.23.207:8301  alive   client  1.17.3  2         dc1  default    <default>
client-payment-hardway  10.0.20.173:8301  alive   client  1.17.3  2         dc1  default    <default>

ubuntu@ip-10-0-16-210:~$ consul catalog services
api
api-sidecar-proxy
consul
my-api-gateway
payment
payment-sidecar-proxy

ubuntu@ip-10-0-16-210:~$ consul intention list
ID  Source          Action  Destination  Precedence
    api             allow   payment      9
    my-api-gateway  allow   api          9

```
