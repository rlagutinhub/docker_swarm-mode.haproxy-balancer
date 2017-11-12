## Docker: docker_swarm-mode.haproxy-balancer

Compiled Docker image: https://hub.docker.com/r/rlagutinhub/docker_swarm-mode.haproxy-balancer/

-	HAproxy image that autoreconfigures itself when used in Docker Swarm Mode.
	HAProxy image that balances between network attachments (not linked) tasks of services and
	reconfigures itself when a docker swarm cluster member redeploys, joins or leaves.
-	Base image centos:latest

#### Docker SDK
- https://docker-py.readthedocs.io
- https://github.com/docker/docker-py
- https://docs.docker.com/develop/sdk/
- https://pypi.python.org/pypi/docker/

Requirements:
- pip3 install -U docker
- pip3 install -U Jinja2
- pip3 install -U pyOpenSSL

Tested:
- Docker Engine 17.09.0-ce
- docker (2.5.1)
- Jinja2 (2.9.6)
- pyOpenSSL (17.3.0)

Docker SDK Example:

```console
import json
import docker

# client = docker.from_env()
client = docker.DockerClient(base_url='unix://var/run/docker.sock')

client.services.list()
[<Service: ww2hfyddw3>, <Service: yq45gxwxhl>]

srv = client.services.get('yq45gxwxhl')
srv.name
srv.attrs
srv.tasks()
print(json.dumps(srv.tasks(), indent=4))

client.networks.list()
net =  client.networks.get('xjaz5s7r5x')
net.name
net.attrs
```

#### Build Image

```console
git clone https://github.com/rlagutinhub/docker_swarm-mode.haproxy-balancer.git
cd docker_swarm-mode.haproxy-balancer
```

Docker Image:

```console
docker build -t rlagutinhub/docker_swarm-mode.haproxy-balancer:201711121545 .
```

#### Network:

```console
docker network create -d overlay haproxy-balancer_prod
```

#### HAPROXY-BALANCER:

Create haproxy-balancer
- Run only on the node manager!!!
- The --endpoint-mode dnsrr not support!!!

```console
docker service create --detach=false \
 --name haproxy-balancer \
 --network haproxy-balancer_prod \
 --mount target=/var/run/docker.sock,source=/var/run/docker.sock,type=bind \
 --mode global \
 --constraint "node.role == manager" \
 rlagutinhub/docker_swarm-mode.haproxy-balancer:201711121545
```

enable autconfigure haproxy-balancer

```console
docker service update --detach=false haproxy-balancer \
 --label-add "com.example.proxy=true"
```

custom default settings haproxy-balancer

```console
docker service update --detach=false haproxy-balancer \
 --label-add "com.example.def_log_server=127.0.0.1" \
 --label-add "com.example.def_retries=3" \
 --label-add "com.example.def_timeout_http_request=10s" \
 --label-add "com.example.def_timeout_queue=1m" \
 --label-add "com.example.def_timeout_connect=10s" \
 --label-add "com.example.def_timeout_client=1m" \
 --label-add "com.example.def_timeout_server=1m" \
 --label-add "com.example.def_timeout_http_keep_alive=10s" \
 --label-add "com.example.def_timeout_check=10s" \
 --label-add "com.example.def_maxconn=10000" \
 --label-add "com.example.stats_port=1936" \
 --label-add "com.example.stats_login=root" \
 --label-add "com.example.stats_password=password"
```

custom configure rsyslog server for haproxy
Configure on the server, which is defined in the def_log_server.

```console
vim /etc/rsyslog.conf (uncomment or add)
$ModLoad imudp
$UDPServerRun 514
local2.* /var/log/haproxy.log
```

ssl certificate - https forntend with tcp443 (docker secrets)

```console
cat server.crt server.key > 443.pem
docker secret create haproxy-balancer_201711061830_443.pem 443.pem
docker service update --detach=false \
 --secret-rm haproxy-balancer_OLD_443.pem \
 --secret-add source=haproxy-balancer_201711061830_443.pem,target=/etc/pki/tls/certs/443.pem,mode=0644 \
 haproxy-balancer
```

ssl certificate - https forntend with tcp8443 (docker secrets)

```console
cat server.crt server.key > 8443.pem
docker secret create haproxy-balancer_201711061830_8443.pem 8443.pem
docker service update --detach=false \
 --secret-rm haproxy-balancer_OLD_8443.pem \
 --secret-add source=haproxy-balancer_201711061830_8443.pem,target=/etc/pki/tls/certs/8443.pem,mode=0644 \
 haproxy-balancer
```

####  APP(s) (https://github.com/rlagutinhub/docker_swarm-mode.haproxy-test)

create app

- The --mode Replicated is supported.
- The --mode Global is supported.
- The --endpoint-mode vip is supported.
- The --endpoint-mode dnsrr is supported. Port published with ingress mode can't be used with dnsrr mode!

```console
docker service create --detach=false \
 --name haproxy-test \
 -e PORTS="8080, 8081, 8443, 8444, 10001, 10002" \
 --network haproxy-balancer_prod \
 --constraint "node.role != manager" \
 rlagutinhub/docker_swarm-mode.haproxy-test:201711111920
```

enable autconfigure haproxy-balancer
- It is required to specify the name of the haproxy-balancer service and the common overlay network
that is used for the haproxy-balancer and this application service.

```console
docker service update --detach=false haproxy-test \
 --label-add "com.example.proxy=true" \
 --label-add "com.example.proxy_name=haproxy-balancer" \
 --label-add "com.example.proxy_net=haproxy-balancer_prod"
```

proxy http with sticky session

```console
docker service update --detach=false haproxy-test \
 --label-add "com.example.proxy_http_name1=http-sticky-true.example.com" \
 --label-add "com.example.proxy_http_front1=80" \
 --label-add "com.example.proxy_http_back1=8080" \
 --label-add "com.example.proxy_http_sticky1=true"
```

proxy http without sticky session

```console
docker service update --detach=false haproxy-test \
 --label-add "com.example.proxy_http_name2=http-sticky-false.example.com" \
 --label-add "com.example.proxy_http_front2=80" \
 --label-add "com.example.proxy_http_back2=8081" \
 --label-add "com.example.proxy_http_sticky2=false"
```

proxy https with sticky session

```console
docker service update --detach=false haproxy-test \
 --label-add "com.example.proxy_https_name1=https-sticky-true.example.com" \
 --label-add "com.example.proxy_https_front1=443" \
 --label-add "com.example.proxy_https_back1=8443" \
 --label-add "com.example.proxy_https_sticky1=true"
```

proxy https without sticky session

```console
docker service update --detach=false haproxy-test \
 --label-add "com.example.proxy_https_name2=https-sticky-false.example.com" \
 --label-add "com.example.proxy_https_front2=443" \
 --label-add "com.example.proxy_https_back2=8444" \
 --label-add "com.example.proxy_https_sticky2=false"
```

proxy tcp with sticky session

```console
docker service update --detach=false haproxy-test \
 --label-add "com.example.proxy_tcp_front1=10001" \
 --label-add "com.example.proxy_tcp_back1=10001" \
 --label-add "com.example.proxy_tcp_sticky1=true"
```

proxy tcp without sticky session

```console
docker service update --detach=false haproxy-test \
 --label-add "com.example.proxy_tcp_front2=10002" \
 --label-add "com.example.proxy_tcp_back2=10002" \
 --label-add "com.example.proxy_tcp_sticky2=false"
```

---

![alt text](https://github.com/rlagutinhub/docker_swarm-mode.haproxy-balancer/blob/master/screen.png)
