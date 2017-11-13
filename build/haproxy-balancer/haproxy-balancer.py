#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# NAME:   DOCKER_SWARM-MODE.HAPROXY-BALANCER.PY
# DESC:   HAPROXY IMAGE THAT AUTORECONFIGURES ITSELF WHEN USED IN DOCKER SWARM MODE
# DATE:   13-11-2017
# LANG:   PYTHON 3
# AUTHOR: LAGUTIN R.A.
# EMAIL:  RLAGUTIN@MTA4.RU

# Examples:
#     /usr/bin/python3 /etc/haproxy/haproxy-balancer/haproxy-balancer.py -w (wait/watch for changes)
#     /usr/bin/python3 /etc/haproxy/haproxy-balancer/haproxy-balancer.py -1 (run once)

'''
HAproxy image that autoreconfigures itself when used in Docker Swarm Mode
HAProxy image that balances between network attachments (not linked) tasks of services and
reconfigures itself when a docker swarm cluster member redeploys, joins or leaves.

Important: The names of services, networks, labels should be in lowercase!

Requirements:

    pip3 install -U docker
    pip3 install -U Jinja2
    pip3 install -U pyOpenSSL

Tested:

    Docker Engine 17.09.0-ce
    docker (2.5.1)
    Jinja2 (2.9.6)
    pyOpenSSL (17.3.0)

Docker SDK:

https://docker-py.readthedocs.io
https://github.com/docker/docker-py
https://docs.docker.com/develop/sdk/
https://pypi.python.org/pypi/docker/

Docker SDK Example:

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
'''

import os
import sys
import json
import time
import docker
import socket
import filecmp
import datetime
import subprocess

from OpenSSL import crypto
from shutil import rmtree, copyfile, move
from jinja2 import Environment, FileSystemLoader


# PID File
PID_FILE = '/run/haproxy-balancer.pid'

# Crypto Providers
TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA

# Default Cert Attr
DEFAULT_CERT_ATTR = {
    'CN': 'localhost.localdomain'
}

# DEFAULT_CERT_ATTR = {
#     'C': 'Russian',
#     'ST': 'Moscow',
#     'L': 'Moscow',
#     'O': 'docker_swarm-mode',
#     'OU': 'haproxy-balancer',
#     'CN': '*.example.com'
# }

# Default Cert File
DEFAULT_CERT_FILE = '/etc/pki/tls/certs/default.pem'

# User Cert Dir (default docker secrets)
USER_CERT_DIR = '/etc/pki/tls/certs'

# Const CUR DIR
CUR_DIR = '/'
# CUR_DIR = os.path.dirname(os.path.abspath(__file__))

# LABEL PREF
LABEL_PREF = 'com.example'
# LABEL_PREF = 'local.example'

# Default HAPROXY MAIN
DEF_MAIN_SETTINGS = {
    "def_log_server": "127.0.0.1",
    "def_retries": "3",
    "def_timeout_http_request": "10s",
    "def_timeout_queue": "1m",
    "def_timeout_connect": "10s",
    "def_timeout_client": "1m",
    "def_timeout_server": "1m",
    "def_timeout_http_keep_alive": "10s",
    "def_timeout_check": "10s",
    "def_maxconn": "10000",
    "stats_port": "1936",
    "stats_login": "root",
    "stats_password": "password"
}

# Const CONF TIMEOUT
CONF_TIMEOUT = 60

# Const CONF PATH
CONF_PATH = '/etc/haproxy/haproxy-balancer/conf'

# Const TEMPLATES PATH
TMPL_PATH = '/etc/haproxy/haproxy-balancer/templates'

# Const HAPROXY ORIG
CONF_ORIG = '/etc/haproxy/haproxy.cfg'

# Const HAPROXY OLD
CONF_OLD = CONF_ORIG + '.' + \
    datetime.datetime.now().strftime('%Y%m%d%H%M%S.%f') + '.old'

# Const HAPROXY COMMON
CONF_COMMON = CONF_PATH + '/' + 'haproxy.cfg' + '.' + \
    datetime.datetime.now().strftime('%Y%m%d%H%M%S.%f') + '.new'

# Const HAPROXY RELOAD Script
CONF_RELOAD_SCR = CONF_PATH + '/' + 'haproxy-reload.sh'

# Const HAPROXY RELOAD CMD Line
CONF_RELOAD_CMD_LINE = "/usr/sbin/haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -sf $(pidof 'haproxy' | sort | uniq | sed -r 's/[ ]/, /g')"

# Const HAPROXY MAIN
TMPL_JINJA2_MAIN = TMPL_PATH + '/' + 'haproxy.main.jinja2.cfg'
CONF_JINJA2_MAIN = CONF_PATH + '/' + '01-haproxy.cfg'

# Const HAPROXY HTTP Frontend
TMPL_JINJA2_FRONTEND_HTTP = TMPL_PATH + '/' + 'haproxy.frontend_http.jinja2.cfg'
CONF_JINJA2_FRONTEND_HTTP = CONF_PATH + '/' + '02-haproxy.frontend_http.cfg'

# Const HAPROXY HTTP Backend without sticky
TMPL_JINJA2_BACKEND_HTTP_STICKY_FALSE = TMPL_PATH + '/' + 'haproxy.backend_http.sticky.false.jinja2.cfg'
CONF_JINJA2_BACKEND_HTTP_STICKY_FALSE = CONF_PATH + '/' + '05-haproxy.backend_http.sticky.false.cfg'

# Const HAPROXY HTTP Backend with sticky
TMPL_JINJA2_BACKEND_HTTP_STICKY_TRUE = TMPL_PATH + '/' + 'haproxy.backend_http.sticky.true.jinja2.cfg'
CONF_JINJA2_BACKEND_HTTP_STICKY_TRUE = CONF_PATH + '/' + '08-haproxy.backend_http.sticky.true.cfg'

# Const HAPROXY HTTPS Frontend
TMPL_JINJA2_FRONTEND_HTTPS = TMPL_PATH + '/' + 'haproxy.frontend_https.jinja2.cfg'
CONF_JINJA2_FRONTEND_HTTPS = CONF_PATH + '/' + '03-haproxy.frontend_https.cfg'

# Const HAPROXY HTTPS Backend without sticky
TMPL_JINJA2_BACKEND_HTTPS_STICKY_FALSE = TMPL_PATH + '/' + 'haproxy.backend_https.sticky.false.jinja2.cfg'
CONF_JINJA2_BACKEND_HTTPS_STICKY_FALSE = CONF_PATH + '/' + '06-haproxy.backend_https.sticky.false.cfg'

# Const HAPROXY HTTPS Backend with sticky
TMPL_JINJA2_BACKEND_HTTPS_STICKY_TRUE = TMPL_PATH + '/' + 'haproxy.backend_https.sticky.true.jinja2.cfg'
CONF_JINJA2_BACKEND_HTTPS_STICKY_TRUE = CONF_PATH + '/' + '09-haproxy.backend_https.sticky.true.cfg'

# Const HAPROXY TCP Frontend
TMPL_JINJA2_FRONTEND_TCP = TMPL_PATH + '/' + 'haproxy.frontend_tcp.jinja2.cfg'
CONF_JINJA2_FRONTEND_TCP = CONF_PATH + '/' + '04-haproxy.frontend_tcp.cfg'

# Const HAPROXY TCP Backend without sticky
TMPL_JINJA2_BACKEND_TCP_STICKY_FALSE = TMPL_PATH + '/' + 'haproxy.backend_tcp.sticky.false.jinja2.cfg'
CONF_JINJA2_BACKEND_TCP_STICKY_FALSE = CONF_PATH + '/' + '07-haproxy.backend_tcp.sticky.false.cfg'

# Const HAPROXY TCP Backend with sticky
TMPL_JINJA2_BACKEND_TCP_STICKY_TRUE = TMPL_PATH + '/' + 'haproxy.backend_tcp.sticky.true.jinja2.cfg'
CONF_JINJA2_BACKEND_TCP_STICKY_TRUE = CONF_PATH + '/' + '10-haproxy.backend_tcp.sticky.true.cfg'


class DockerServiceClass(object):

    def __init__(self, srv_id):

        self.srv = client.services.get(srv_id)

    def get_id(self):

        return self.srv.id

    def get_name(self):

        return self.srv.name

    def get_labels(self):

        set_Labels = self.srv.attrs['Spec']['Labels']
        mod_Labels = {(key.strip()).lower(): (value.strip()).lower()
                      for (key, value) in set_Labels.items()}

        return mod_Labels
        # self.srv.attrs['Spec']['Labels']

    def get_mode(self):

        return self.srv.attrs['Spec']['Mode']

    def get_tasks(self):

        col_task = dict()
        net_task = dict()
        col_tasks = list()
        tasks = self.srv.tasks()
        # print(json.dumps(tasks, indent=4))

        if tasks:

            for task in tasks:

                if task['Status']['State'] == 'running':

                    col_task['Timestamp'] = task['Status']['Timestamp']
                    col_task['State'] = task['Status']['State']

                    try:
                        col_task['PID'] = task['Status']['ContainerStatus']['PID']
                    except KeyError:
                        col_task['PID'] = 'None'

                    col_task['ContainerID'] = task['Status']['ContainerStatus']['ContainerID']
                    col_task['NodeID'] = task['NodeID']

                    # mode replicated - container DNS name = srv.name.Slot.ID
                    # mode global - container DNS name = srv.name.NodeID.ID (Slot None)

                    try:
                        col_task['Slot'] = task['Slot']
                    except KeyError:
                        col_task['Slot'] = 'None'

                    col_task['Task_ID'] = task['ID']
                    col_task['Task_Ver'] = task['Version']['Index']

                    col_task['NetworksAttachment'] = []

                    for net in task['NetworksAttachments']:
                        net_task['Net_ID'] = net['Network']['ID']
                        net_task['Net_Index'] = net['Network']['Version']['Index']
                        net_task['Net_Scope'] = net['Network']['Spec']['Scope']
                        net_task['Net_Name'] = net['Network']['Spec']['Name']

                        try:
                            net_task['Net_DrvName'] = net['Network']['Spec']['DriverConfiguration']['Name']
                        except KeyError:
                            net_task['Net_DrvName'] = 'None'

                        net_task['Net_Addr'] = net['Addresses']

                        col_task['NetworksAttachment'].append(net_task.copy())
                        net_task.clear()

                    col_tasks.append(col_task.copy())
                    col_task.clear()

            # print(json.dumps(col_tasks, indent=4))
            return col_tasks

        else:
            return None

    def get_EndpointSpec(self):

        try:
            return self.srv.attrs["Spec"]["EndpointSpec"]

        except KeyError:
            return None   

    def get_Env(self):

        try:
            return self.srv.attrs["Spec"]["TaskTemplate"]["ContainerSpec"]["Env"]

        except KeyError:
            return None

    def get_Image(self):

        return self.srv.attrs["Spec"]["TaskTemplate"]["ContainerSpec"]["Image"]

    def get_Mounts(self):

        try:
            return self.srv.attrs["Spec"]["TaskTemplate"]["ContainerSpec"]["Mounts"]

        except KeyError:
            return None

    def get_Networks(self):

        try:
            return self.srv.attrs["Spec"]["TaskTemplate"]["Networks"]

        except KeyError:
            try:
                return self.srv.attrs["Spec"]["Networks"]

            except KeyError:
                return None

    def get_Constraints(self):

        try:
            return self.srv.attrs["Spec"]["TaskTemplate"]["Placement"]["Constraints"]

        except KeyError:
            return None

    def get_Resources(self):

        return self.srv.attrs["Spec"]["TaskTemplate"]["Resources"]

    def get_Mode(self):

        return self.srv.attrs["Spec"]["Mode"]


class DockerContainerClass(object):

    def __init__(self, cln_id):

        self.cln = self.__check_cln(cln_id)

    def __check_cln(self, cln_id):

        try:
            return client.containers.get(cln_id)

        except docker.errors.APIError:
            return None

    def get_data(self):

        if self.cln:

            service_name = self.cln.attrs['Config']['Labels']['com.docker.swarm.service.name']
            service_id = self.cln.attrs['Config']['Labels']['com.docker.swarm.service.id']

            task_name = self.cln.attrs['Config']['Labels']['com.docker.swarm.task.name']
            task_id = self.cln.attrs['Config']['Labels']['com.docker.swarm.task.id']

            return {'service_name': service_name, 'service_id': service_id, 'task_name': task_name, 'task_id': task_id}

        else:
            return False


class DockerNetworkClass(object):

    def __init__(self, net_id):

        self.net = client.networks.get(net_id)

    def net_id(self):

        return self.net.id

    def net_name(self):

        return self.net.name

    def net_servises(self):

        return self.net.client.services.list()


class bcolors(object):

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def pid_file(pidpath, mode):

    if mode == 'create':
        pid = str(os.getpid())
        with open(pidpath, 'wt') as f:
            f.write(pid)

    elif mode == 'remove':
        os.remove(pidpath)


def createKeyPair(type, bits):
    """
    Create a public/private key pair.

    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey


def createCertRequest(pkey, digest="sha256", **name):
    """
    Create a certificate request.

    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is sha256
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for key, value in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req


def createCertificate(req, issuerCertKey, serial, validityPeriod,
                      digest="sha256"):
    """
    Generate a certificate given a certificate request.

    Arguments: req        - Certificate request to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is sha256
    Returns:   The signed certificate in an X509 object
    """
    issuerCert, issuerKey = issuerCertKey
    notBefore, notAfter = validityPeriod
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert


def gen_default_cert(certpath):

    if os.path.exists(certpath) and os.path.isfile(certpath):
        pass

    else:

        key = createKeyPair(crypto.TYPE_RSA, 2048)
        req = createCertRequest(key, **DEFAULT_CERT_ATTR)
        cert = createCertificate(req, (req, key), 0, (0, 60 * 60 * 24 * 365 * 10))

        # with open('docker_swarm-mode.haproxy-balancer.key', 'w') as private:
        #     private.write(
        #         crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')
        #     )

        # with open('docker_swarm-mode.haproxy-balancer.crt', 'w') as public:
        #     public.write(
        #         crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
        #     )

        with open(certpath, 'w') as pem:
            pem.write(
                crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
            )
            pem.write(
                crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')
            )


def get_hostname():

    return socket.gethostname()


def check_task(values):

    service_name = values['service_name']
    service_id = values['service_id']
    task_name = values['task_name'].split('.')[0]
    task_slot = values['task_name'].split('.')[1]
    task_id = values['task_id']

    srv = DockerServiceClass(service_id)
    tasks = srv.get_tasks()

    slot_col = list()

    for task in tasks:

        slot_col.append(task['Slot'])

    for task in tasks:

        if task['Task_ID'] == task_id:

            get_slot = task['Slot']
            break

    slot_col.sort()

    if str(get_slot) == slot_col[0]:
        return True

    else:
        return False


def check_EndpointSpec(ports):

    ports = list(set(ports))

    hostname = get_hostname()

    if not hostname:
        return False

    cln = DockerContainerClass(hostname)
    cln_data = cln.get_data()

    if not cln_data:
        return False

    if check_task(cln_data):

        service_id = cln_data['service_id']

        if pars_EndpointSpec(service_id, ports):

            new_EndpointSpec = gen_EndpointSpec(ports)
            # print(json.dumps(new_EndpointSpec, indent=4))

            apply_EndpointSpec(service_id, new_EndpointSpec)


def apply_EndpointSpec(srv_id, new_EndpointSpec):

    service = DockerServiceClass(srv_id)

    env = service.get_Env()
    image = service.get_Image()
    name = service.get_name()
    labels = service.get_labels()
    mode = service.get_Mode()
    networks = service.get_Networks()
    mounts = service.get_Mounts()
    constraints = service.get_Constraints()
    resources = service.get_Resources()

    endpoint_spec = new_EndpointSpec

    options = {
        'env': env,
        'image': image,
        'name': name,
        'labels': labels,
        'mode': mode,
        'networks': networks,
        'mounts': mounts,
        'constraints': constraints,
        'endpoint_spec': endpoint_spec,
        'resources': resources
    }

    # print(options)

    try:
        client.services.get(srv_id).update(**options)
        sys.exit(0)

    except docker.errors.APIError as e:
        print('Error', e)


def pars_EndpointSpec(srv_id, ports):

    err_count = 0
    ports = set(ports)

    service = DockerServiceClass(srv_id)
    EndpointSpec = service.get_EndpointSpec()

    if not EndpointSpec:
        return True

    set_PublishedPort = set()
    set_TargetPort = set()

    try:
        if EndpointSpec['Mode'] != 'vip':
            err_count += 1

    except KeyError:
        err_count += 1

    try:
        Ports = EndpointSpec['Ports']

    except KeyError:
        err_count += 1

    if not err_count:

        for Port in Ports:

            for key, value in Port.items():

                if key == 'PublishedPort':
                    set_PublishedPort.add(str(value))

                if key == 'TargetPort':
                    set_TargetPort.add(str(value))

                if key == 'Protocol':
                    if value != 'tcp':
                        err_count += 1

                if key == 'PublishMode':
                    if value != 'ingress':
                        err_count += 1

    diff_PublishedPort_TargetPort = (set_PublishedPort ^ set_TargetPort)
    diff_ports_PublishedPort = (set_PublishedPort ^ ports)
    diff_ports_TargetPort = (set_TargetPort ^ ports)

    # print('diff_PublishedPort_TargetPort:', diff_PublishedPort_TargetPort)
    # print('diff_ports_PublishedPort:', diff_ports_PublishedPort)
    # print('diff_ports_TargetPort:', diff_ports_TargetPort)
    # print('err_count:', err_count)

    if (diff_PublishedPort_TargetPort or diff_ports_PublishedPort or diff_ports_TargetPort or
            err_count):

        # Diff found
        return True

    else:

        # Diff not found
        return False


def gen_EndpointSpec(ports):

# EndpointSpec = {
#     'Mode': 'vip',
#     'Ports': [
#         {
#             'Protocol': 'tcp',
#             'PublishMode': 'ingress',
#             'PublishedPort': 80,
#             'TargetPort': 80
#         },
#         {
#             'Protocol': 'tcp',
#             'PublishMode': 'ingress',
#             'PublishedPort': 443,
#             'TargetPort': 443
#         }
#     ]
# }

    EndpointSpec = dict()
    EndpointSpec_Ports = list()
    EndpointSpec_Ports_tmp = dict()

    for port in ports:

        EndpointSpec_Ports_tmp = {
            'Protocol': 'tcp',
            'PublishMode': 'ingress',
            'PublishedPort': int(port),
            'TargetPort': int(port)
        }

        EndpointSpec_Ports.append(EndpointSpec_Ports_tmp.copy())
        EndpointSpec_Ports_tmp.clear()

    EndpointSpec = {
        'Mode': 'vip',
        'Ports': EndpointSpec_Ports
    }

    return EndpointSpec


def diff_conf(conffile1, conffile2):

    if (os.path.exists(conffile1) and os.path.isfile(conffile1) and
            os.path.exists(conffile2) and os.path.isfile(conffile2)):

        # Return True if conffile1 and conffile2 identical
        return filecmp.cmp(conffile1, conffile2, shallow=False)

    else:
        return False


def new_conf(confpath, conffile):

    conf_files = [f for f in os.listdir(confpath)]
    conf_files.sort()

    with open(conffile, 'wt') as fo:
        for conf_file in conf_files:
            with open(confpath + '/' + conf_file, 'rt') as fi:
                fo.write(fi.read())

    if os.path.exists(conffile) and os.path.isfile(conffile):

        return True

    else:
        return False


def old_conf(conffile1, conffile2):

    if os.path.exists(conffile1) and os.path.isfile(conffile1):

        try:
            os.rename(conffile1, conffile2)

        except OSError as e:
            print('Error:', e)


def rot_conf(conffile1, conffile2, mode='copy'):

    if os.path.exists(conffile1) and os.path.isfile(conffile1):

        try:
            if mode == 'copy':
                copyfile(conffile1, conffile2)

            elif mode == 'move':
                move(conffile1, conffile2)

        except IOError as e:
            print('Error:', e)


def clean_dir(confpath):

    if os.path.exists(confpath) and os.path.isdir(confpath):

        try:
            rmtree(confpath)
            os.makedirs(confpath)

        except (IOError, OSError) as e:
            print('Error:', e)

    else:

        try:
            os.makedirs(confpath)

        except OSError as e:
            print('Error:', e)


def services_id():

    service_col = list()

    for service in client.services.list():

        service_col.append(str(service.id))

    # print(service_col)
    return service_col


def frontend_http(frontend_http_col, mode='http'):

    # print('frontend_http_col', frontend_http_col)
    '''
    INPUT EXAMPLE: frontend_http_col = [
        {
            'name': 'app1.dev.example.com',
            'sticky': 'false',
            'port': '80'
        },
        {
            'name': 'app.dev.example.com',
            'sticky': 'false',
            'port': '80'
            }
    ]
    '''

    frontend_http_col_tmp = dict()
    frontend_http_jinja2 = list()
    frontend_http_port_pars = list()

    for front in frontend_http_col:

        if front['port'] in frontend_http_port_pars:

            for front2 in frontend_http_jinja2:

                if front2['port'] == front['port']:
                    front2['names'].append(
                        {'name': front['name'], 'sticky': front['sticky']})

        else:

            frontend_http_port_pars.append(front['port'])
            frontend_http_col_tmp['port'] = front['port']

            if mode == 'https':

                if (os.path.exists(USER_CERT_DIR + '/' + front['port'] + '.pem') and
                        os.path.isfile(USER_CERT_DIR + '/' + front['port'] + '.pem')):

                    frontend_http_col_tmp['cert'] = USER_CERT_DIR + \
                        '/' + front['port'] + '.pem'

                else:

                    frontend_http_col_tmp['cert'] = DEFAULT_CERT_FILE

            frontend_http_col_tmp['names'] = [
                {'name': front['name'], 'sticky': front['sticky']}]

            frontend_http_jinja2.append(frontend_http_col_tmp.copy())
            frontend_http_col_tmp.clear()

    return frontend_http_jinja2


def backend_http(backend_http_col):

    # print('backend_http_col', backend_http_col)
    '''
    INPUT EXAMPLE: backend_http_col = [
        {
            'ip': '10.0.0.32',
            'slot': 1,
            'id': 'gk6ak7asfvvg9mlwvvr5yteu8',
            'task': 'app1',
            'backend': 'HTTP_app1.dev.example.com_80_sticky.false',
            'port': '8080'
        },
        {
            'ip': '10.0.0.27',
            'slot': 2,
            'id': 'nntx1i256yjyggaz4qmwsjnlw',
            'task': 'app1',
            'backend': 'HTTP_app1.dev.example.com_80_sticky.false',
            'port': '8080'
        },
        {
            'ip': '10.0.0.18',
            'slot': 6,
            'id': '1h595wcqd6wp4n4dhz7tfsgta',
            'task': 'app',
            'backend': 'HTTP_app.dev.example.com_80_sticky.false',
            'port': '8080'
        },
        {
            'ip': '10.0.0.26',
            'slot': 14,
            'id': '31m52lrig6sb4sw3452qlgtn4',
            'task': 'app',
            'backend': 'HTTP_app.dev.example.com_80_sticky.false',
            'port': '8080'
        }
    ]
    '''

    backend_http_col_tmp = dict()
    backend_http_jinja2 = list()
    backend_http_backend_pars = list()

    for back in backend_http_col:

        if back['backend'] in backend_http_backend_pars:

            for back2 in backend_http_jinja2:

                if back2['backend'] == back['backend']:
                    back2['tasks'].append(
                        {'task': back['task'], 'slot': back['slot'], 'id': back['id'],
                         'ip': back['ip'], 'port': back['port']})

        else:

            backend_http_backend_pars.append(back['backend'])
            backend_http_col_tmp['backend'] = back['backend']

            backend_http_col_tmp['tasks'] = [
                {'task': back['task'], 'slot': back['slot'], 'id': back['id'],
                 'ip': back['ip'], 'port': back['port']}]

            backend_http_jinja2.append(backend_http_col_tmp.copy())
            backend_http_col_tmp.clear()

    return backend_http_jinja2


def frontend_tcp(frontend_tcp_col):

    # print('frontend_tcp_col', frontend_tcp_col)
    '''
    INPUT EXAMPLE: frontend_tcp_col = [
        {
            "port": "5901"
        },
        {
            "port": "5902"
        }
    ]
    '''

    frontend_tcp_col_tmp = dict()
    frontend_tcp_jinja2 = list()

    for front in frontend_tcp_col:

        frontend_tcp_col_tmp['port'] = front['port']
        frontend_tcp_col_tmp['name'] = front['name']
        frontend_tcp_col_tmp['sticky'] = front['sticky']
        frontend_tcp_jinja2.append(frontend_tcp_col_tmp.copy())
        frontend_tcp_col_tmp.clear()

    return frontend_tcp_jinja2


def backend_tcp(backend_tcp_col):

    # print('backend_tcp_col', backend_tcp_col)
    '''
    INPUT EXAMPLE: backend_tcp_col = [
        {
            "port": "5901",
            "backend": "TCP_5901_sticky.false",
            "id": "xcaqcgspos6gbs8etm33ryx1u",
            "slot": 1,
            "task": "app8",
            "ip": "10.0.0.23"
        },
        {
            "port": "5902",
            "backend": "TCP_5902_sticky.false",
            "id": "2ti75oyr5wei8v5ub7pmpk8of",
            "slot": 1,
            "task": "app9",
            "ip": "10.0.0.25"
        }
    ]
    '''

    backend_tcp_col_tmp = dict()
    backend_tcp_jinja2 = list()
    backend_tcp_backend_pars = list()

    for back in backend_tcp_col:

        if back['backend'] in backend_tcp_backend_pars:

            for back2 in backend_tcp_jinja2:

                if back2['backend'] == back['backend']:
                    back2['tasks'].append(
                        {'task': back['task'], 'slot': back['slot'], 'id': back['id'],
                         'ip': back['ip'], 'port': back['port']})

        else:

            backend_tcp_backend_pars.append(back['backend'])
            backend_tcp_col_tmp['backend'] = back['backend']

            backend_tcp_col_tmp['tasks'] = [
                {'task': back['task'], 'slot': back['slot'], 'id': back['id'],
                 'ip': back['ip'], 'port': back['port']}]

            backend_tcp_jinja2.append(backend_tcp_col_tmp.copy())
            backend_tcp_col_tmp.clear()

    return backend_tcp_jinja2


def backend_net(NetworksAttachment, NetworkName):

    for net in NetworksAttachment:

        if (net['Net_Scope'].lower() == 'swarm' and
            net['Net_DrvName'].lower() != 'none' and
            net['Net_Addr'] and
                net['Net_Name'].lower() == NetworkName.lower()):

            ip = net['Net_Addr'][0].split('/')[0]

            if ip is True:
                break

    # else:
    #     ip = '169.254.0.1' # Set APIPA

    return ip


def tcpport_exist_check(tcpport, frontend_tcp_col):

    for items in frontend_tcp_col:

        if tcpport == items['port']:
            return False

    return True


def tcpport_value_check(value):

    value_check = False

    try:
        if int(value) and int(value) > 0 and int(value) <= 65535:
            value_check = True

    except (ValueError, TypeError) as e:
        print('Error:', e)

    return value_check


def render_haproxy_cfg(data, tmpl, out):

    env = Environment(loader=FileSystemLoader(CUR_DIR), trim_blocks=True)
    templ = env.get_template(tmpl)

    # print(type(data))
    if isinstance(data, dict):
        outp = templ.render(data)

    elif isinstance(data, list):
        outp = templ.render(values=data)

    with open(out, 'wt') as f:
        f.write(outp)


def main_settings():

    hostname = get_hostname()

    if not hostname:
        return DEF_MAIN_SETTINGS

    cln = DockerContainerClass(hostname)
    cln_data = cln.get_data()

    if not cln_data:
        return DEF_MAIN_SETTINGS

    service_id = cln_data['service_id']

    service = DockerServiceClass(service_id)
    service_labels = service.get_labels()

    return diff_dict(DEF_MAIN_SETTINGS, service_labels)


def diff_dict(olddict, newdict):

    setdict = dict()
    newdict_mod = dict()

    err_count = 0

    for key, value in newdict.items():

        if not key.startswith(LABEL_PREF + '.'):
            err_count += 1

        newdict_mod[key.replace(LABEL_PREF + '.', '')] = value

    if err_count == 0:

        for def_key, def_value in olddict.items():

            if def_key not in newdict_mod:
                setdict[def_key] = def_value

        for def_key, def_value in olddict.items():
            for new_key, new_value in newdict_mod.items():

                if def_key == new_key:
                    # print('def', def_key, '>', 'new', new_key)
                    setdict[def_key] = new_value

        # print(json.dumps(setdict, indent=4))
        return setdict

    else:
        return olddict


def get_haproxy_true():

    status = False

    hostname = get_hostname()

    if not hostname:
        return status

    cln = DockerContainerClass(hostname)
    cln_data = cln.get_data()

    if not cln_data:
        return status

    service_id = cln_data['service_id']

    service = DockerServiceClass(service_id)
    service_labels = service.get_labels()

    if (LABEL_PREF + '.' + 'proxy' in service_labels.keys() and
            service_labels[LABEL_PREF + '.' + 'proxy'] == 'true'):

        status = True

    return status


def get_haproxy_stats_port():

    hostname = get_hostname()

    if not hostname:
        return False

    cln = DockerContainerClass(hostname)
    cln_data = cln.get_data()

    if not cln_data:
        return False

    service_id = cln_data['service_id']

    service = DockerServiceClass(service_id)
    service_labels = service.get_labels()

    if LABEL_PREF + '.' + 'stats_port' in service_labels.keys():
        return service_labels[LABEL_PREF + '.' + 'stats_port']

    else:
        return DEF_MAIN_SETTINGS['stats_port']


def get_haproxy_service():

    hostname = get_hostname()

    if not hostname:
        sys.exit(1)

    cln = DockerContainerClass(hostname)
    cln_data = cln.get_data()

    if not cln_data:
        sys.exit(1)

    service_id = cln_data['service_id']

    service = DockerServiceClass(service_id)

    return {
        'name': service.get_name(),
        'id': service.get_id()
    }


def check_proxy_net(proxy_net, haproxy_service_id, service_id):

    net_id = None
    service_col = list()

    for netwrok in client.networks.list():

        if netwrok.name == proxy_net:
            net_id = netwrok.id
            break

    if net_id:

        net = DockerNetworkClass(net_id)

        for service in net.net_servises():
            service_col.append(str(service.id))

    if service_col:

        if haproxy_service_id in service_col and service_id in service_col:
            return True

        else:
            return False

    else:

        return False


def configure():

    ports_col = list()
    frontend_http_col = list()
    backend_http_col_sticky_false = list()
    backend_http_col_sticky_true = list()

    frontend_https_col = list()
    backend_https_col_sticky_false = list()
    backend_https_col_sticky_true = list()

    frontend_tcp_col = list()
    backend_tcp_col_sticky_false = list()
    backend_tcp_col_sticky_true = list()

    haproxy_service = get_haproxy_service()

    try:
        haproxy_service_name = haproxy_service['name']
        haproxy_service_id = haproxy_service['id']

    except KeyError:
        sys.exit(1)

    if not haproxy_service_name:
        sys.exit(1)

    if not haproxy_service_id:
        sys.exit(1)

    for service_id in services_id():

        service = DockerServiceClass(service_id)
        service_name = service.get_name()
        service_labels = service.get_labels()
        service_tasks = service.get_tasks()
        service_mode = service.get_mode()

        if list(service_mode.keys())[0] == 'Replicated':
            if service_mode['Replicated']['Replicas'] > 0:
                service_mode_check = 'Replicated'

            else:
                service_mode_check = False

        elif list(service_mode.keys())[0] == 'Global':
            service_mode_check = 'Global'

        else:
            service_mode_check = False

        if (service_name and service_labels and service_tasks and service_mode and service_mode_check and
            LABEL_PREF + '.' + 'proxy_net' in service_labels.keys() and check_proxy_net(service_labels[LABEL_PREF + '.' + 'proxy_net'], haproxy_service_id, service_id) and
            LABEL_PREF + '.' + 'proxy_name' in service_labels.keys() and service_labels[LABEL_PREF + '.' + 'proxy_name'] == haproxy_service_name and
                LABEL_PREF + '.' + 'proxy' in service_labels.keys() and service_labels[LABEL_PREF + '.' + 'proxy'] == 'true' and get_haproxy_true()):

            # Collect HAPROXY HTTP
            count = 1

            while (LABEL_PREF + '.' + 'proxy_http_name' + str(count) in service_labels.keys() and
                   LABEL_PREF + '.' + 'proxy_http_front' + str(count) in service_labels.keys() and
                   LABEL_PREF + '.' + 'proxy_http_back' + str(count) in service_labels.keys() and
                   LABEL_PREF + '.' + 'proxy_http_sticky' + str(count) in service_labels.keys()):

                if (not tcpport_value_check(service_labels[LABEL_PREF + '.' + 'proxy_http_front' + str(count)]) or
                        not tcpport_value_check(service_labels[LABEL_PREF + '.' + 'proxy_http_back' + str(count)])):

                    count += 1
                    continue

                if not (service_labels[LABEL_PREF + '.' + 'proxy_http_sticky' + str(count)] == 'false' or
                        service_labels[LABEL_PREF + '.' + 'proxy_http_sticky' + str(count)] == 'true'):

                    count += 1
                    continue

                ports_col.append(service_labels[LABEL_PREF + '.' + 'proxy_http_front' + str(count)])

                frontend_http_col_tmp = dict()

                frontend_http_col_tmp['port'] = service_labels[LABEL_PREF + '.' + 'proxy_http_front' + str(count)]
                frontend_http_col_tmp['name'] = service_labels[LABEL_PREF + '.' + 'proxy_http_name' + str(count)]
                frontend_http_col_tmp['sticky'] = service_labels[LABEL_PREF + '.' + 'proxy_http_sticky' + str(count)]
                frontend_http_col.append(frontend_http_col_tmp.copy())
                frontend_http_col_tmp.clear()

                if service_labels[LABEL_PREF + '.' + 'proxy_http_sticky' + str(count)] == 'false':

                    backend_http_col_tmp = dict()

                    for service_task in service_tasks:

                        backend_http_col_tmp['backend'] = 'http' + '_' + service_labels[LABEL_PREF + '.' + 'proxy_http_name' + str(count)] + '_' + \
                            service_labels[LABEL_PREF + '.' + 'proxy_http_front' + str(count)] + '_' + \
                            'sticky' + '.' + \
                            service_labels[LABEL_PREF + '.' + 'proxy_http_sticky' +
                                           str(count)]

                        backend_http_col_tmp['task'] = service_name

                        # mode replicated - container DNS name = srv.name.Slot.ID
                        # mode global - container DNS name = srv.name.NodeID.ID (Slot None)

                        if service_mode_check == 'Replicated':
                            backend_http_col_tmp['slot'] = service_task['Slot']

                        elif service_mode_check == 'Global':
                            backend_http_col_tmp['slot'] = service_task['NodeID']

                        backend_http_col_tmp['id'] = service_task['Task_ID']

                        # backend_http_col_tmp['ip'] = service_task['Net_Addr']
                        backend_http_col_tmp['ip'] = backend_net(
                            service_task['NetworksAttachment'],
                            service_labels[LABEL_PREF + '.' + 'proxy_net'])

                        backend_http_col_tmp['port'] = service_labels[LABEL_PREF + '.' + 'proxy_http_back' + str(count)]

                        backend_http_col_sticky_false.append(backend_http_col_tmp.copy())
                        backend_http_col_tmp.clear()

                elif service_labels[LABEL_PREF + '.' + 'proxy_http_sticky' + str(count)] == 'true':

                    backend_http_col_tmp = dict()

                    for service_task in service_tasks:

                        backend_http_col_tmp['backend'] = 'http' + '_' + service_labels[LABEL_PREF + '.' + 'proxy_http_name' + str(count)] + '_' + \
                            service_labels[LABEL_PREF + '.' + 'proxy_http_front' + str(count)] + '_' + \
                            'sticky' + '.' + \
                            service_labels[LABEL_PREF + '.' + 'proxy_http_sticky' +
                                           str(count)]

                        backend_http_col_tmp['task'] = service_name

                        # mode replicated - container DNS name = srv.name.Slot.ID
                        # mode global - container DNS name = srv.name.NodeID.ID (Slot None)

                        if service_mode_check == 'Replicated':
                            backend_http_col_tmp['slot'] = service_task['Slot']

                        elif service_mode_check == 'Global':
                            backend_http_col_tmp['slot'] = service_task['NodeID']

                        backend_http_col_tmp['id'] = service_task['Task_ID']

                        # backend_http_col_tmp['ip'] = service_task['Net_Addr']
                        backend_http_col_tmp['ip'] = backend_net(
                            service_task['NetworksAttachment'],
                            service_labels[LABEL_PREF + '.' + 'proxy_net'])

                        backend_http_col_tmp['port'] = service_labels[LABEL_PREF + '.' + 'proxy_http_back' + str(count)]

                        backend_http_col_sticky_true.append(backend_http_col_tmp.copy())
                        backend_http_col_tmp.clear()

                count += 1

            # Collect HAPROXY HTTPS
            count = 1

            while (LABEL_PREF + '.' + 'proxy_https_name' + str(count) in service_labels.keys() and
                   LABEL_PREF + '.' + 'proxy_https_front' + str(count) in service_labels.keys() and
                   LABEL_PREF + '.' + 'proxy_https_back' + str(count) in service_labels.keys() and
                   LABEL_PREF + '.' + 'proxy_https_sticky' + str(count) in service_labels.keys()):

                if (not tcpport_value_check(service_labels[LABEL_PREF + '.' + 'proxy_https_front' + str(count)]) or
                        not tcpport_value_check(service_labels[LABEL_PREF + '.' + 'proxy_https_back' + str(count)])):

                    count += 1
                    continue

                if not (service_labels[LABEL_PREF + '.' + 'proxy_https_sticky' + str(count)] == 'false' or
                        service_labels[LABEL_PREF + '.' + 'proxy_https_sticky' + str(count)] == 'true'):

                    count += 1
                    continue

                ports_col.append(service_labels[LABEL_PREF + '.' + 'proxy_https_front' + str(count)])

                frontend_https_col_tmp = dict()

                frontend_https_col_tmp['port'] = service_labels[LABEL_PREF + '.' + 'proxy_https_front' + str(count)]
                frontend_https_col_tmp['name'] = service_labels[LABEL_PREF + '.' + 'proxy_https_name' + str(count)]
                frontend_https_col_tmp['sticky'] = service_labels[LABEL_PREF + '.' + 'proxy_https_sticky' + str(count)]
                frontend_https_col.append(frontend_https_col_tmp.copy())
                frontend_https_col_tmp.clear()

                if service_labels[LABEL_PREF + '.' + 'proxy_https_sticky' + str(count)] == 'false':

                    backend_https_col_tmp = dict()

                    for service_task in service_tasks:

                        backend_https_col_tmp['backend'] = 'https' + '_' + service_labels[LABEL_PREF + '.' + 'proxy_https_name' + str(count)] + '_' + \
                            service_labels[LABEL_PREF + '.' + 'proxy_https_front' + str(count)] + '_' + \
                            'sticky' + '.' + \
                            service_labels[LABEL_PREF + '.' + 'proxy_https_sticky' +
                                           str(count)]

                        backend_https_col_tmp['task'] = service_name

                        # mode replicated - container DNS name = srv.name.Slot.ID
                        # mode global - container DNS name = srv.name.NodeID.ID (Slot None)

                        if service_mode_check == 'Replicated':
                            backend_https_col_tmp['slot'] = service_task['Slot']

                        elif service_mode_check == 'Global':
                            backend_https_col_tmp['slot'] = service_task['NodeID']

                        backend_https_col_tmp['id'] = service_task['Task_ID']

                        # backend_https_col_tmp['ip'] = service_task['Net_Addr']
                        backend_https_col_tmp['ip'] = backend_net(
                            service_task['NetworksAttachment'],
                            service_labels[LABEL_PREF + '.' + 'proxy_net'])

                        backend_https_col_tmp['port'] = service_labels[LABEL_PREF + '.' + 'proxy_https_back' + str(count)]

                        backend_https_col_sticky_false.append(backend_https_col_tmp.copy())
                        backend_https_col_tmp.clear()

                elif service_labels[LABEL_PREF + '.' + 'proxy_https_sticky' + str(count)] == 'true':

                    backend_https_col_tmp = dict()

                    for service_task in service_tasks:

                        backend_https_col_tmp['backend'] = 'https' + '_' + service_labels[LABEL_PREF + '.' + 'proxy_https_name' + str(count)] + '_' + \
                            service_labels[LABEL_PREF + '.' + 'proxy_https_front' + str(count)] + '_' + \
                            'sticky' + '.' + \
                            service_labels[LABEL_PREF + '.' + 'proxy_https_sticky' +
                                           str(count)]

                        backend_https_col_tmp['task'] = service_name

                        # mode replicated - container DNS name = srv.name.Slot.ID
                        # mode global - container DNS name = srv.name.NodeID.ID (Slot None)

                        if service_mode_check == 'Replicated':
                            backend_https_col_tmp['slot'] = service_task['Slot']

                        elif service_mode_check == 'Global':
                            backend_https_col_tmp['slot'] = service_task['NodeID']

                        backend_https_col_tmp['id'] = service_task['Task_ID']

                        # backend_https_col_tmp['ip'] = service_task['Net_Addr']
                        backend_https_col_tmp['ip'] = backend_net(
                            service_task['NetworksAttachment'],
                            service_labels[LABEL_PREF + '.' + 'proxy_net'])

                        backend_https_col_tmp['port'] = service_labels[LABEL_PREF + '.' + 'proxy_https_back' + str(count)]

                        backend_https_col_sticky_true.append(backend_https_col_tmp.copy())
                        backend_https_col_tmp.clear()

                count += 1

            # Collect HAPROXY TCP
            count = 1

            while (LABEL_PREF + '.' + 'proxy_tcp_front' + str(count) in service_labels.keys() and
                   LABEL_PREF + '.' + 'proxy_tcp_back' + str(count) in service_labels.keys() and
                   LABEL_PREF + '.' + 'proxy_tcp_sticky' + str(count) in service_labels.keys()):

                if (not tcpport_value_check(service_labels[LABEL_PREF + '.' + 'proxy_tcp_front' + str(count)]) or
                        not tcpport_value_check(service_labels[LABEL_PREF + '.' + 'proxy_tcp_back' + str(count)])):

                    count += 1
                    continue

                if not (service_labels[LABEL_PREF + '.' + 'proxy_tcp_sticky' + str(count)] == 'false' or
                        service_labels[LABEL_PREF + '.' + 'proxy_tcp_sticky' + str(count)] == 'true'):

                    count += 1
                    continue

                if tcpport_exist_check(service_labels[LABEL_PREF + '.' + 'proxy_tcp_front' + str(count)],
                                 frontend_tcp_col):

                    ports_col.append(service_labels[LABEL_PREF + '.' + 'proxy_tcp_front' + str(count)])

                    frontend_tcp_col_tmp = dict()

                    frontend_tcp_col_tmp['port'] = service_labels[LABEL_PREF + '.' + 'proxy_tcp_front' + str(count)]
                    frontend_tcp_col_tmp['name'] = service_name
                    frontend_tcp_col_tmp['sticky'] = service_labels[LABEL_PREF + '.' + 'proxy_tcp_sticky' + str(count)]
                    frontend_tcp_col.append(frontend_tcp_col_tmp.copy())
                    frontend_tcp_col_tmp.clear()

                    if service_labels[LABEL_PREF + '.' + 'proxy_tcp_sticky' + str(count)] == 'false':

                        backend_tcp_col_tmp = dict()

                        for service_task in service_tasks:

                            backend_tcp_col_tmp['backend'] = 'tcp' + '_' + service_name + '_' + \
                                service_labels[LABEL_PREF + '.' + 'proxy_tcp_front' + str(count)] + '_' + \
                                'sticky' + '.' + \
                                service_labels[LABEL_PREF + '.' + 'proxy_tcp_sticky' +
                                               str(count)]

                            backend_tcp_col_tmp['task'] = service_name

                            # mode replicated - container DNS name = srv.name.Slot.ID
                            # mode global - container DNS name = srv.name.NodeID.ID (Slot None)

                            if service_mode_check == 'Replicated':
                                backend_tcp_col_tmp['slot'] = service_task['Slot']

                            elif service_mode_check == 'Global':
                                backend_tcp_col_tmp['slot'] = service_task['NodeID']

                            backend_tcp_col_tmp['id'] = service_task['Task_ID']

                            # backend_tcp_col_tmp['ip'] = service_task['Net_Addr']
                            backend_tcp_col_tmp['ip'] = backend_net(
                                service_task['NetworksAttachment'],
                                service_labels[LABEL_PREF + '.' + 'proxy_net'])

                            backend_tcp_col_tmp['port'] = service_labels[LABEL_PREF + '.' + 'proxy_tcp_back' + str(count)]

                            backend_tcp_col_sticky_false.append(backend_tcp_col_tmp.copy())
                            backend_tcp_col_tmp.clear()

                    elif service_labels[LABEL_PREF + '.' + 'proxy_tcp_sticky' + str(count)] == 'true':

                        backend_tcp_col_tmp = dict()

                        for service_task in service_tasks:

                            backend_tcp_col_tmp['backend'] = 'tcp' + '_' + service_name + '_' + \
                                service_labels[LABEL_PREF + '.' + 'proxy_tcp_front' + str(count)] + '_' + \
                                'sticky' + '.' + \
                                service_labels[LABEL_PREF + '.' + 'proxy_tcp_sticky' +
                                               str(count)]

                            backend_tcp_col_tmp['task'] = service_name

                            # mode replicated - container DNS name = srv.name.Slot.ID
                            # mode global - container DNS name = srv.name.NodeID.ID (Slot None)

                            if service_mode_check == 'Replicated':
                                backend_tcp_col_tmp['slot'] = service_task['Slot']

                            elif service_mode_check == 'Global':
                                backend_tcp_col_tmp['slot'] = service_task['NodeID']

                            backend_tcp_col_tmp['id'] = service_task['Task_ID']

                            # backend_tcp_col_tmp['ip'] = service_task['Net_Addr']
                            backend_tcp_col_tmp['ip'] = backend_net(
                                service_task['NetworksAttachment'],
                                service_labels[LABEL_PREF + '.' + 'proxy_net'])

                            backend_tcp_col_tmp['port'] = service_labels[LABEL_PREF + '.' + 'proxy_tcp_back' + str(count)]

                            backend_tcp_col_sticky_true.append(backend_tcp_col_tmp.copy())
                            backend_tcp_col_tmp.clear()

                count += 1

        # print(service_name)
        # print(service_labels)
        # print(service_tasks)

    # Check EndpointSpec
    stats_port = get_haproxy_stats_port()
    if stats_port: ports_col.append(stats_port)
    check_EndpointSpec(ports_col)

    # Clean  OLD HAPROXY
    clean_dir(CONF_PATH)

    # Generate Default Certificate
    gen_default_cert(DEFAULT_CERT_FILE)

    # Generate HAPROXY MAIN
    set_main_settings = main_settings()

    if set_main_settings:

        # print('Generate HAPROXY MAIN: set_main_settings =',
        #       json.dumps(set_main_settings, indent=4))

        render_haproxy_cfg(set_main_settings,
                           TMPL_JINJA2_MAIN, CONF_JINJA2_MAIN)

    # Generate HAPROXY HTTP Frontend
    if frontend_http_col:

        # print('Generate HAPROXY HTTP Frontend: frontend_http_col =',
        #       json.dumps(frontend_http_col, indent=4))

        frontend_http_col_res = frontend_http(frontend_http_col)

        if (frontend_http_col_res and
            os.path.exists(TMPL_JINJA2_FRONTEND_HTTP) and
                os.path.isfile(TMPL_JINJA2_FRONTEND_HTTP)):

            # print('Generate HAPROXY HTTP Frontend: frontend_http_col_res =',
            #       json.dumps(frontend_http_col_res, indent=4))

            render_haproxy_cfg(
                frontend_http_col_res, TMPL_JINJA2_FRONTEND_HTTP, CONF_JINJA2_FRONTEND_HTTP)

    # Generate HAPROXY HTTP Backend without sticky
    if backend_http_col_sticky_false:

        # print('Generate HAPROXY HTTP Backend without sticky: backend_http_col_sticky_false =',
        #       json.dumps(backend_http_col_sticky_false, indent=4))

        backend_http_col_sticky_false_res = backend_http(
            backend_http_col_sticky_false)

        if (backend_http_col_sticky_false_res and
            os.path.exists(TMPL_JINJA2_BACKEND_HTTP_STICKY_FALSE) and
                os.path.isfile(TMPL_JINJA2_BACKEND_HTTP_STICKY_FALSE)):

            # print('Generate HAPROXY HTTP Backend without sticky: backend_http_col_sticky_false_res =',
            #       json.dumps(backend_http_col_sticky_false_res, indent=4))

            render_haproxy_cfg(backend_http_col_sticky_false_res,
                               TMPL_JINJA2_BACKEND_HTTP_STICKY_FALSE, CONF_JINJA2_BACKEND_HTTP_STICKY_FALSE)

    # Generate HAPROXY HTTP Backend with sticky
    if backend_http_col_sticky_true:

        # print('Generate HAPROXY HTTP Backend with sticky: backend_http_col_sticky_true =',
        #       json.dumps(backend_http_col_sticky_true, indent=4))

        backend_http_col_sticky_true_res = backend_http(
            backend_http_col_sticky_true)

        if (backend_http_col_sticky_true_res and
            os.path.exists(TMPL_JINJA2_BACKEND_HTTP_STICKY_TRUE) and
                os.path.isfile(TMPL_JINJA2_BACKEND_HTTP_STICKY_TRUE)):

            # print('Generate HAPROXY HTTP Backend with sticky: backend_http_col_sticky_true_res =',
            #       json.dumps(backend_http_col_sticky_true_res, indent=4))

            render_haproxy_cfg(backend_http_col_sticky_true_res,
                               TMPL_JINJA2_BACKEND_HTTP_STICKY_TRUE, CONF_JINJA2_BACKEND_HTTP_STICKY_TRUE)

    # Generate HAPROXY HTTPS Frontend
    if frontend_https_col:

        # print('Generate HAPROXY HTTPS Frontend: frontend_https_col =',
        #       json.dumps(frontend_https_col, indent=4))

        frontend_https_col_res = frontend_http(frontend_https_col, 'https')

        if (frontend_https_col_res and
            os.path.exists(TMPL_JINJA2_FRONTEND_HTTPS) and
                os.path.isfile(TMPL_JINJA2_FRONTEND_HTTPS)):

            # print('Generate HAPROXY HTTPS Frontend: frontend_https_col_res =',
            #       json.dumps(frontend_https_col_res, indent=4))

            render_haproxy_cfg(
                frontend_https_col_res, TMPL_JINJA2_FRONTEND_HTTPS, CONF_JINJA2_FRONTEND_HTTPS)

    # Generate HAPROXY HTTPS Backend without sticky
    if backend_https_col_sticky_false:

        # print('Generate HAPROXY HTTPS Backend without sticky: backend_https_col_sticky_false =',
        #       json.dumps(backend_https_col_sticky_false, indent=4))

        backend_https_col_sticky_false_res = backend_http(
            backend_https_col_sticky_false)

        if (backend_https_col_sticky_false_res and
            os.path.exists(TMPL_JINJA2_BACKEND_HTTPS_STICKY_FALSE) and
                os.path.isfile(TMPL_JINJA2_BACKEND_HTTPS_STICKY_FALSE)):

            # print('Generate HAPROXY HTTPS Backend without sticky: backend_https_col_sticky_false_res =',
            #       json.dumps(backend_https_col_sticky_false_res, indent=4))

            render_haproxy_cfg(backend_https_col_sticky_false_res,
                               TMPL_JINJA2_BACKEND_HTTPS_STICKY_FALSE, CONF_JINJA2_BACKEND_HTTPS_STICKY_FALSE)

    # Generate HAPROXY HTTPS Backend with sticky
    if backend_https_col_sticky_true:

        # print('Generate HAPROXY HTTPS Backend with sticky: backend_https_col_sticky_true =',
        #       json.dumps(backend_https_col_sticky_true, indent=4))

        backend_https_col_sticky_true_res = backend_http(
            backend_https_col_sticky_true)

        if (backend_https_col_sticky_true_res and
                os.path.exists(TMPL_JINJA2_BACKEND_HTTPS_STICKY_TRUE) and
                os.path.isfile(TMPL_JINJA2_BACKEND_HTTPS_STICKY_TRUE)):

            # print('Generate HAPROXY HTTPS Backend with sticky: backend_https_col_sticky_true_res =',
            #       json.dumps(backend_https_col_sticky_true_res, indent=4))

            render_haproxy_cfg(
                backend_https_col_sticky_true_res, TMPL_JINJA2_BACKEND_HTTPS_STICKY_TRUE,
                CONF_JINJA2_BACKEND_HTTPS_STICKY_TRUE)

    # Generate HAPROXY TCP Frontend
    if frontend_tcp_col:

        # print('Generate HAPROXY TCP Frontend: frontend_tcp_col =',
        #       json.dumps(frontend_tcp_col, indent=4))

        frontend_tcp_col_res = frontend_tcp(frontend_tcp_col)

        if (frontend_tcp_col_res and
            os.path.exists(TMPL_JINJA2_FRONTEND_TCP) and
                os.path.isfile(TMPL_JINJA2_FRONTEND_TCP)):

            # print('Generate HAPROXY TCP Frontend: frontend_tcp_col_res =',
            #       json.dumps(frontend_tcp_col_res, indent=4))

            render_haproxy_cfg(
                frontend_tcp_col_res, TMPL_JINJA2_FRONTEND_TCP, CONF_JINJA2_FRONTEND_TCP)

    # Generate HAPROXY TCP Backend without sticky
    if backend_tcp_col_sticky_false:

        # print('Generate HAPROXY TCP Backend without sticky: backend_tcp_col_sticky_false =',
        #       json.dumps(backend_tcp_col_sticky_false, indent=4))

        backend_tcp_col_sticky_false_res = backend_tcp(
            backend_tcp_col_sticky_false)

        if (backend_tcp_col_sticky_false_res and
            os.path.exists(TMPL_JINJA2_BACKEND_TCP_STICKY_FALSE) and
                os.path.isfile(TMPL_JINJA2_BACKEND_TCP_STICKY_FALSE)):

            # print('Generate HAPROXY TCP Backend without sticky: backend_tcp_col_sticky_false_res =',
            #       json.dumps(backend_tcp_col_sticky_false_res, indent=4))

            render_haproxy_cfg(backend_tcp_col_sticky_false_res,
                               TMPL_JINJA2_BACKEND_TCP_STICKY_FALSE, CONF_JINJA2_BACKEND_TCP_STICKY_FALSE)

    # Generate HAPROXY TCP Backend with sticky
    if backend_tcp_col_sticky_true:

        # print('Generate HAPROXY TCP Backend with sticky: backend_tcp_col_sticky_true =',
        #       json.dumps(backend_tcp_col_sticky_true, indent=4))

        backend_tcp_col_sticky_true_res = backend_tcp(
            backend_tcp_col_sticky_true)

        if (backend_tcp_col_sticky_true_res and
                os.path.exists(TMPL_JINJA2_BACKEND_TCP_STICKY_TRUE) and
                os.path.isfile(TMPL_JINJA2_BACKEND_TCP_STICKY_TRUE)):

            # print('Generate HAPROXY TCP Backend with sticky: backend_tcp_col_sticky_true_res =',
            #       json.dumps(backend_tcp_col_sticky_true_res, indent=4))

            render_haproxy_cfg(
                backend_tcp_col_sticky_true_res, TMPL_JINJA2_BACKEND_TCP_STICKY_TRUE,
                CONF_JINJA2_BACKEND_TCP_STICKY_TRUE)

    # Generate HAPROXY COMMON CONF
    if new_conf(CONF_PATH, CONF_COMMON):

        if diff_conf(CONF_COMMON, CONF_ORIG):

            # print(CONF_COMMON, CONF_ORIG, '=', 'identical')
            pass

        else:

            # print(CONF_COMMON, CONF_ORIG, '=', 'not identical')
            old_conf(CONF_ORIG, CONF_OLD)
            rot_conf(CONF_COMMON, CONF_ORIG, mode='copy')

            if gen_conf_reload_scr(CONF_RELOAD_SCR, CONF_RELOAD_CMD_LINE):

                # Graceful restart haproxy
                # /usr/sbin/haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -sf OLD_PID
                # https://www.haproxy.com/blog/truly-seamless-reloads-with-haproxy-no-more-hacks/

                # -sf <pid>* : send the "finish" signal (SIGUSR1) to older processes after boot
                #     completion to ask them to finish what they are doing and to leave. <pid>
                #     is a list of pids to signal (one per argument). The list ends on any
                #     option starting with a "-". It is not a problem if the list of pids is
                #     empty, so that it can be built on the fly based on the result of a command
                #     like "pidof" or "pgrep".

                # /usr/sbin/haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -sf $(pidof 'haproxy' | sort | uniq | sed -r 's/[ ]/, /g')

                run_command(CONF_RELOAD_SCR, False)


def run_command(cmd, verbose=False):

    '''
    Example:

    cmd = 'ps ax'.split()
    run_cmd_res = run_cmd(cmd, False)

    for stdout in run_cmd_res['stdout']:
    print(stdout)

    for stderr in run_cmd_res['stderr']:
        print(stderr)

    print(run_cmd_res['errcode'])
    '''

    process = subprocess.Popen(cmd,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    (output, error) = process.communicate()

    if verbose:

        if output:

            # print(output.decode('utf-8').splitlines()) # stdout one line
            print('stdout:\n', output.decode('utf-8'))

        if error:
            # print(error.decode('utf-8').splitlines()) # stderr one line
            print('stderr:\n\n', error.decode('utf-8'))

    # return process.returncode

    return {
        'stdout': output.decode('utf-8').splitlines(),
        'stderr': error.decode('utf-8').splitlines(),
        'errcode': process.returncode
    }


def gen_conf_reload_scr(scrpath, cmdline):

    with open(scrpath, 'wt') as f:
        f.write('#! /bin/sh' + '\n')
        f.write('\n')
        f.write('set -e' + '\n')
        f.write('set -x' + '\n')
        f.write('\n')
        f.write(cmdline + '\n')
        f.write('\n')

    os.chmod(scrpath, 0o777)

    if os.path.exists(scrpath) and os.path.isfile(scrpath):

        return True

    else:
        return False


def usage():

    print()
    print(bcolors.OKGREEN + 'NAME:   DOCKER_SWARM-MODE.HAPROXY-BALANCER.PY' + bcolors.ENDC)
    print(bcolors.OKGREEN + 'DESC:   HAPROXY IMAGE THAT AUTORECONFIGURES ITSELF WHEN USED IN DOCKER SWARM MODE' + bcolors.ENDC)
    print(bcolors.OKGREEN + 'DATE:   13-11-2017' + bcolors.ENDC)
    print(bcolors.OKGREEN + 'LANG:   PYTHON 3' + bcolors.ENDC)
    print(bcolors.OKGREEN + 'AUTHOR: LAGUTIN R.A.' + bcolors.ENDC)
    print(bcolors.OKGREEN + 'EMAIL:  RLAGUTIN@MTA4.RU' + bcolors.ENDC)
    print()
    print(bcolors.BOLD + 'HAproxy image that autoreconfigures itself when used in Docker Swarm Mode' + bcolors.ENDC)
    print('''HAProxy image that balances between network attachments (not linked) tasks of services and
reconfigures itself when a docker swarm cluster member redeploys, joins or leaves.

''')

    print(bcolors.FAIL + 'Important: The names of services, networks, labels should be in lowercase!' + bcolors.ENDC)
    print()
    print(bcolors.BOLD + bcolors.UNDERLINE + 'Requirements:' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
pip3 install -U docker
pip3 install -U Jinja2
pip3 install -U pyOpenSSL
    ''' + bcolors.ENDC)

    print(bcolors.BOLD + bcolors.UNDERLINE + 'Tested:' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
Docker Engine 17.09.0-ce
docker (2.5.1)
Jinja2 (2.9.6)
pyOpenSSL (17.3.0)
    ''' + bcolors.ENDC)

    print(bcolors.BOLD + bcolors.UNDERLINE + 'Docker SDK:' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
https://docker-py.readthedocs.io
https://github.com/docker/docker-py
https://docs.docker.com/develop/sdk/
https://pypi.python.org/pypi/docker/
    ''' + bcolors.ENDC)

    print(bcolors.BOLD + bcolors.UNDERLINE + 'Docker SDK Example:' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
import json
import docker
    ''' + bcolors.ENDC)
    print(bcolors.OKGREEN + '# client = docker.from_env()' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''client = docker.DockerClient(base_url='unix://var/run/docker.sock')

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
    ''' + bcolors.ENDC)

    print(bcolors.BOLD + bcolors.UNDERLINE + 'Usage:' + bcolors.ENDC)
    print(bcolors.BOLD + bcolors.WARNING + '''

/usr/bin/python3 /etc/haproxy/haproxy-balancer/haproxy-balancer.py [-1|-w]

    pass -w to wait/watch for changes
    pass -1 to run once

    ''' + bcolors.ENDC)

    print(bcolors.BOLD + bcolors.UNDERLINE + 'Install:' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''

git clone https://github.com/rlagutinhub/docker_swarm-mode.haproxy-balancer.git
cd docker_swarm-mode.haproxy-balancer

docker build -t rlagutinhub/docker_swarm-mode.haproxy-balancer .

    ''' + bcolors.ENDC)

    print(bcolors.BOLD + bcolors.UNDERLINE + 'Configure:' + bcolors.ENDC)
    print(bcolors.HEADER + '''

    *** HAPROXY-BALANCER ***

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'network' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker network create -d overlay haproxy-balancer_prod

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'create haproxy-balancer' + bcolors.ENDC)
    print(bcolors.FAIL + 'Run only on the node manager!!! The --endpoint-mode dnsrr not support!!!' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service create --detach=false \\
 --name haproxy-balancer \\
 --network haproxy-balancer_prod \\
 --mount target=/var/run/docker.sock,source=/var/run/docker.sock,type=bind \\
 --mode global \\
 --constraint "node.role == manager" \\
 rlagutinhub/docker_swarm-mode.haproxy-balancer:latest

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'enable autconfigure haproxy-balancer' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service update --detach=false haproxy-balancer \\
 --label-add "com.example.proxy=true"

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'custom default settings haproxy-balancer' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service update --detach=false haproxy-balancer \\
 --label-add "com.example.def_log_server=127.0.0.1" \\
 --label-add "com.example.def_retries=3" \\
 --label-add "com.example.def_timeout_http_request=10s" \\
 --label-add "com.example.def_timeout_queue=1m" \\
 --label-add "com.example.def_timeout_connect=10s" \\
 --label-add "com.example.def_timeout_client=1m" \\
 --label-add "com.example.def_timeout_server=1m" \\
 --label-add "com.example.def_timeout_http_keep_alive=10s" \\
 --label-add "com.example.def_timeout_check=10s" \\
 --label-add "com.example.def_maxconn=10000" \\
 --label-add "com.example.stats_port=1936" \\
 --label-add "com.example.stats_login=root" \\
 --label-add "com.example.stats_password=password"

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + '    custom configure rsyslog server for haproxy' + bcolors.ENDC)
    print(bcolors.FAIL + '    Configure on the server, which is defined in the def_log_server.' + bcolors.ENDC)
    print()
    print(bcolors.BOLD + '    vim /etc/rsyslog.conf (uncomment or add)' + bcolors.ENDC)
    print('''    $ModLoad imudp
    $UDPServerRun 514
    local2.* /var/log/haproxy.log

    ''')

    print(bcolors.OKGREEN + 'ssl certificate - https forntend with tcp443 (docker secrets)' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
cat server.crt server.key > 443.pem
docker secret create haproxy-balancer_201711061830_443.pem 443.pem
docker service update --detach=false \\
 --secret-rm haproxy-balancer_OLD_443.pem \\
 --secret-add source=haproxy-balancer_201711061830_443.pem,target=/etc/pki/tls/certs/443.pem,mode=0644 \\
 haproxy-balancer

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'ssl certificate - https forntend with tcp8443 (docker secrets)' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
cat server.crt server.key > 8443.pem
docker secret create haproxy-balancer_201711061830_8443.pem 8443.pem
docker service update --detach=false \\
 --secret-rm haproxy-balancer_OLD_8443.pem \\
 --secret-add source=haproxy-balancer_201711061830_8443.pem,target=/etc/pki/tls/certs/8443.pem,mode=0644 \\
 haproxy-balancer
     ''' + bcolors.ENDC)

    print(bcolors.HEADER + '''
    *** APP(s) *** (https://github.com/rlagutinhub/docker_swarm-mode.haproxy-test)

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'create app' + bcolors.ENDC)
    print(bcolors.FAIL + 'The --mode Replicated is supported.' + bcolors.ENDC)
    print(bcolors.FAIL + 'The --mode Global is supported.' + bcolors.ENDC)
    print(bcolors.FAIL + 'The --endpoint-mode vip is supported.' + bcolors.ENDC)
    print(bcolors.FAIL + 'The --endpoint-mode dnsrr is supported. Port published with ingress mode can\'t be used with dnsrr mode!' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service create --detach=false \\
 --name haproxy-test \\
 -e PORTS="8080, 8081, 8443, 8444, 10001, 10002" \\
 --network haproxy-balancer_prod \\
 --constraint "node.role != manager" \\
 rlagutinhub/docker_swarm-mode.haproxy-test:201711111920

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'enable autconfigure haproxy-balancer' + bcolors.ENDC)
    print(bcolors.FAIL + 'It is required to specify the name of the haproxy-balancer service and the common overlay network \
     \nthat is used for the haproxy-balancer and this application service.''' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service update --detach=false haproxy-test \\
 --label-add "com.example.proxy=true" \\
 --label-add "com.example.proxy_name=haproxy-balancer" \\
 --label-add "com.example.proxy_net=haproxy-balancer_prod"

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'proxy http with sticky session' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service update --detach=false haproxy-test \\
 --label-add "com.example.proxy_http_name1=http-sticky-true.example.com" \\
 --label-add "com.example.proxy_http_front1=80" \\
 --label-add "com.example.proxy_http_back1=8080" \\
 --label-add "com.example.proxy_http_sticky1=true"

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'proxy http without sticky session' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service update --detach=false haproxy-test \\
 --label-add "com.example.proxy_http_name2=http-sticky-false.example.com" \\
 --label-add "com.example.proxy_http_front2=80" \\
 --label-add "com.example.proxy_http_back2=8081" \\
 --label-add "com.example.proxy_http_sticky2=false"

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'proxy https with sticky session' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service update --detach=false haproxy-test \\
 --label-add "com.example.proxy_https_name1=https-sticky-true.example.com" \\
 --label-add "com.example.proxy_https_front1=443" \\
 --label-add "com.example.proxy_https_back1=8443" \\
 --label-add "com.example.proxy_https_sticky1=true"

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'proxy https without sticky session' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service update --detach=false haproxy-test \\
 --label-add "com.example.proxy_https_name2=https-sticky-false.example.com" \\
 --label-add "com.example.proxy_https_front2=443" \\
 --label-add "com.example.proxy_https_back2=8444" \\
 --label-add "com.example.proxy_https_sticky2=false"

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'proxy tcp with sticky session' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service update --detach=false haproxy-test \\
 --label-add "com.example.proxy_tcp_front1=10001" \\
 --label-add "com.example.proxy_tcp_back1=10001" \\
 --label-add "com.example.proxy_tcp_sticky1=true"

    ''' + bcolors.ENDC)

    print(bcolors.OKGREEN + 'proxy tcp without sticky session' + bcolors.ENDC)
    print(bcolors.OKBLUE + '''
docker service update --detach=false haproxy-test \\
 --label-add "com.example.proxy_tcp_front2=10002" \\
 --label-add "com.example.proxy_tcp_back2=10002" \\
 --label-add "com.example.proxy_tcp_sticky2=false"
    ''' + bcolors.ENDC)


def loop():

    print("Waiting for docker events")
    watch_set = set(('update', 'remove',))

    try:

        for event in client.events(decode=True):

            if event['Action'] in watch_set and event['Type'] == 'service':

                time.sleep(int(CONF_TIMEOUT))

                print('Reconfigure haproxy with delay', str(CONF_TIMEOUT), ':', event)
                configure()

    except KeyboardInterrupt:
        pass


def main():

    if len(sys.argv) == 2:

        if sys.argv[1] == '-w':

            pid_file(PID_FILE, 'create')

            configure()
            loop()

            pid_file(PID_FILE, 'remove')

        elif sys.argv[1] == '-1':

            pid_file(PID_FILE, 'create')

            configure()

            pid_file(PID_FILE, 'remove')

        else:
            usage()

    else:
        usage()


if __name__ == '__main__':

    try:
        # client = docker.from_env()
        client = docker.DockerClient(base_url='unix://var/run/docker.sock')

    except OSError as e:
        print('Error:', e)
        sys.exit(1)

    sys.exit(main())
