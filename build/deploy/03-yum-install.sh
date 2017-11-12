#! /bin/sh

set -e
set -x

# system
yum -y --setopt=tsflags=nodocs install \
 bash-completion \
 iproute \
 bind-utils \
 which \
 less \
 wget \
 curl \
 openssl \
 net-tools \
 sysvinit-tools \
 lsof \
 nmap \
 tcpdump \
 telnet \
 tree \
 zip \
 unzip \
 vim-enhanced

# rsyslog
yum -y --setopt=tsflags=nodocs install rsyslog

# python
yum -y --setopt=tsflags=nodocs install python2 python2-pip python34 python34-pip python-devel python34-devel

# haproxy
yum -y --setopt=tsflags=nodocs install haproxy
