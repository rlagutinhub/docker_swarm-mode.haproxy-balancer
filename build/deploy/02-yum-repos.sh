#! /bin/sh

set -e
set -x

# epel repo
yum -y --setopt=tsflags=nodocs install epel-release
