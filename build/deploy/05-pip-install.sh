#! /bin/sh

set -e
set -x

pip2 install -U pip
#pip2 install -U ipython
pip2 install -U supervisor

pip3 install -U pip
#pip3 install -U ipython
pip3 install -U docker
pip3 install -U Jinja2
pip3 install -U pyOpenSSL
