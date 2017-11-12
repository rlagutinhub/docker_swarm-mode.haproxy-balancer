#! /bin/sh

set -e
set -x

cat <<EOF > /etc/profile.d/bash-color.sh
PS1='\[\e[1;33m\][\u@\h \W]\$\[\e[0m\]'
EOF

chmod +x /etc/profile.d/bash-color.sh

cat <<EOF > /etc/rsyslog.conf
# rsyslog configuration file

\$ModLoad imudp
\$UDPServerRun 514

local2.* /var/log/haproxy.log

EOF

chmod 0644 /etc/rsyslog.conf
