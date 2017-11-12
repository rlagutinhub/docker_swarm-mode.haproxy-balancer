#!/bin/bash

set -e
set -x

if [ "${1:0:1}" = '-' ]; then
    set -- supervisord "$@"
fi

if [ "$1" = 'supervisord' ]; then

    shift
    set -- "$(which supervisord)" "$@"

fi

exec "$@"


