#!/usr/bin/env python2

# How to exit all supervisor processes if one exited with 0 result
# http://supervisord.org/events.html#event-event-type

import os
import re
import sys
import time
import signal
import subprocess


from supervisor.childutils import listener


def usage():

    print('pass str processnames, and int timeout')


def write_stdout(s):
    sys.stdout.write(s)
    sys.stdout.flush()


def write_stderr(s):
    sys.stderr.write(s)
    sys.stderr.flush()


def check_process(process):

    returnprocess = False
    s = subprocess.Popen(["ps", "ax"], stdout=subprocess.PIPE)

    for x in s.stdout:

        if re.search(process, x):
            returnprocess = True


def check_pid(pid):

    try:
        os.kill(pid, 0)

    except OSError:
        return False

    else:
        return True


def kill_pid(pid):

    return os.kill(pid, signal.SIGQUIT)


def main():

    while True:

        headers, body = listener.wait(sys.stdin, sys.stdout)
        body = dict([pair.split(":") for pair in body.split(" ")])

        write_stderr("Headers: %r\n" % repr(headers))
        write_stderr("Body: %r\n" % repr(body))

        try:

            if body["processname"] == program_name:

                if headers["eventname"] != "PROCESS_STATE_RUNNING":

                    i = 0
                    check_program_pid = False
                    time.sleep(5)  # first timeout 5s

                    while i < timeout:

                        time.sleep(1)

                        if os.path.exists(program_pid) and os.path.isfile(program_pid):

                            pidfile = open(program_pid, 'rt')
                            pid = int(pidfile.readline())

                            if check_pid(pid):
                                check_program_pid = True
                                break

                        i += 1

                    if not check_program_pid:

                        try:
                            pidfile = open(supervisord_pid, 'rt')
                            pid = int(pidfile.readline())
                            kill_pid(pid)

                        except Exception as e:
                            write_stderr("Unexpected Exception: " + str(e))
                            sys.exit(0)


        except Exception as e:
            write_stderr("Unexpected Exception: " + str(e))
            listener.fail(sys.stdout)
            sys.exit(1)

        else:
            listener.ok(sys.stdout)


if __name__ == '__main__':

    if len(sys.argv) == 5:

        try:

            scr_name = str(sys.argv[0])
            supervisord_pid = str(sys.argv[1])
            program_name = str(sys.argv[2])
            program_pid = str(sys.argv[3])
            timeout = int(sys.argv[4])

            main()

        except ValueError as e:
            write_stderr("Unexpected Exception: " + str(e))
            sys.exit(1)

    else:

        usage()
        sys.exit(0)
