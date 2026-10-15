"""Runs INSIDE the jail, before the operator's script. Standard library only.

The jail has a private network namespace: only its own loopback. This boot
forks a relay that listens on 127.0.0.1:3128 and forwards every connection to
the runner's egress proxy (a unix socket in the work directory), then execs
the real script with the same interpreter flags. The proxy outside decides
what may be reached; this relay decides nothing.

    python -E -s -B _satom_boot.py <script.py> [args...]
"""
import os
import socket
import sys
import threading

PORT = 3128
SOCK = os.path.join(os.getcwd(), ".satom-egress.sock")


def _pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _serve(client):
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        up.connect(SOCK)
    except OSError:
        client.close()
        up.close()
        return
    t = threading.Thread(target=_pump, args=(up, client), daemon=True)
    t.start()
    _pump(client, up)
    t.join()
    client.close()
    up.close()


def _relay(listener):
    # Nothing of the script's stdout pipe or result descriptor stays open in
    # the relay: the runner reads stdout to EOF.
    lfd = listener.fileno()
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    os.closerange(3, lfd)
    os.closerange(lfd + 1, 4096)
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            os._exit(0)
        threading.Thread(target=_serve, args=(conn,), daemon=True).start()


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: _satom_boot.py <script.py> [args...]\n")
        return 2
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", PORT))
    listener.listen(64)
    if os.fork() == 0:
        _relay(listener)
    listener.close()
    os.execv(sys.executable,
             [sys.executable, "-E", "-s", "-B"] + sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
