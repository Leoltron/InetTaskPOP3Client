# !/usr/bin/env python3
import contextlib

from client import POP3Client

USER = "user"
PASSWORD = "password"

if __name__ == '__main__':
    client = POP3Client('pop.someserver.com', 5555, USER, PASSWORD,
                        print_output=False, timeout=1)
    try:
        with contextlib.closing(client):
            client.connect()
            client.log_in()
            client.start_interactive_mode()
    except Exception as e:
        print(str(e))