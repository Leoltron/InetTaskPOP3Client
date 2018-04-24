# !/usr/bin/env python3
import socket
import ssl
import re
import decoder
from letter import Letter

RETRIEVE_RE = re.compile(r"retrieve (?P<id>\d+)", re.IGNORECASE)
TOP_RE = re.compile(r"top (?P<id>\d+) (?P<lines>\d+)", re.IGNORECASE)
HEADERS_RE = re.compile(r"headers (?P<id>\d+)", re.IGNORECASE)


def _assert_pop3_ok(bytes_: bytes):
    if bytes_[0:3] != b'+OK' and bytes_[0:4] != b'-ERR':
        raise AssertionError(
            ((str(bytes_[:50]) + "...") if len(bytes_) > 50 else str(
                bytes_)) +
            " does not contain +OK in the beginning...")


def print_letter_headers(letter):
    for key in letter.headers:
        print(key + ": " + letter.headers[key])


def print_help():
    print(
        "Command list:\n"
        "\n\theaders <id>: print headers of letter"
        "\n\thelp: print this"
        "\n\tlist: show list of available letters"
        "\n\tretrieve <id>: download letter"
        "\n\ttop <id> <amount>: show amount lines of letter"
        "\n\tquit: quit interactive mode"
    )


class POP3Client:
    def __init__(self, ip: str, port: int, login: str, password: str,
                 timeout=2, print_output=False):
        self.password = password
        self.login = login
        self._ip = ip
        self._port = port
        self._timeout = timeout
        self._connected = False
        self.sock = None
        self.print_output = print_output

    def connect(self):
        if self.connected and self.sock:
            self.sock.close()
        try:
            print("Creating socket... ", end='', flush=True)
            sock = socket.socket()
            sock.settimeout(self._timeout)
            self.sock = ssl.wrap_socket(sock)
            print("Socket created.")
            print(
                "Connecting to [" + self._ip + ":" + str(self._port) + "]... ",
                end='', flush=True)
            self.sock.connect((self._ip, self._port))
            print("Connected.")
            print("Reading hello message... ", end='', flush=True)
            self._connected = True
            self._rcv()
            print("Done. Connection established.")
        except Exception as e:
            print(str(e))
            self._connected = False

    @property
    def connected(self):
        return self._connected

    def close(self):
        self.disconnect()

    def disconnect(self):
        if self.connected:
            if self.sock:
                self.quit()
                self.sock.close()
            self._connected = False

    def _rcv(self):
        if self.connected:
            message = b''
            try:
                buf = self.sock.recv(1024)
                while buf:
                    message += buf
                    buf = self.sock.recv(1024)
            except socket.timeout:
                pass
            if message:
                _assert_pop3_ok(message)
            if self.print_output:
                print(message.decode(encoding='utf-8', errors='ignore'))
            return message
        raise ConnectionError("Not connected.")

    def _send(self, bytes_):
        if self.connected:
            return self.sock.sendall(bytes_ + b'\n')
        raise ConnectionError("Not connected.")

    def start_interactive_mode(self):
        if not self.connected:
            self.connect()
            if not self.connected:
                return
        try:
            while True:
                print(">", end='')
                command = input().strip().lower()
                retr_match = RETRIEVE_RE.fullmatch(command)
                head_match = HEADERS_RE.fullmatch(command)
                top_match = TOP_RE.fullmatch(command)
                if command == 'help' or command == "?":
                    print_help()
                elif command == 'exit' or command == 'quit':
                    print("Goodbye.")
                    break
                elif command == 'list':
                    self.print_letters_info()
                elif retr_match:
                    self.retrieve(int(retr_match.group("id")))
                elif top_match:
                    letter = self.get_letter_top(int(top_match.group("id")),
                                                 int(top_match.group("lines")))
                    for line in letter.data:
                        print(line.decode('ascii'))
                elif head_match:
                    letter = self.get_letter_top(int(head_match.group("id")))
                    print_letter_headers(letter)
                else:
                    print(
                        "Unknown command. Print '?' to get full list of commands.")
        except Exception as e:
            print(str(e))
            raise
        finally:
            self.quit()

    def quit(self):
        self._send(b"QUIT")

    def log_in(self):
        print("Logging in...")
        self._send(b"USER " + self.login.encode('ascii'))
        print("User sent... ", end='')
        self._rcv()
        print("OK")
        self._send(b"PASS " + self.password.encode('ascii'))
        print("Password sent... ", end='')
        self._rcv()
        print("OK\nLogin successful.")

    def print_letters_info(self):
        self._send(b'LIST')
        data = self._rcv().replace(b'\r\n', b'\n').split(b'\n')

        splitted_first_line = data[0].split()
        letters_count = int(splitted_first_line[1])
        total_size = int(splitted_first_line[2])
        print("Total: " + str(letters_count) + (
            " letters" if letters_count != 1 else " letter") + ", " + str(
            total_size) + " bytes.")

        for i in range(letters_count):
            splitted = data[i + 1].split()
            id_ = int(splitted[0])
            size = int(splitted[1])
            letter = self.get_letter_top(id_)
            print("Letter #" + str(id_) +
                  " (" + str(size) + " bytes):" +
                  "\n\t From: " + letter.from_ +
                  '\n\t Subject: "' + letter.subject + '"' +
                  "\n\t Date: " + letter.date_str)

    def get_letter_top(self, id_: int, data_lines_count: int = 0) -> Letter:
        self._send(b'TOP ' + str(id_).encode('ascii') + b' ' +
                   str(data_lines_count).encode('ascii'))
        data = self._rcv().replace(b'\r\n', b'\n').split(b'\n')[1:]
        return Letter.from_byte_lines(data[1:])

    def retrieve(self, id_: int):
        self._send(b"RETR " + str(id_).encode('ascii'))
        data = self._rcv().replace(b'\r\n', b'\n').split(b'\n')[1:]
        letter = Letter.from_byte_lines(data)
        decoded = decoder.decode_by_content_type(letter.data, letter.headers)
        save_all(decoded)


def save_all(obj, content_type=None):
    obj_type = type(obj)

    if obj_type is list:
        for o in obj:
            save_all(o)
    elif obj_type is str and content_type:
        if content_type == 'text/plain':
            with open(decoder.find_free_file("letter", "txt"), "w",
                      encoding='utf-8') as f:
                f.write(obj)
        elif content_type == 'text/html':
            with open(decoder.find_free_file("letter", "html"), "w",
                      encoding='utf-8') as f:
                f.write(obj)
        else:
            print("No idea what to do with " + str(
                obj) + " and content type " + content_type)
    elif obj_type is tuple:
        save_all(obj[1], content_type=obj[0])
    elif obj_type is dict:
        for key in obj.keys():
            save_all(obj[key], content_type=key)
    else:
        print("No idea what to do with obj of type " + str(obj_type))
