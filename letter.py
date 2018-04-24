# !/usr/bin/env python3
import decoder

class Letter:
    def __init__(self, headers: dict, data: list):
        self.headers = headers
        self.data = data

    @property
    def subject(self):
        return self.headers.setdefault("Subject", '')

    @property
    def from_(self):
        return self.headers.setdefault("From", 'unknown')

    @property
    def date_str(self):
        return self.headers.setdefault("Date", 'unknown')

    @property
    def content_type(self):
        return self.headers.setdefault("Content-Type", '*/*')

    @staticmethod
    def from_byte_lines(lines: list):
        headers = dict()
        data = []
        header_section = True
        key = ''
        for line in lines:
            if line == b'.':
                break
            if header_section:
                if line.strip() and (line[0] == b"\t"[0] or line[0] == b" "[0]):
                    headers[key] += "\n" + line.decode()
                elif line.decode().strip():
                    key, value = line.decode().split(": ", maxsplit=1)
                    headers[key] = value
                else:
                    header_section = False
            else:
                data.append(line)
        for key in headers:
            headers[key] = decoder.decode_lines(headers[key].split("\n"))
        return Letter(headers, data)
