# !/usr/bin/env python3
import base64
import os
import quopri
import re

encoded_str_regexp = re.compile(
    r"\s*=\?(?P<charset>[^?]+)\?(?P<enc>[^?]+)\?(?P<data>.*)")


def decode_lines(lines) -> str:
    return ''.join((decode_str(line) for line in lines))


def decode_str(line: str) -> str:
    match = encoded_str_regexp.fullmatch(line)
    if match:
        return decode_data(
            match.group("data"),
            match.group("enc"),
            match.group("charset")
        )
    return line


def decode_data(data: str, encoding: str, charset: str) -> str:
    if encoding == 'B':
        return base64.b64decode(data).decode(encoding=charset)
    else:
        raise ValueError("Unexpected encoding: '" + encoding + "'")


mime_content_type_decoders = dict


def decode_by_content_type(data_lines, headers: dict, ):
    transfer_encoding = headers.setdefault("Content-Transfer-Encoding", "7bit")
    result = dict()

    args = [a.strip() for a in headers["Content-Type"].split(";")]
    actual_content_type = args[0]
    args = dict([a.split('=', maxsplit=1) for a in args[1:]])
    args.setdefault("charset", "ascii")

    if 'Content-Disposition' in headers and \
            'attachment' in headers['Content-Disposition']:
        cd_args = [a.strip() for a in
                   headers['Content-Disposition'].split(";")]
        cd_args = dict([a.split('=', maxsplit=1) for a in cd_args[1:]])

        name = cd_args.setdefault("filename", "unknown")
        with open(find_free_file(decode_filename(name)), "wb") as f:
            f.write(decode_by_transfer_encoding(b"\n".join(data_lines),
                                                transfer_encoding))
        return None
    elif 'text/' in actual_content_type:
        result[actual_content_type] = \
            decode_by_transfer_encoding(b'\n'.join(data_lines),
                                        transfer_encoding) \
                .decode(args["charset"], errors='ignore')
    elif 'multipart/' in actual_content_type:
        boundary = "--" + args['boundary'].replace('"', '')
        result[actual_content_type] = decode_multipart_parts(data_lines,
                                                             boundary.encode(
                                                                 "ascii"))
    else:
        name = args.setdefault("name", "unknown")
        with open(name, "wb") as f:
            f.write(decode_by_transfer_encoding(b"\n".join(data_lines),
                                                transfer_encoding))
    return result


def decode_filename(name):
    return clear_filename(decode_str(name.replace('"', '')))


def clear_filename(name):
    return name[name.replace('\\', '/').rfind('/') + 1:]


def decode_multipart_parts(data_lines, boundary: bytes) -> list:
    boundary_end = boundary + b"--"
    parts = []
    current_part = []
    current_part_headers = dict()
    last_header = ''
    headers_passed = False
    for line in data_lines:
        if line == boundary or line == boundary_end:
            if current_part:
                part = decode_by_content_type(current_part,
                                              current_part_headers)
                if part:
                    parts.append(
                        (current_part_headers["Content-Type"].split(";")[0],
                         part))
            current_part = []
            headers_passed = False
        elif headers_passed:
            current_part.append(line)
        else:
            if line:
                if b":" in line:
                    splitted = line.split(b": ", maxsplit=1)
                    last_header = splitted[0].decode()
                    current_part_headers[last_header] = \
                        decode_str(splitted[1].decode())
                else:
                    current_part_headers[last_header] += \
                        decode_str(line.decode().strip())
            else:
                headers_passed = True
    return parts


def decode_as_text(data, args):
    return data.decode(args["charset"])


def return_same(o):
    return o


mime_transfer_decoders = {
    "7bit": return_same,
    "8bit": return_same,
    "quoted-printable": quopri.decodestring,
    "base64": base64.b64decode
}


def decode_by_transfer_encoding(data: bytes, transfer_encoding: str) -> bytes:
    return mime_transfer_decoders[transfer_encoding.lower()](data)


def find_free_file(name: str, ext: str = None) -> str:
    def gen_filename(n):
        if ext:
            return name + ('' if n < 0 else "(" + str(n) + ")") + '.' + ext
        return ('' if n < 0 else "(" + str(n) + ")") + name

    filename = gen_filename(-1)
    i = 0
    while os.path.exists(filename):
        i += 1
        filename = gen_filename(i)
    return filename
