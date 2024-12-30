#!/usr/bin/env python3

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import re
import os
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVER_AES_KEY = bytes.fromhex(os.getenv("SERVER_AES_KEY", "ff"*32))
SERVER_AES_IV = bytes.fromhex(os.getenv("SERVER_AES_IV", "ff"*16))

assert hashlib.sha256(SERVER_AES_KEY+SERVER_AES_IV).digest()[:4].hex() == "f15588fd", "invalid SERVER_AES_KEY and/or SERVER_AES_IV"


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.protocol_version = "HTTP/1.1"
        if ".php" in self.path or ".cfg" in self.path:
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

    def do_GET(self):
        self.protocol_version = "HTTP/1.1"

        if "/status.php" in self.path:
            msg = b'OK>text=Hello there.;'
            #msg = b"SERVER>text=Server is down!;"
            self.send_response(200)
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

        elif "/check_uuid.php" in self.path:
            m = re.search(r"UID=([A-F0-9]+)", self.path)
            if m is not None:
                serial = m.group(1)
            else:
                serial = "DEADBEEF"

            msg = f"OK_INDB:{serial}:0A:".encode()
            msg += b" "*(16-(len(msg) % 16))
            cipher = Cipher(algorithms.AES(SERVER_AES_KEY), modes.CBC(SERVER_AES_IV))
            encryptor = cipher.encryptor()
            ct = encryptor.update(msg) + encryptor.finalize()
            ct = base64.b64encode(ct)

            self.send_response(200)
            self.send_header("Content-Length", str(len(ct)))
            self.end_headers()
            self.wfile.write(ct)

        elif "_BLHeli32DefaultsX.cfg" in self.path:
            try:
                with open("./BLHeli32DefaultsX.cfg", "rb") as fh:
                    msg = fh.read()
                cl = str(len(msg))
                st = 200
            except Exception:
                msg = b""
                cl = "0"
                st = 404

            self.send_response(st)
            self.send_header("Content-Length", cl)
            self.end_headers()
            self.wfile.write(msg)

        elif "/_BLHeli32ServerHexFiles.cfg" in self.path:
            # TODO figure out file format
            lines = [
                #"HAKRC_35A_Multi_32_109.Hex{test=1,foo=bar}",
                "",
                "",
            ]
            lines = "\n".join(lines)
            lines = lines.encode()

            self.send_response(200)
            self.send_header("Content-Length", str(len(lines)))
            self.end_headers()
            self.wfile.write(lines)

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


# use /etc/hosts (or some other mechanism) to remap blheli.org to localhost
httpd = HTTPServer(("localhost", 443), SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.check_hostname = False
ctx.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
