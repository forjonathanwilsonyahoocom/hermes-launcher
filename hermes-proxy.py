#!/usr/bin/env python3
import os
import re
import json
import time
import uuid
import errno
import socket
import argparse
from datetime import datetime

from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client

CAPTURE_DIR_DEFAULT = "/tmp/hermes-proxy"

HOP_HEADERS = {
    # hop-by-hop headers that should not be forwarded as-is
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def safe_filename(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    return s[:200] if len(s) > 200 else s

def guess_extension(path: str, content_type: str | None, body_sniff: bytes | None):
    ct = (content_type or "").lower()
    if path.endswith("/v1/chat/completions") and ct.startswith("text/event-stream"):
        return ".sse"
    if ct.startswith("application/json"):
        return ".json"
    if ct.startswith("text/") or "xml" in ct:
        return ".txt"
    # best-effort
    if body_sniff:
        if body_sniff.lstrip().startswith(b"{") or body_sniff.lstrip().startswith(b"["):
            return ".json"
    return ".bin"

class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_ANY(self):
        # Map incoming path to upstream
        upstream_host = self.server.upstream_host
        upstream_port = self.server.upstream_port

        # Read full request body (we need complete JSON)
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            # No body or unknown; read nothing to avoid hanging
            req_body = b""
        else:
            try:
                n = int(content_length)
            except ValueError:
                n = 0
            req_body = self.rfile.read(n) if n > 0 else b""

        # Capture request metadata and body
        req_id = str(uuid.uuid4())
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        capture_dir = self.server.capture_dir

        # Determine endpoints for naming
        path = self.path
        clean_path = path.split("?", 1)[0]
        endpoint_tag = safe_filename(clean_path)

        # Write structured request body to disk
        req_ct = self.headers.get("Content-Type")
        ext = guess_extension(clean_path, req_ct, req_body[:200] if req_body else None)
        req_path = os.path.join(capture_dir, f"{ts}-{req_id}-request{ext}")
        self.server.req_seq += 1
        # Also store a small JSON metadata file for easier scanning
        req_meta_path = os.path.join(capture_dir, f"{ts}-{req_id}-request-meta.json")

        req_meta = {
            "seq": self.server.req_seq,
            "timestamp_utc": ts,
            "req_id": req_id,
            "method": self.command,
            "path": path,
            "headers": {k: v for k, v in self.headers.items()},
            "content_type": req_ct,
            "content_length": len(req_body),
        }
        with open(req_meta_path, "w", encoding="utf-8") as f:
            json.dump(req_meta, f, indent=2, ensure_ascii=False)

        # body may be large; still write fully
        with open(req_path, "wb") as f:
            f.write(req_body)

        # Forward request to upstream
        conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=0)
        try:
            # Build forwarded headers
            fwd_headers = {}
            for k, v in self.headers.items():
                lk = k.lower()
                if lk in HOP_HEADERS:
                    continue
                # Content-Length we set explicitly via body we already read
                if lk == "content-length":
                    continue
                fwd_headers[k] = v

            fwd_headers["Content-Length"] = str(len(req_body))

            conn.request(self.command, path, body=req_body, headers=fwd_headers)
            upstream_resp = conn.getresponse()

            status = upstream_resp.status
            reason = upstream_resp.reason
            resp_ct = upstream_resp.getheader("Content-Type")
            resp_te = upstream_resp.getheader("Transfer-Encoding")

            # Send response headers to downstream client
            # (critical for SSE: keep Content-Type and not buffer)
            self.send_response(status, reason)

            # Forward most headers except hop-by-hop
            for k, v in upstream_resp.getheaders():
                lk = k.lower()
                if lk in HOP_HEADERS:
                    continue
                # We'll re-handle content-length for streamed responses by not setting it.
                if lk == "content-length":
                    continue
                self.send_header(k, v)
            self.end_headers()

            # Capture full response body while streaming to client
            resp_sniff = upstream_resp.read(0)  # no-op; keeps API consistent
            # We can't “peek” without consuming; we will just stream and accumulate.
            # Use a temp file to avoid huge memory if desired.
            # For SSE, response can be long; we still capture everything to disk.
            ext_r = guess_extension(clean_path, resp_ct, None)
            resp_ts_path = os.path.join(capture_dir, f"{ts}-{req_id}-response{ext_r}")
            resp_meta_path = os.path.join(capture_dir, f"{ts}-{req_id}-response-meta.json")

            resp_meta = {
                "seq": self.server.req_seq,
                "timestamp_utc": ts,
                "req_id": req_id,
                "status": status,
                "reason": reason,
                "content_type": resp_ct,
                "transfer_encoding": resp_te,
                "headers": {k: v for k, v in upstream_resp.getheaders()},
            }
            with open(resp_meta_path, "w", encoding="utf-8") as f:
                json.dump(resp_meta, f, indent=2, ensure_ascii=False)

            total = 0
            # Stream in chunks: forward immediately, write to disk too
            with open(resp_ts_path, "wb") as out:
                while True:
                    chunk = upstream_resp.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    out.write(chunk)
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except BrokenPipeError:
                        # client hung up; upstream may still be streaming.
                        break

            # Update response total in meta
            resp_meta["content_length_captured"] = total
            with open(resp_meta_path, "w", encoding="utf-8") as f:
                json.dump(resp_meta, f, indent=2, ensure_ascii=False)

        finally:
            conn.close()

    def do_GET(self): self.do_ANY()
    def do_POST(self): self.do_ANY()
    def do_PUT(self): self.do_ANY()
    def do_DELETE(self): self.do_ANY()
    def do_OPTIONS(self): self.do_ANY()
    def do_HEAD(self): self.do_ANY()

    def log_message(self, format, *args):
        # Avoid terminal spam
        return

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=11435)
    ap.add_argument("--upstream-host", default="127.0.0.1")
    ap.add_argument("--upstream-port", type=int, default=11434)
    ap.add_argument("--capture-dir", default=CAPTURE_DIR_DEFAULT)
    args = ap.parse_args()

    ensure_dir(args.capture_dir)
    # Create a run subdir
    run_id = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    cap = os.path.join(args.capture_dir, f"run-{run_id}")
    ensure_dir(cap)

    class ThreadedHTTPServer(HTTPServer):
        pass

    httpd = ThreadedHTTPServer((args.listen_host, args.listen_port), ProxyHandler)
    httpd.upstream_host = args.upstream_host
    httpd.upstream_port = args.upstream_port
    httpd.capture_dir = cap
    httpd.req_seq = 0

    print(f"Proxy listening on {args.listen_host}:{args.listen_port} -> {args.upstream_host}:{args.upstream_port}")
    print(f"Capturing to: {cap}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()

