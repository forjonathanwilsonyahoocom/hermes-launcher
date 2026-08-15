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

#use this compression in the request handler before forwarding

def compress_request(raw_body: bytes) -> bytes:
    try:
        # 1. bytes -> dict
        req_json = json.loads(raw_body.decode('utf-8'))

        # 2. Nuke the system prompt
        if req_json.get('messages') and len(req_json['messages']) > 0:
            req_json['messages'][0]['content'] = "Return JSON IR. Schema: {file, symbols:[{name, start_line, end_line, calls[]}]}. No prose."

        # 3. Strip tools - keep only what you need, or empty list
        if 'tools' in req_json:
            # For Pass A you don't need any tools if you inject the file yourself
            req_json['tools'] = []
            # Or keep specific ones:
            # req_json['tools'] = [t for t in req_json['tools']
            # if t['function']['name'] == 'read_file']

        # 4. dict -> str -> bytes
        compressed = json.dumps(req_json, separators=(',', ':')) # compact
        return compressed.encode('utf-8')

    except Exception as e:
        # If anything fails, pass through unchanged so you don't break the stream
        print(f"compress_request failed: {e}")
        return raw_body
        
        

# Then: forwarded_req = compress_request(original_req)

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
        req_body = compress_request(req_body)
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
            try:
                conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=60)
                # Build forwarded headers
                fwd_headers = {}
                for k, v in self.headers.items():
                    lk = k.lower()
                    if lk in HOP_HEADERS:
                        continue
                    if lk == "content-length":
                        continue
                    fwd_headers[k] = v
                fwd_headers["Content-Length"] = str(len(req_body))

                conn.request(self.command, path, body=req_body, headers=fwd_headers)
                upstream_resp = conn.getresponse()

                status = upstream_resp.status
                reason = upstream_resp.reason
                resp_ct = upstream_resp.getheader("Content-Type")

                self.send_response(status, reason)

                for k, v in upstream_resp.getheaders():
                    lk = k.lower()
                    if lk in HOP_HEADERS:
                        continue
                    if lk == "content-length":
                        continue
                    self.send_header(k, v)
                self.end_headers()

                ext_r = guess_extension(clean_path, resp_ct, None)
                resp_ts_path = os.path.join(capture_dir, f"{ts}-{req_id}-response{ext_r}")
                resp_meta_path = os.path.join(capture_dir, f"{ts}-{req_id}-response-meta.json")

                total = 0
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
                            break

                resp_meta = {
                    "seq": self.server.req_seq,
                    "timestamp_utc": ts,
                    "req_id": req_id,
                    "status": status,
                    "reason": reason,
                    "content_type": resp_ct,
                    "content_length_captured": total,
                    "headers": {k: v for k, v in upstream_resp.getheaders()},
                }
                with open(resp_meta_path, "w", encoding="utf-8") as f:
                    json.dump(resp_meta, f, indent=2, ensure_ascii=False)

            except Exception as e:
                # Return an error to the client instead of empty reply
                msg = f"Proxy error: {type(e).__name__}: {e}"
                try:
                    self.send_response(502, "Bad Gateway")
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(msg.encode("utf-8", errors="replace"))
                except Exception:
                    pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

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


