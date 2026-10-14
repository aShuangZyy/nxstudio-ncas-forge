#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地 HTTPS MITM 代理（仅用于本机被测程序，不转发到外部服务之外的任何地方）。

功能：
  1) 接受 HTTP CONNECT host:443
  2) 用本地 CA 签出的叶证书做 TLS 终止
  3) 把解密后的请求（方法/路径/头/体）写日志
  4) 之后二选一：
     --relay         把请求转给真实上游（不校验证书），把响应原样返回并记录
     --rules FILE    按规则伪造响应（JSON 规则文件）

用法：
  python mitm.py --listen 8899 --cert _mitm/certs/leaf.pfx --pass mitm123 --log _mitm/mitm.log --relay
  python mitm.py --listen 8899 --cert _mitm/certs/leaf.pfx --pass mitm123 --log _mitm/mitm.log --rules _mitm/rules.json
"""
import argparse
import json
import os
import select
import socket
import ssl
import sys
import threading
import time

LOG_LOCK = threading.Lock()
LOGPATH = None


def log(line):
    stamp = time.strftime("%H:%M:%S")
    with LOG_LOCK:
        with open(LOGPATH, "a", encoding="utf-8") as f:
            f.write(f"[{stamp}] {line}\n")
    print(f"[{stamp}] {line}", flush=True)


def read_until_headers(sock):
    """读到 \r\n\r\n 为止，返回 (header_bytes, rest)。"""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None, buf
        buf += chunk
        if len(buf) > 262144:
            break
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def recv_exact(sock, n, pre):
    data = pre
    while len(data) < n:
        chunk = sock.recv(min(65536, n - len(data)))
        if not chunk:
            break
        data += chunk
    return data


def parse_headers(head_bytes):
    lines = head_bytes.split(b"\r\n")
    request_line = lines[0].decode("latin-1")
    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return request_line, headers


def read_http_message(sock, pre):
    head, rest = read_until_headers_pre(sock, pre)
    if head is None:
        return None
    request_line, headers = parse_headers(head)
    body = b""
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body, rest = read_chunked(sock, rest)
    else:
        n = int(headers.get("content-length", "0") or 0)
        if n:
            body = recv_exact(sock, n, rest)
            rest = body[n:]
            body = body[:n]
    return request_line, headers, body, rest


def read_until_headers_pre(sock, pre):
    buf = pre
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return (buf if buf else None), b""
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def read_chunked(sock, pre):
    data = pre
    out = b""
    while True:
        while b"\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                return out, b""
            data += chunk
        size_line, _, data = data.partition(b"\r\n")
        size = int(size_line.split(b";")[0], 16)
        if size == 0:
            while b"\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            _, _, data = data.partition(b"\r\n")
            return out, data
        while len(data) < size + 2:
            chunk = sock.recv(4096)
            if not chunk:
                return out, b""
            data += chunk
        out += data[:size]
        data = data[size + 2:]


def build_response(status, body, extra_headers=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    headers = [
        f"HTTP/1.1 {status}",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        "Connection: keep-alive",
    ]
    if extra_headers:
        headers += extra_headers
    return ("\r\n".join(headers) + "\r\n\r\n").encode("latin-1") + body


def load_rules(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def match_rule(rules, host, path):
    for rule in rules.get("rules", []):
        if rule.get("host") and rule["host"] not in host:
            continue
        needle = rule.get("path_contains")
        if needle and needle not in path:
            continue
        return rule
    return None


def host_matches_any(rules, host):
    """该主机是否会被任何规则处理（与 match_rule 的主机匹配口径一致）。

    没有规则命中时走"盲隧道"：只做 TCP 转发、不解密，浏览器等其它程序照常上网。
    """
    if not rules:
        return False
    h = (host or "").lower()
    for rule in rules.get("rules", []):
        needle = rule.get("host")
        if needle and needle.lower() in h:
            return True
    return False


def blind_tunnel(client, host, port):
    """无规则的 CONNECT：不解密，直接双向转发。"""
    try:
        up = socket.create_connection((host, port), timeout=15)
    except Exception as exc:  # noqa: BLE001
        log(f"!! 隧道连接失败 {host}:{port}: {exc}")
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except Exception:  # noqa: BLE001
            pass
        return
    try:
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    except Exception:  # noqa: BLE001
        up.close()
        return
    log(f"== 直通隧道 {host}:{port}（未命中规则，不解密）")
    up.setblocking(False)
    client.setblocking(False)
    socks = [client, up]
    idle = 0
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 5)
            if not r:
                idle += 1
                if idle > 60:  # 5 分钟完全静默就收摊
                    break
                continue
            idle = 0
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                other = up if s is client else client
                other.sendall(data)
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            up.close()
        except Exception:  # noqa: BLE001
            pass


def plain_http_passthrough(client, head, args):
    """明文 HTTP 代理请求：改写为 origin-form 后直连上游，双向转发。"""
    lines = head.split(b"\r\n")
    try:
        method, url, ver = lines[0].decode("latin-1").split(" ")[:3]
    except ValueError:
        client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        return
    headers = parse_headers(head)
    port = 80
    if url.lower().startswith("http://"):
        rest = url[7:]
        hostport, _, path = rest.partition("/")
        path = "/" + path
        if ":" in hostport:
            host, _, ps = hostport.partition(":")
            port = int(ps)
        else:
            host = hostport
    else:
        hp = headers.get("host", "")
        path = url
        if ":" in hp:
            host, _, ps = hp.partition(":")
            port = int(ps)
        else:
            host = hp
    if not host:
        client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        return
    if host_matches_any(args.rules_data, host):
        client.sendall(build_response("502 Bad Gateway", '{"error":"plain_http_rule_host"}'))
        log(f"<== 明文 HTTP 命中规则主机但未处理：{host}{path}")
        return
    try:
        up = socket.create_connection((host, port), timeout=15)
    except Exception as exc:  # noqa: BLE001
        log(f"!! 明文上游失败 {host}:{port}: {exc}")
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        return
    new_first = f"{method} {path} {ver}".encode("latin-1")
    body_lines = b"\r\n".join(lines[1:])
    up.sendall(new_first + b"\r\n" + body_lines + b"\r\n\r\n")
    log(f"== 明文直通 {host}:{port} {method} {path}")
    up.setblocking(False)
    client.setblocking(False)
    try:
        while True:
            r, _, _ = select.select([client, up], [], [], 30)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (up if s is client else client).sendall(data)
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            up.close()
        except Exception:  # noqa: BLE001
            pass


def handle_client(client, args, tls_ctx):
    peer = client.getpeername()
    try:
        client.settimeout(20)
        head, _ = read_until_headers(client)
        if head is None:
            return
        line = head.decode("latin-1").split("\r\n")[0]
        log(f"<- {peer} {line}")
        if not line.upper().startswith("CONNECT"):
            plain_http_passthrough(client, head, args)
            return
        target = line.split()[1]
        host = target.split(":")[0]
        port = 443
        if ":" in target:
            try:
                port = int(target.rsplit(":", 1)[1])
            except ValueError:
                port = 443
        if not host_matches_any(args.rules_data, host):
            blind_tunnel(client, host, port)
            return
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        try:
            tls = tls_ctx.wrap_socket(client, server_side=True)
        except ssl.SSLError as exc:
            log(f"!! TLS 握手失败 ({host}): {exc}")
            return
        log(f"== TLS 建立 host={host} 密码套件={tls.cipher()[0] if tls.cipher() else '?'}")

        pre = b""
        while True:
            msg = read_http_message(tls, pre)
            if msg is None:
                break
            request_line, headers, body, pre = msg
            method, path, _ = (request_line.split(" ") + ["", ""])[:3]
            log(f"--> {host} {request_line}")
            for k in ("content-type", "authorization", "user-agent", "accept", "soapaction"):
                if k in headers:
                    v = headers[k]
                    if k == "authorization":
                        v = v[:40] + "..." if len(v) > 40 else v
                    log(f"      {k}: {v}")
            if body:
                text = body.decode("utf-8", "replace")
                log(f"      BODY({len(body)}): {text[:2000]}")

            rule = match_rule(args.rules_data, host, path) if args.rules_data else None
            if rule is not None:
                payload = rule.get("body", "{}")
                if isinstance(payload, dict):
                    payload = json.dumps(payload)
                code = rule.get("status", "200 OK")
                tls.sendall(build_response(code, payload))
                log(f"<== 伪造响应 {code} rule={rule.get('name','?')} bytes={len(payload)}")
                continue

            if args.relay:
                resp = relay(host, request_line, headers, body, args)
                if resp is None:
                    tls.sendall(build_response("502 Bad Gateway", '{"error":"relay_failed"}'))
                    log("<== 上游失败 502")
                else:
                    tls.sendall(resp)
                    log(f"<== 转发上游 {len(resp)} bytes")
                continue

            tls.sendall(build_response("502 Bad Gateway", '{"error":"no_rule"}'))
            log("<== 无规则 502")
    except Exception as exc:  # noqa: BLE001
        log(f"!! 连接异常 {peer}: {type(exc).__name__}: {exc}")
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


def read_upstream_response(up):
    """按 Content-Length / chunked 精确读取，避免等待到超时。"""
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = up.recv(65536)
        if not d:
            return buf
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    headers = {}
    for ln in head.split(b"\r\n")[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    body = rest
    if headers.get("transfer-encoding", "").lower() == "chunked":
        while not chunked_complete(body):
            d = up.recv(65536)
            if not d:
                break
            body += d
    else:
        n = int(headers.get("content-length", "0") or 0)
        while len(body) < n:
            d = up.recv(65536)
            if not d:
                break
            body += d
    return head + b"\r\n\r\n" + body


def chunked_complete(buf):
    pos = 0
    while True:
        idx = buf.find(b"\r\n", pos)
        if idx < 0:
            return False
        try:
            size = int(buf[pos:idx].split(b";")[0], 16)
        except ValueError:
            return False
        if size == 0:
            return b"\r\n\r\n" in buf[idx:idx + 8] or len(buf) >= idx + 4
        pos = idx + 2 + size + 2
        if pos > len(buf):
            return False


def relay(host, request_line, headers, body, args):
    """把请求转发给真实上游（不校验证书），返回原始响应字节。"""
    try:
        raw = socket.create_connection((host, 443), timeout=20)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        up = ctx.wrap_socket(raw, server_hostname=host)
        out = [request_line.encode("latin-1") + b"\r\n"]
        skip = {"proxy-connection", "connection", "keep-alive"}
        for k, v in headers.items():
            if k in skip:
                continue
            out.append(f"{k}: {v}".encode("latin-1") + b"\r\n")
        out.append(b"Connection: close\r\n\r\n")
        up.sendall(b"".join(out) + body)
        up.settimeout(25)
        resp = read_upstream_response(up)
        up.close()
        head, _, respbody = resp.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode("latin-1") if head else "?"
        log(f"      <= 上游状态: {status}")
        log(f"      <= 上游体({len(respbody)}): {respbody[:4000].decode('utf-8','replace')}")
        return resp
    except Exception as exc:  # noqa: BLE001
        log(f"!! 转发失败 {host}: {type(exc).__name__}: {exc}")
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=8899)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", default=None)
    ap.add_argument("--pass", dest="pfx_pass", default="")
    ap.add_argument("--log", required=True)
    ap.add_argument("--relay", action="store_true")
    ap.add_argument("--rules", default=None)
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()

    global LOGPATH
    LOGPATH = args.log
    open(LOGPATH, "a", encoding="utf-8").close()
    args.rules_data = load_rules(args.rules) if args.rules else None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, keyfile=args.key, password=args.pfx_pass or None)
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.listen))
    srv.listen(50)
    srv.settimeout(1.0)
    log(f"MITM 已监听 127.0.0.1:{args.listen}  relay={args.relay} rules={'有' if args.rules_data else '无'}")
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        try:
            client, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle_client, args=(client, args, ctx), daemon=True).start()
    log("MITM 退出")


if __name__ == "__main__":
    main()
