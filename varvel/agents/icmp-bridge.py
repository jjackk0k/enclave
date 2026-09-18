# VARVEL — ICMP raw-socket bridge (native termination for the governed channel's
# ICMP fallback transport). Node has no raw-ICMP access; this helper is the piece
# that does. It is deliberately DUMB: the proven codec (engine/icmpcodec.mjs)
# stays the single implementation in JS — this process only moves raw bytes.
#
# Protocol: JSON lines on stdio (stdout is protocol-only; run with `python -u`).
#   -> parent : {"op":"capability","supported":bool,"reason":str}   (always the FIRST line)
#   parent -> : {"id":N,"op":"send","dst":"1.2.3.4","packetB64":"..."}
#   -> parent : {"id":N,"op":"sent","bytes":L} | {"id":N,"op":"error","error":str}
#   -> parent : {"op":"recv","src":"1.2.3.4","packetB64":"..."}
#
# Raw sockets need Administrator on Windows / root (or CAP_NET_RAW) elsewhere.
# Unprivileged start is NOT a crash: report capability supported:false and exit 0 —
# the channel stays up on HTTP/DNS and reports ICMP honestly as unavailable.
# Governance (HMAC, seq, scope ring) lives above this layer in the channel — a
# frame this helper moves is just an envelope until the channel validates it.

import json
import socket
import sys
import threading

_send_lock = threading.Lock()
_sock = None


def emit(obj):
    line = json.dumps(obj)
    with _send_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def open_raw():
    """Probe the raw ICMP socket. Returns (sock, reason)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(None)
        return s, ""
    except OSError as e:
        return None, "raw ICMP socket refused: %s (elevated Administrator/root required)" % e


def _checksum(data):
    """RFC 1071 internet checksum (probe packets only — VARVEL frames arrive pre-built)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total = (total + ((data[i] << 8) | data[i + 1])) & 0xFFFFFFFF
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def self_probe(sock):
    """Socket-open is NOT proof the wire moves (Windows may allow the open while
    send/receive stays restricted). Send one plain echo request to loopback and
    require SOME ICMP traffic back within 1.5s — our copy or the kernel's reply.
    Returns (ok, reason)."""
    body = b"\x08\x00\x00\x00" + (0x5601).to_bytes(2, "big") + (1).to_bytes(2, "big") + b"varvel-probe"
    pkt = body[:2] + _checksum(body).to_bytes(2, "big") + body[4:]
    try:
        sock.sendto(pkt, ("127.0.0.1", 0))
    except OSError as e:
        return False, "raw ICMP socket opens but SEND is blocked: %s (elevated Administrator/root required)" % e
    try:
        sock.settimeout(1.5)
        sock.recvfrom(65535)
        return True, ""
    except socket.timeout:
        return False, "raw ICMP socket opens but no loopback echo returned — receive path restricted (elevated Administrator/root required)"
    except OSError as e:
        return False, "raw ICMP receive failed: %s" % e
    finally:
        sock.settimeout(None)


def strip_ip_header(data):
    """Raw IPv4 sockets deliver the IP header on receive (Windows + Linux alike).
    Return just the ICMP message. If it doesn't look like IPv4, pass through as-is
    (some loopback paths deliver the bare ICMP message)."""
    if len(data) >= 20 and (data[0] >> 4) == 4:
        ihl = (data[0] & 0x0F) * 4
        if 20 <= ihl <= len(data):
            return data[ihl:]
    return data


def recv_loop():
    while True:
        try:
            data, addr = _sock.recvfrom(65535)
        except OSError:
            return  # socket closed — parent is shutting us down
        pkt = strip_ip_header(data)
        if not pkt:
            continue
        try:
            emit({"op": "recv", "src": addr[0], "packetB64": __import__("base64").b64encode(pkt).decode("ascii")})
        except Exception:
            return  # stdout broken — nothing left to do


def main():
    global _sock
    _sock, reason = open_raw()
    if _sock is None:
        emit({"op": "capability", "supported": False, "reason": reason})
        return 0
    ok, reason = self_probe(_sock)
    if not ok:
        emit({"op": "capability", "supported": False, "reason": reason})
        return 0
    emit({"op": "capability", "supported": True, "reason": "raw ICMP socket open + loopback probe answered"})

    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()

    import base64
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            emit({"op": "error", "error": "bad json line"})
            continue
        if msg.get("op") != "send":
            emit({"id": msg.get("id"), "op": "error", "error": "unknown op"})
            continue
        mid = msg.get("id")
        try:
            pkt = base64.b64decode(str(msg.get("packetB64", "")))
            dst = str(msg.get("dst", ""))
            socket.inet_aton(dst)  # validate the literal before touching the socket
            sent = _sock.sendto(pkt, (dst, 0))
            emit({"id": mid, "op": "sent", "bytes": sent})
        except (OSError, ValueError) as e:
            emit({"id": mid, "op": "error", "error": str(e)})
    return 0  # stdin EOF — parent closed the pipe


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
