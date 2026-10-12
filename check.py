import socket, struct, json, time, os, re, random, csv, urllib.request
from concurrent.futures import ThreadPoolExecutor

SRC = os.environ.get("SRC_URL", "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt")
IPH, IPP = os.environ.get("IP_HOST", "api.ipify.org"), int(os.environ.get("IP_PORT", "80"))
HDH, HDP = os.environ.get("HDR_HOST", "httpbin.org"), int(os.environ.get("HDR_PORT", "80"))
MAX = int(os.environ.get("MAX", "6000"))      # сколько проверять за запуск
KEEP = int(os.environ.get("KEEP", "300"))     # сколько лучших в data.txt
T = 6

def recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise OSError("closed")
        b += c
    return b

def through(ip, port, host, hport, path):
    """GET через SOCKS5 без логина. Возвращает (тело, мс)."""
    t0 = time.time()
    s = socket.create_connection((ip, port), timeout=T); s.settimeout(T)
    try:
        s.sendall(b"\x05\x01\x00")
        if recvn(s, 2) != b"\x05\x00": raise OSError("auth")
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", hport))
        r = recvn(s, 4)
        if r[1] != 0: raise OSError("connect")
        recvn(s, {1: 6, 4: 18}.get(r[3]) or (recvn(s, 1)[0] + 2))
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while len(data) < 65536:
            c = s.recv(4096)
            if not c: break
            data += c
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    if b" 200" not in head.split(b"\r\n")[0]: raise OSError("status")
    return body.decode(errors="ignore"), int((time.time() - t0) * 1000)

def load():
    txt = urllib.request.urlopen(SRC, timeout=60).read().decode()
    seen, out = {}, []
    for l in txt.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", l)
        if not m or m[1].startswith("45.74.31."): continue
        if seen.get(m[1], 0) >= 2: continue      # не больше 2 портов на один IP
        seen[m[1]] = seen.get(m[1], 0) + 1
        out.append((m[1], int(m[2])))
    random.seed(1); random.shuffle(out)
    return out[:MAX]

def check(p):
    ip, port = p
    try:
        body, ms = through(ip, port, IPH, IPP, "/?format=json")
        exit_ip = json.loads(body[body.index("{"):body.rindex("}") + 1])["ip"]
        return ip, port, ms, exit_ip
    except Exception:
        return None

def anonymity(p, my_ip):
    try:
        body, _ = through(p[0], p[1], HDH, HDP, "/get")
        j = json.loads(body[body.index("{"):body.rindex("}") + 1])
        hd = {k.lower(): str(v) for k, v in j.get("headers", {}).items()}
        blob = json.dumps(hd) + str(j.get("origin", ""))
        if my_ip and my_ip in blob: return "Прозрачный"
        if any(k in hd for k in ("via", "x-forwarded-for", "forwarded", "x-real-ip")): return "Анонимный"
        return "Elite"
    except Exception:
        return "Неизвестно"

def geo(ips):
    res = {}
    ips = list(dict.fromkeys(ips))
    for i in range(0, len(ips), 100):
        try:
            req = urllib.request.Request("http://ip-api.com/batch?fields=query,countryCode,country,city",
                data=json.dumps(ips[i:i+100]).encode(), headers={"Content-Type": "application/json"})
            for r in json.loads(urllib.request.urlopen(req, timeout=20).read()):
                res[r["query"]] = r
        except Exception:
            pass
        time.sleep(4.5)
    return res

def main():
    try: my_ip = json.loads(urllib.request.urlopen(f"http://{IPH}:{IPP}/?format=json", timeout=10).read())["ip"]
    except Exception: my_ip = ""
    plist = load(); print("проверяю", len(plist))
    with ThreadPoolExecutor(300) as ex: alive = [r for r in ex.map(check, plist) if r]
    print("живых", len(alive))
    alive.sort(key=lambda r: r[2])
    with ThreadPoolExecutor(50) as ex: anon = list(ex.map(lambda r: anonymity(r, my_ip), alive))
    g = geo([r[3] for r in alive])
    rows = []
    for n, (r, a) in enumerate(zip(alive, anon), 1):
        x = g.get(r[3], {})
        cc = x.get("countryCode", "ZZ")
        rows.append([n, r[0], r[1], r[2], r[3], cc, x.get("country", ""), x.get("city", ""), a, f"socks://Og==@{r[0]}:{r[1]}#{cc}-{n}"])
    with open("results.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(["№", "IP", "Порт", "Пинг мс", "Выходной IP", "Код", "Страна", "Город", "Анонимность", "Ссылка для Happ"]); w.writerows(rows)
    with open("data.txt", "w") as f:
        for r in rows[:KEEP]: f.write(r[9] + "\n")
    print("готово: data.txt", min(KEEP, len(rows)), "строк")

if __name__ == "__main__": main()
