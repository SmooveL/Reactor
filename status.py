"""Проверка статуса фишингового сайта (работает или уже заблокирован).

Все базовые сигналы собираются БЕЗ прямого посещения сайта. Единственная
прямая проверка (http) по умолчанию отключена и включается явно.

Сигналы в порядке надёжности:
  registry  - статус в RDAP (clientHold/serverHold — авторитетное снятие домена).
  dns       - резолвится ли хост и не сменились ли NS-серверы.
  urlscan   - сканировал ли кто-то сайт и каков вердикт (ключ не нужен).
  gsb       - показывает ли Google Safe Browsing предупреждение в Chrome.
  vt        - сколько движков VirusTotal уже пометили URL.
  http      - опционально: прямой запрос с вашего IP.
"""
import base64
import json
import os
import socket
import urllib.parse
from datetime import datetime, timezone

import reactor as fs

HOLD_STATES = ("client hold", "server hold", "clienthold", "serverhold",
               "pending delete", "redemption", "suspended")


def now():
    return datetime.now(timezone.utc).isoformat()


def check_registry(domain):
    d = fs.jget(f"https://rdap.org/domain/{domain}")
    if not d:
        return {"ok": False, "note": "не удалось получить данные RDAP", "status": [], "held": None}
    st = d.get("status", []) or []
    held = any(any(h in str(x).lower() for h in HOLD_STATES) for x in st)
    return {
        "ok": True,
        "status": st,
        "held": held,
        "note": (
            "регистратор приостановил домен (hold/suspended)"
            if held
            else "домен зарегистрирован и активен"
        ),
    }


def check_dns(host, domain, known_ns=None):
    ips, resolves = [], False
    for h in (host, domain):
        try:
            ips += [a[4][0] for a in socket.getaddrinfo(h, None)]
            resolves = True
        except Exception:
            pass
    ns = []
    r = fs.jget(f"https://dns.google/resolve?name={domain}&type=NS")
    if r:
        ns = sorted({a.get("data", "").strip(".").lower() for a in r.get("Answer", [])
                     if a.get("data")})
    moved = bool(known_ns and ns and set(ns) != {n.strip(".").lower() for n in known_ns})
    return {
        "ok": True,
        "resolves": resolves,
        "ips": sorted(set(ips)),
        "ns": ns,
        "ns_changed": moved,
        "note": (
            "больше не резолвится в DNS"
            if not resolves
            else "NS-серверы изменились с момента первой жалобы"
            if moved
            else "всё ещё резолвится в DNS"
        ),
    }


def check_urlscan(domain):
    q = urllib.parse.quote(f'page.domain:"{domain}"')
    s = fs.jget(f"https://urlscan.io/api/v1/search/?q={q}&size=1")
    if not s:
        return {"ok": False, "note": "ошибка запроса к urlscan.io"}
    results = s.get("results") or []
    if not results:
        return {"ok": True, "scanned": False, "note": "в urlscan.io ещё нет сканирований"}
    top = results[0]
    uuid = top.get("_id") or (top.get("task") or {}).get("uuid")
    verdict_val, score = None, None
    det = fs.jget(f"https://urlscan.io/api/v1/result/{uuid}/") if uuid else None
    if det:
        v = (det.get("verdicts") or {}).get("overall") or {}
        verdict_val, score = v.get("malicious"), v.get("score")
    return {
        "ok": True,
        "scanned": True,
        "when": (top.get("task") or {}).get("time"),
        "malicious": verdict_val,
        "score": score,
        "screenshot": top.get("screenshot"),
        "report": f"https://urlscan.io/result/{uuid}/" if uuid else None,
        "note": (
            "просканирован, признан вредоносным"
            if verdict_val
            else "просканирован, вердикта о вредоносности нет"
            if verdict_val is False
            else "просканирован"
        ),
    }


def check_virustotal(url):
    key = os.getenv("VT_API_KEY")
    if not key:
        return {"ok": False, "note": "ключ VirusTotal не задан"}
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    st, raw = fs.http(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": key})
    if st == 404:
        return {"ok": False, "note": "ещё нет в VirusTotal — ссылка отправится при следующей жалобе"}
    if st in (401, 403):
        return {"ok": False, "note": f"VirusTotal отклонил ключ (HTTP {st})"}
    try:
        d = json.loads(raw)
    except ValueError:
        d = None
    if not d:
        return {"ok": False, "note": f"ошибка запроса к VirusTotal (HTTP {st})"}
    a = ((d.get("data") or {}).get("attributes") or {})
    stats = a.get("last_analysis_stats") or {}
    flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    return {
        "ok": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "flagged": flagged,
        "reputation": a.get("reputation"),
        "note": (f"помечен движками: {flagged}" if flagged else "пока не помечен ни одним движком"),
    }


def check_safebrowsing(url):
    """Показывает ли Chrome предупреждение? Главный сигнал реальной защиты пользователей."""
    key = os.getenv("GSB_API_KEY")
    if not key:
        return {"ok": False, "note": "ключ Google Safe Browsing не задан"}
    body = {
        "client": {"clientId": "reactor", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    st, raw = fs.http(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                      data=body)
    if st != 200:
        msg = ""
        try:
            msg = (json.loads(raw).get("error") or {}).get("message", "")
        except ValueError:
            pass
        if "referer" in msg.lower():
            msg = (
                "API-ключ ограничен по HTTP referer; сервер его не передаёт. "
                "В Google Cloud Console -> Credentials -> ваш ключ -> Application "
                "restrictions выберите None (или IP addresses)"
            )
        return {"ok": False, "note": f"Google Safe Browsing отклонил ключ (HTTP {st}): {msg}"[:300]}
    try:
        matches = (json.loads(raw) or {}).get("matches") or []
    except ValueError:
        return {"ok": False, "note": "Google Safe Browsing вернул некорректный ответ"}
    kinds = sorted({m.get("threatType", "") for m in matches})
    return {
        "ok": True,
        "listed": bool(matches),
        "threats": kinds,
        "note": (
            "Chrome предупреждает посетителей: " + ", ".join(kinds)
            if matches
            else "пока нет в Google Safe Browsing"
        ),
    }


def check_http(url):
    """Опционально: выполняет прямой HTTP-запрос с вашего IP."""
    st, body = fs.http(url)
    low = (body or "").lower()
    warned = ("suspected phishing" in low or "deceptive site" in low
              or "warning: suspected phishing" in low)
    dead = st in (0, 403, 404, 410, 500, 502, 503, 521, 522, 523, 525, 530)
    return {
        "ok": True,
        "code": st,
        "cloudflare_warning": warned,
        "looks_dead": dead,
        "note": (
            "Cloudflare показывает предупреждение о фишинге"
            if warned
            else f"сервер вернул HTTP {st}"
            if st
            else "нет ответа"
        ),
    }


def verdict(sig):
    """Считает сайт снятым только при положительных доказательствах, но не при ошибках проверки."""
    reg, dns = sig.get("registry", {}), sig.get("dns", {})
    if reg.get("held"):
        return "suspended", "регистратор приостановил домен (hold) — это реальная блокировка"
    if dns.get("ok") and not dns.get("resolves"):
        moved = " и его NS-серверы изменились" if dns.get("ns_changed") else ""
        return "offline", (
            "домен не резолвится" + moved
            + ", но всё ещё зарегистрирован и не приостановлен — сайт может вернуться в любой момент"
        )
    http = sig.get("http") or {}
    if http.get("cloudflare_warning"):
        return "blocked", "Cloudflare предупреждает посетителей о фишинге"
    if http.get("ok") and http.get("looks_dead"):
        return "blocked", f"сервер вернул HTTP {http.get('code')}"
    gsb = sig.get("safebrowsing") or {}
    if gsb.get("listed"):
        return "blocked", "Google Safe Browsing предупреждает посетителей"
    vt = sig.get("vt") or {}
    us = sig.get("urlscan") or {}
    if vt.get("flagged") or us.get("malicious"):
        return "live-flagged", "сайт ещё работает, но уже попал в блок-листы"
    if dns.get("resolves"):
        return "live", "сайт работает и пока нигде не помечен"
    return "unknown", "недостаточно данных"


def check(url, host, domain, known_ns=None, touch_site=False):
    sig = {
        "registry": check_registry(domain),
        "dns": check_dns(host, domain, known_ns),
        "safebrowsing": check_safebrowsing(url),
        "urlscan": check_urlscan(domain),
        "vt": check_virustotal(url),
    }
    if touch_site:
        sig["http"] = check_http(url)
    state, why = verdict(sig)
    return {
        "checked": now(),
        "state": state,
        "why": why,
        "signals": sig,
        "touched_site": bool(touch_site),
        "had_http": bool(sig.get("http", {}).get("ok")),
    }


def selftest():
    assert verdict({"registry": {"held": True}})[0] == "suspended"
    # Пропажа DNS без hold у регистратора — не окончательное снятие
    v, why = verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": False}})
    assert v == "offline" and "всё ещё зарегистрирован" in why, (v, why)
    v, why = verdict({"registry": {"held": False},
                      "dns": {"ok": True, "resolves": False, "ns_changed": True}})
    assert "NS-серверы изменились" in why
    # Сбой запроса RDAP на живом сайте не должен трактоваться как блокировка
    assert verdict({"registry": {"ok": False, "held": None},
                    "dns": {"ok": True, "resolves": True}})[0] == "live"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "vt": {"flagged": 7}})[0] == "live-flagged"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "safebrowsing": {"listed": True}})[0] == "blocked"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "safebrowsing": {"ok": False}})[0] == "live", \
        "отсутствие ключа Google Safe Browsing не должно считаться доказательством чистоты"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "http": {"ok": True, "cloudflare_warning": True}})[0] == "blocked"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "http": {"ok": True, "looks_dead": True, "code": 522}})[0] == "blocked"
    # Обычные EPP-статусы не являются hold
    st = ["client transfer prohibited", "add period"]
    assert not any(any(h in s.lower() for h in HOLD_STATES) for s in st)
    assert any(any(h in s.lower() for h in HOLD_STATES) for s in ["clientHold"])
    print("status selftest OK")


if __name__ == "__main__":
    selftest()
