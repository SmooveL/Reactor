#!/usr/bin/env python3
"""reactor - инструмент подачи жалоб на фишинговые ресурсы («Золотое Яблоко»).

Принимает фишинговую ссылку, собирает данные о домене (RDAP/DNS), отправляет
ссылку в API блок-листов, готовит .eml-жалобы для регистратора/хостера и
формирует список веб-форм вендоров с предзаполнением.

Stdlib only. No pip install.

Usage:
    python3 reactor.py https://www.example.top/          # dry run, recon only
    python3 reactor.py https://www.example.top/ --send   # actually report
    python3 reactor.py --selftest
"""
import argparse
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import channels
from email.message import EmailMessage

UA = "Mozilla/5.0 (compatible; abuse-reporter/1.0)"
TIMEOUT = 25

TARGET_BRAND = "goldapple"
TARGET_BRAND_LABEL = "Золотое Яблоко (goldapple.ru)"

DEFAULT_LEGIT_DOMAINS = (
    "goldapple.ru",
    "goldapple.kz",
    "goldapple.by",
    "goldapple.sa",
    "goldapple.qa",
    "goldapple.ae",
)

BRAND_MARKERS = (
    "goldapple",
    "gold-apple",
    "gold_apple",
    "gold apple",
    "золотое яблоко",
    "золотого яблока",
    "золотому яблоку",
    "золотым яблоком",
    "золотом яблоке",
    "goldaple",
    "g0ldapple",
)

# Чужие бренды удалены; копия службе безопасности бренда не отправляется.
BRAND_ABUSE = {}

# Always-on email clearinghouses.
CLEARINGHOUSES = [
    ("APWG", "reportphishing@apwg.org"),
    ("Netcraft (email fallback)", "scam@netcraft.com"),
]

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


class OfficialDomainError(ValueError):
    """Исключение при попытке пожаловаться на официальный домен «Золотого Яблока»."""


def load_legit_domains(config_path=None):
    """Читает список официальных доменов из config.json, с откатом на DEFAULT_LEGIT_DOMAINS."""
    path = config_path or _CONFIG_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        doms = cfg.get("legit_domains")
        if isinstance(doms, list) and doms:
            cleaned = [str(d).strip().lower().rstrip(".") for d in doms if str(d).strip()]
            if cleaned:
                return tuple(cleaned)
    except Exception:
        pass
    return DEFAULT_LEGIT_DOMAINS


def is_legit_domain(url, legit_domains=None):
    """Точная проверка официального домена или его поддомена.

    goldapple.ru и shop.goldapple.ru -> True (запрещено жаловаться).
    goldapple.ru.fake-site.top -> False (разрешено).
    """
    domains = legit_domains if legit_domains is not None else load_legit_domains()
    raw = (url or "").strip()
    if not raw:
        return False
    parsed = urllib.parse.urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False
    for domain in domains:
        d = (domain or "").strip().lower().rstrip(".")
        if not d:
            continue
        if host == d or host.endswith("." + d):
            return True
    return False


def looks_like_goldapple(text="", url=""):
    """Проверяет, есть ли в ссылке или тексте упоминание «Золотого Яблока»."""
    hay = f"{text or ''} {url or ''}".lower()
    return any(marker in hay for marker in BRAND_MARKERS)


# ---------------------------------------------------------------- http helpers

def http(url, data=None, headers=None, method=None, timeout=None):
    """Returns (status, body_text). Never raises on HTTP error status."""
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout or TIMEOUT,
                                    context=ssl.create_default_context()) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # DNS death, timeout, TLS, whatever
        return 0, f"{type(e).__name__}: {e}"


def jget(url, headers=None, timeout=None):
    st, body = http(url, headers=headers, timeout=timeout)
    if st != 200:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


# --------------------------------------------------------------------- recon

# Hosting platforms where each customer gets a subdomain. The tenant label IS the
# site: treating these as ordinary domains would have us reporting Cloudflare or
# Google to their own registrar instead of reporting the scammer.
PLATFORM_SUFFIXES = {
    "pages.dev", "workers.dev", "r2.dev", "vercel.app", "netlify.app", "netlify.com",
    "github.io", "gitlab.io", "web.app", "firebaseapp.com", "hosted.app", "run.app",
    "appspot.com", "herokuapp.com", "onrender.com", "fly.dev", "surge.sh", "glitch.me",
    "repl.co", "replit.app", "000webhostapp.com", "wixsite.com", "weeblysite.com",
    "blogspot.com", "square.site", "myshopify.com", "webflow.io", "framer.app",
    "bubbleapps.io", "notion.site", "canva.site", "durable.co", "trycloudflare.com",
    "ngrok.io", "ngrok-free.app", "serveo.net", "loca.lt", "codeanyapp.com",
}

TWO_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.cn",
                      "com.br", "com.au", "co.nz", "co.za", "com.tw", "com.hk",
                      "com.sg", "co.kr", "com.mx", "co.in", "com.tr"}


def platform_suffix(host):
    """The hosting platform this host sits on, or None."""
    h = (host or "").lower().strip(".")
    for suf in PLATFORM_SUFFIXES:
        if h == suf or h.endswith("." + suf):
            return suf
    return None


def registrable_domain(host):
    """Good-enough eTLD+1, with hosting platforms treated as public suffixes."""
    host = (host or "").lower().strip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    suf = platform_suffix(host)
    if suf:
        # keep the tenant label: evil.pages.dev, not pages.dev
        depth = len(suf.split(".")) + 1
        return ".".join(parts[-depth:]) if len(parts) >= depth else host
    if ".".join(parts[-2:]) in TWO_LABEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def rdap_emails(obj):
    """Pull every abuse-ish email out of an RDAP entity tree (vCard jCard)."""
    found = []

    def walk(node, in_abuse):
        if isinstance(node, dict):
            roles = node.get("roles") or []
            abuse = in_abuse or ("abuse" in [r.lower() for r in roles])
            vc = node.get("vcardArray")
            if vc and len(vc) > 1:
                for entry in vc[1]:
                    if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "email":
                        found.append((abuse, str(entry[3])))
            for v in node.values():
                walk(v, abuse)
        elif isinstance(node, list):
            for v in node:
                walk(v, in_abuse)

    walk(obj, False)
    abuse_first = [e for a, e in found if a] or [e for _, e in found]
    seen, out = set(), []
    for e in abuse_first:
        if e.lower() not in seen and "@" in e:
            seen.add(e.lower())
            out.append(e)
    return out


def recon(url):
    p = urllib.parse.urlparse(url)
    host = p.hostname or ""
    dom = registrable_domain(host)
    info = {
        "url": url,
        "host": host,
        "domain": dom,
        "ips": [],
        "registrar": None,
        "registrar_abuse": [],
        "created": None,
        "ns": [],
        "ip_abuse": [],
        "network": None,
        "cloudflare": False,
        "brand": TARGET_BRAND,
        "brand_label": TARGET_BRAND_LABEL,
        "is_legit": is_legit_domain(url),
        "brand_match": looks_like_goldapple("", url),
    }

    try:
        info["ips"] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except Exception:
        pass

    d = jget(f"https://rdap.org/domain/{dom}") or jget(
        f"https://rdap.zdnsgtld.com/{dom.rsplit('.', 1)[-1]}/domain/{dom}"
    )
    if d:
        info["registrar_abuse"] = rdap_emails(d)
        for ent in d.get("entities", []):
            if "registrar" in [r.lower() for r in ent.get("roles", [])]:
                vc = ent.get("vcardArray")
                if vc and len(vc) > 1:
                    for e in vc[1]:
                        if isinstance(e, list) and e[0] == "fn":
                            info["registrar"] = str(e[3])
        for ev in d.get("events", []):
            if ev.get("eventAction") == "registration":
                info["created"] = ev.get("eventDate")
        info["ns"] = [n.get("ldhName", "") for n in d.get("nameservers", [])]

    if not info["ns"]:
        st, body = http(f"https://dns.google/resolve?name={dom}&type=NS")
        if st == 200:
            try:
                info["ns"] = [a["data"].strip(".") for a in json.loads(body).get("Answer", [])]
            except Exception:
                pass

    info["cloudflare"] = any("cloudflare" in n.lower() for n in info["ns"])

    for ip in info["ips"][:2]:
        ipd = jget(f"https://rdap.org/ip/{ip}")
        if ipd:
            info["network"] = ipd.get("name") or info["network"]
            info["ip_abuse"] += [e for e in rdap_emails(ipd) if e not in info["ip_abuse"]]
    return info


def guess_brand(info):
    """Единственный бренд проекта — «Золотое Яблоко». Копия на бренд не отправляется."""
    return TARGET_BRAND, ""


# ------------------------------------------------------------------ API submits

def submit_netcraft(url, reporter):
    if is_legit_domain(url):
        return "BLOCKED", "Официальный домен «Золотого Яблока» — отправка жалобы запрещена"
    if not reporter:
        return "SKIP", "set REPORTER_EMAIL"
    payload = {
        "email": reporter,
        "urls": [{"url": url, "country": "RU"}],
        "reason": f"Phishing site impersonating {TARGET_BRAND_LABEL}.",
    }
    for attempt in (1, 2):   # their API 400s intermittently on a first, valid POST
        st, body = http("https://report.netcraft.com/api/v3/report/urls", data=payload)
        if st in (200, 201):
            return "OK", body[:300]
        if attempt == 1:
            import time as _t
            _t.sleep(2)
    return f"HTTP {st}", body[:300]


def submit_urlscan(url):
    if is_legit_domain(url):
        return "BLOCKED", "Официальный домен «Золотого Яблока» — отправка жалобы запрещена"
    key = os.getenv("URLSCAN_API_KEY")
    if not key:
        return "SKIP", "set URLSCAN_API_KEY (free at urlscan.io/user/signup)"
    st, body = http(
        "https://urlscan.io/api/v1/scan/",
        data={"url": url, "visibility": "public", "tags": ["phishing"]},
        headers={"API-Key": key},
    )
    return ("OK" if st == 200 else f"HTTP {st}"), body[:300]


def submit_virustotal(url):
    if is_legit_domain(url):
        return "BLOCKED", "Официальный домен «Золотого Яблока» — отправка жалобы запрещена"
    key = os.getenv("VT_API_KEY")
    if not key:
        return "SKIP", "set VT_API_KEY (free at virustotal.com)"
    data = urllib.parse.urlencode({"url": url}).encode()
    req = urllib.request.Request(
        "https://www.virustotal.com/api/v3/urls",
        data=data,
        headers={
            "x-apikey": key,
            "User-Agent": UA,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return "OK", r.read().decode()[:300]
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}", e.read().decode()[:300]
    except Exception as e:
        return "ERR", str(e)


API_TARGETS = [
    ("Netcraft", submit_netcraft, True),      # True = needs reporter email arg
    ("urlscan.io", submit_urlscan, False),
    ("VirusTotal", submit_virustotal, False),
]


# ------------------------------------------------------------------- email side

def complaint_body(info, recipient_label, detail=""):
    """Письмо зарубежному регистратору/хостеру остаётся на английском языке."""
    extra = (detail or info.get("detail") or "").strip()
    description_block = (
        extra
        if extra
        else (
            f"The site is designed to deceive users and harvest credentials or "
            f"payment data from victims who believe they are using {TARGET_BRAND_LABEL}."
        )
    )
    return f"""To whom it may concern ({recipient_label}),

I am reporting an active phishing website impersonating {TARGET_BRAND_LABEL} for immediate takedown.

  Phishing URL : {info['url']}
  Domain       : {info['domain']}
  Resolved IPs : {', '.join(info['ips']) or 'n/a'}
  Nameservers  : {', '.join(info['ns']) or 'n/a'}
  Registrar    : {info['registrar'] or 'n/a'}
  Registered   : {info['created'] or 'n/a'}
  Network      : {info['network'] or 'n/a'}
  Reported at  : {datetime.now(timezone.utc).isoformat()}

{description_block}

This violates your acceptable use policy and, for the registrar, the ICANN RAA 2013
Section 3.18 obligation to investigate and respond to reports of abuse.

Please suspend the domain / disable the hosting account and confirm the action
taken. I am available for any further evidence you require.

Regards,
{os.getenv('REPORTER_NAME', 'Gold Apple Digital Risk Protection')}
"""


def base_mailbox(addr):
    """you+abuse@gmail.com -> you@gmail.com. Gmail selects accounts by the real
    mailbox, not by a plus-alias, and a +tag sends as the base account anyway."""
    local, _, dom = str(addr or "").lower().partition("@")
    return f"{local.split('+')[0]}@{dom}" if dom else ""


def compose_links(to, subject, body, reporter="", gmail_index=None):
    """Hand-off links so you can send from your own mail client instead of letting
    this tool touch SMTP."""
    q = urllib.parse.urlencode({"subject": subject, "body": body}, quote_via=urllib.parse.quote)
    gp = {"view": "cm", "fs": "1", "to": to, "su": subject, "body": body}
    who = base_mailbox(reporter)
    if who:
        gp["authuser"] = who
    gq = urllib.parse.urlencode(gp, quote_via=urllib.parse.quote)
    path = f"u/{int(gmail_index)}/" if gmail_index not in (None, "", -1) else ""
    return {
        "mailto": f"mailto:{urllib.parse.quote(to)}?{q}",
        "gmail": f"https://mail.google.com/mail/{path}?{gq}",
    }


def build_emls(info, outdir, legit_domains=None):
    """Write one .eml per recipient. Returns list of (path, to_addr, label, subject, body)."""
    if is_legit_domain(info.get("url") or info.get("host") or "", legit_domains):
        raise OfficialDomainError(
            f"Отказ: {info.get('url') or info.get('host')} — официальный домен «Золотого Яблока»."
        )

    os.makedirs(outdir, exist_ok=True)
    reporter = os.getenv("REPORTER_EMAIL", "")
    targets = []
    for e in info["registrar_abuse"]:
        targets.append((e, f"registrar {info['registrar'] or ''}".strip()))
    for e in info["ip_abuse"]:
        targets.append((e, f"network {info['network'] or ''}".strip()))
    # Копия службе безопасности бренда отключена по ТЗ.
    targets += [(m, lbl) for lbl, m in CLEARINGHOUSES]
    targets += channels.emails(os.getenv("REPORTER_COUNTRY", ""))

    seen, out = set(), []
    for addr, label in targets:
        if addr.lower() in seen:
            continue
        seen.add(addr.lower())
        m = EmailMessage()
        m["Subject"] = f"Phishing site takedown request ({TARGET_BRAND_LABEL}): {info['domain']}"
        m["To"] = addr
        if reporter:
            m["From"] = reporter
        m.set_content(complaint_body(info, label))
        path = os.path.join(outdir, re.sub(r"[^a-z0-9]+", "_", addr.lower()) + ".eml")
        with open(path, "wb") as f:
            f.write(bytes(m))
        out.append((path, addr, label, m["Subject"], m.get_content()))
    return out


def smtp_send(emls):
    host = os.getenv("SMTP_HOST")
    if not host:
        return None
    port = int(os.getenv("SMTP_PORT", "587"))
    user, pw = os.getenv("SMTP_USER"), os.getenv("SMTP_PASS")
    results = []
    with smtplib.SMTP(host, port, timeout=30) as s:
        s.starttls(context=ssl.create_default_context())
        if user:
            s.login(user, pw)
        for path, addr, *_ in emls:
            try:
                with open(path, "rb") as f:
                    s.sendmail(os.getenv("REPORTER_EMAIL", user), [addr], f.read())
                results.append((addr, "SENT"))
            except Exception as e:
                results.append((addr, f"FAIL {e}"))
    return results


# --------------------------------------------------------------- manual forms

def manual_forms(info):
    u = urllib.parse.quote(info["url"], safe="")
    forms = list(channels.forms(os.getenv("REPORTER_COUNTRY", "")))
    forms += [
        ("Google Safe Browsing", f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={u}"),
        ("Microsoft SmartScreen", f"https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest?url={u}"),
        ("PhishTank (submit)", "https://phishtank.org/add_web_phish.php"),
        ("Spamhaus DBL removal/report", "https://www.spamhaus.org/report-spam/"),
        ("APWG eCrime portal", "https://apwg.org/reportphishing/"),
    ]
    if info["cloudflare"]:
        forms.insert(0, ("Cloudflare abuse (phishing) — обязательно, сайт за Cloudflare",
                         "https://abuse.cloudflare.com/phishing"))
    forms.append(("Жалоба в ICANN — только если регистратор игнорирует обращение более 24 ч.",
                  "https://forms.icann.org/en/resources/compliance/complaints/registrars/abuse-report-form"))
    return forms


# --------------------------------------------------------------------- output

def run(url, send, outdir, brand=None):
    if is_legit_domain(url):
        print(f"\n[ЗАБЛОКИРОВАНО] {url} — официальный домен «Золотого Яблока». Подача жалобы отменена.")
        return {"url": url, "blocked": True, "is_legit": True, "brand": TARGET_BRAND}

    if not looks_like_goldapple("", url):
        print(f"\n[ПРЕДУПРЕЖДЕНИЕ] Ссылка {url} не содержит признаков «Золотого Яблока». Проверьте перед отправкой.")

    print(f"\n=== РАЗВЕДКА  {url} ===")
    info = recon(url)
    info["brand"] = TARGET_BRAND
    for k in ("domain", "ips", "registrar", "created", "ns", "network"):
        print(f"  {k:<10}: {info[k]}")
    print(f"  {'abuse':<10}: registrar={info['registrar_abuse']} network={info['ip_abuse']}")
    if info["created"] and info["created"][:4] >= "2024":
        print("  ПРИМЕЧАНИЕ: свежезарегистрированный домен — сильный признак фишинга")

    print("\n=== ОТПРАВКА В API ===")
    reporter = os.getenv("REPORTER_EMAIL")
    for name, fn, needs_email in API_TARGETS:
        if not send:
            print(f"  [тестовый запуск] {name}")
            continue
        status, detail = fn(url, reporter) if needs_email else fn(url)
        print(f"  {name:<14} {status:<10} {detail[:120]}")

    print("\n=== ПИСЬМА ЖАЛОБ ===")
    emls = build_emls(info, outdir)
    for path, addr, label, *_ in emls:
        print(f"  {addr:<38} ({label})  -> {path}")
    if send and os.getenv("SMTP_HOST"):
        print("  отправка через SMTP...")
        for addr, res in smtp_send(emls) or []:
            print(f"    {addr:<38} {res}")
    elif send:
        print("  SMTP_HOST не задан — сформированы .eml файлы, откройте их в почтовом клиенте")

    print("\n=== ФОРМЫ ВЕНДОРОВ (CAPTCHA / ручная отправка) ===")
    for name, link in manual_forms(info):
        print(f"  {name}\n    {link}")
    print()
    return info


# -------------------------------------------------------------------- selftest

def selftest():
    import tempfile

    assert registrable_domain("www.tegexyy.top") == "tegexyy.top"
    assert registrable_domain("a.b.c.co.uk") == "c.co.uk"
    assert registrable_domain("example.com") == "example.com"
    # домен хостинг-платформы не должен становиться целью жалобы
    assert registrable_domain("evil-login.pages.dev") == "evil-login.pages.dev"
    assert registrable_domain("x.y.scam.workers.dev") == "scam.workers.dev"
    assert registrable_domain("phish.github.io") == "phish.github.io"
    assert platform_suffix("scam.workers.dev") == "workers.dev"
    assert platform_suffix("tegexyy.top") is None

    fake = {"entities": [
        {"roles": ["registrar"], "entities": [
            {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@reg.test"]]]}]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["email", {}, "text", "someone@else.test"]]]},
    ]}
    assert rdap_emails(fake)[0] == "abuse@reg.test", rdap_emails(fake)
    noisy = {"entities": [{"roles": ["technical"], "vcardArray": ["vcard", [["email", {}, "text", "noc@net.test"]]]},
                          {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@net.test"]]]}]}
    assert rdap_emails(noisy) == ["abuse@net.test"], rdap_emails(noisy)

    # Чужих брендов в BRAND_ABUSE нет, бренд всегда «Золотое Яблоко», копия бренду не шлётся
    assert BRAND_ABUSE == {}
    assert guess_brand({"url": "https://x.top/", "host": "x.top", "brand": "telegram"}) == ("goldapple", "")

    # Официальные домены и их поддомены блокируются, мимикрия — нет
    for legit_url in (
        "https://goldapple.ru",
        "https://shop.goldapple.ru/catalog",
        "https://goldapple.kz/promo",
        "https://m.goldapple.by/",
        "https://goldapple.sa",
        "https://goldapple.qa",
        "https://goldapple.ae",
    ):
        assert is_legit_domain(legit_url) is True, legit_url

    for phish_url in (
        "https://goldapple.ru.fake-site.top/login",
        "https://gold-apple-sale.shop/",
        "https://mygoldapple.ru/",
    ):
        assert is_legit_domain(phish_url) is False, phish_url

    assert submit_netcraft("https://shop.goldapple.ru/", "a@b.test")[0] == "BLOCKED"
    assert submit_urlscan("https://goldapple.kz/")[0] == "BLOCKED"
    assert submit_virustotal("https://goldapple.by/")[0] == "BLOCKED"

    # Проверка каналов по стране и Cloudflare
    os.environ["REPORTER_COUNTRY"] = "MY"
    my_forms = [u for _, u in manual_forms({"url": "https://x.top/", "cloudflare": False})]
    assert "https://aduan.mcmc.gov.my/" in my_forms, "country channels must lead the list"
    os.environ["REPORTER_COUNTRY"] = ""
    assert "https://aduan.mcmc.gov.my/" not in [
        u for _, u in manual_forms({"url": "https://x.top/", "cloudflare": False})
    ]

    info = {
        "url": "https://goldapple.ru.fake-site.top/promo",
        "host": "goldapple.ru.fake-site.top",
        "domain": "fake-site.top",
        "ips": [],
        "ns": [],
        "registrar": None,
        "created": None,
        "network": None,
        "registrar_abuse": ["abuse@reg.test"],
        "ip_abuse": [],
        "cloudflare": True,
        "brand": None,
    }
    assert guess_brand(info) == ("goldapple", "")
    assert "abuse.cloudflare.com" in manual_forms(info)[0][1]
    body = complaint_body(info, "registrar")
    assert "fake-site.top" in body
    assert TARGET_BRAND_LABEL in body

    # build_emls не должен включать почту бренда и должен отказывать для официального домена
    with tempfile.TemporaryDirectory() as tmp:
        emls = build_emls(info, tmp)
        addrs = [addr for _, addr, *_ in emls]
        assert "abuse@reg.test" in addrs
        assert not any("goldapple" in a.lower() for a in addrs)

        legit_info = dict(info, url="https://goldapple.ru/sale", host="goldapple.ru", domain="goldapple.ru")
        blocked = False
        try:
            build_emls(legit_info, tmp)
        except OfficialDomainError:
            blocked = True
        assert blocked, "build_emls must reject official Gold Apple domains"

    print("selftest OK")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Подача жалоб на фишинговые ресурсы «Золотого Яблока».")
    ap.add_argument("url", nargs="?", help="фишинговая ссылка")
    ap.add_argument("--send", action="store_true", help="реально отправить жалобы (по умолчанию тестовый запуск)")
    ap.add_argument("--out", default="reports", help="папка для черновиков .eml")
    ap.add_argument("--brand", help="игнорируется — цель всегда «Золотое Яблоко»")
    ap.add_argument(
        "--compose",
        action="store_true",
        help="открыть черновики писем в локальной почтовой программе (ничего не отправляет)",
    )
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        sys.exit(0)
    if not a.url:
        ap.error("укажите URL или --selftest")
    if is_legit_domain(a.url):
        print(f"[ЗАБЛОКИРОВАНО] {a.url} — официальный домен «Золотого Яблока».")
        sys.exit(1)
    out = os.path.join(a.out, urllib.parse.urlparse(a.url).hostname or "target")
    info = run(a.url, a.send, out, TARGET_BRAND)
    if a.compose:
        import subprocess
        info["brand"] = TARGET_BRAND
        drafts = build_emls(info, out)
        for _path, addr, _label, subj, body in drafts:
            subprocess.Popen(["open", compose_links(addr, subj, body)["mailto"]])
        print(f"Открыто черновиков: {len(drafts)}. Проверьте письма и отправьте вручную.")