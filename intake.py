"""Разбор вставленного фишингового сообщения в список целей для жалоб.

Извлекает ссылки (включая обфусцированные), проверяет официальные домены
«Золотого Яблока», определяет признаки мошенничества в русском и английском
тексте, раскрывает сокращённые ссылки и помечает уже обработанные хосты.
"""
import re
import urllib.parse

import reactor as fs

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

DEOBF = [
    (re.compile(r"\bh(?:xx|XX)(ps?)\b", re.I), r"htt\1"),
    # (.) [.] {.} и текстовые (dot)/(точка)
    (re.compile(r"\s*[\(\[\{]\s*\.\s*[\)\]\}]\s*"), "."),
    (re.compile(r"\s*[\(\[\{]\s*(?:dot|точка)\s*[\)\]\}]\s*", re.I), "."),
    (re.compile(r"\s+(?:dot|точка)\s+", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\bhttps?\s*:\s*/\s*/", re.I), lambda m: m.group(0).replace(" ", "")),
]

URL_RE = re.compile(r"""(?xi)
    \b(?:https?://)?   
    (?:[a-zа-яё0-9](?:[a-zа-яё0-9-]{0,61}[a-zа-яё0-9])?\.)+
    (?:com|net|org|top|xyz|icu|cyou|shop|store|online|site|club|live|vip|cc|co|io|me|
       info|biz|link|click|fun|life|world|today|app|dev|pro|asia|sg|my|hk|tw|cn|id|ph|
       th|vn|in|uk|ru|kz|by|sa|ae|qa|su|рф|xn--p1ai|uz|am|ge|kg|ua|
       pw|ws|tv|gg|space|tech|sale|promo|gift|beauty|market|zone|win|
       tk|ml|ga|cf|gq|buzz|rest|autos|bond|cfd|sbs|lol|mom|quest)
    \b(?:/[^\s<>"'()\[\]«»]*)?
""")

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "goo.gl", "ow.ly", "buff.ly", "cutt.ly",
    "rb.gy", "rebrand.ly", "shorturl.at", "s.id", "lnkd.in", "t.ly", "tiny.cc", "v.gd",
    "shorte.st", "bl.ink", "trib.al", "u.to", "clck.ru", "qr.ae", "wa.link", "chl.li",
    "vk.cc", "ya.cc", "goo.su", "clc.to", "qps.ru",
}

BRAND_HINTS = {
    "goldapple": [
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
    ],
}

LURES = [
    (
        r"verif(y|ication)|подтверд|верифик|авториз",
        "просит подтвердить данные",
    ),
    (
        r"suspend|deactivat|blocked|locked|заблокир|блокировк|деактивир|огранич|заморож",
        "угроза блокировки аккаунта",
    ),
    (
        r"unusual (login|activity)|new device|logged in from|подозрительн|необычн\w* вход|новое устройство",
        "ложное предупреждение безопасности",
    ),
    (
        r"within \d+ ?(hours?|hrs?|minutes?|mins?)|immediately|urgent|срочн|немедленн|в течение \d+|успей|только сегодня|последний день",
        "искусственная срочность",
    ),
    (
        r"click (the )?link|tap (the )?link|follow the link|перейд\w* по ссылк|нажми\w* на ссылк|ссылк\w* ниже",
        "подталкивает перейти по ссылке",
    ),
    (
        r"one[- ]?time|otp|code|password|pin|смс[- ]?код|код из смс|парол|cvv|cvc|номер карт|данн\w+ карт|реквизит",
        "выманивание кода, пароля или данных карты",
    ),
    (
        r"prize|reward|claim|won|приз|розыгрыш|выигр|подар|бьюти[- ]?бокс|beauty[- ]?box|сертификат|распродаж|скидк|бесплатн|бонус|акци",
        "приманка (приз, розыгрыш, скидка)",
    ),
    (
        r"deliver|parcel|package|customs|shipping|refund|доставк|посылк|курьер|возврат|компенсац|опрос|оплат\w* заказ",
        "фейковая доставка, возврат или оплата",
    ),
]


def deobfuscate(text):
    out = text or ""
    for pat, rep in DEOBF:
        out = pat.sub(rep, out)
    return out


def extract_urls(text):
    clean = deobfuscate(text or "")
    seen, out = set(), []
    for m in URL_RE.finditer(clean):
        raw = m.group(0).rstrip(".,;:)]}’\"'»!?")
        url = raw if raw.lower().startswith(("http://", "https://")) else "https://" + raw
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if not host or host in seen:
            continue
        start = m.start()
        if start and clean[start - 1] == "@":
            continue
        seen.add(host)
        out.append(url)
    return out


def is_legit_domain(url, legit_domains=None):
    """Проверяет точное совпадение с официальным доменом или его поддоменом."""
    domains = legit_domains if legit_domains is not None else DEFAULT_LEGIT_DOMAINS
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


def guess_brand(text, url=""):
    """Возвращает 'goldapple', если текст или ссылка похожи на «Золотое Яблоко», иначе None."""
    hay = f"{text or ''} {url or ''}".lower()
    best, best_at = None, len(hay) + 1
    for brand, words in BRAND_HINTS.items():
        for w in words:
            at = hay.find(w)
            if at >= 0 and at < best_at:
                best, best_at = brand, at
    return best


def looks_like_goldapple(text, url=""):
    return guess_brand(text, url) == TARGET_BRAND


def lures(text):
    low = (text or "").lower()
    return [label for pat, label in LURES if re.search(pat, low)]


def is_shortener(url):
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host in SHORTENERS


def expand(url, allow_touch=True):
    """Раскрывает только известные сокращатели ссылок.

    Обычные фишинговые ссылки здесь никогда не запрашиваются.
    Возвращает кортеж (final_url, note).
    """
    if not is_shortener(url):
        return url, ""
    if not allow_touch:
        return url, "сокращённая ссылка — раскрытие пропущено"
    fs.http(url, method="HEAD")
    try:
        req = __import__("urllib.request", fromlist=["request"]).Request(
            url, headers={"User-Agent": fs.UA}, method="HEAD")
        with __import__("urllib.request", fromlist=["request"]).urlopen(req, timeout=20) as r:
            final = r.geturl()
        return final, (f"раскрыто из {urllib.parse.urlparse(url).hostname}"
                       if final != url else "сокращатель не сделал редирект")
    except Exception as e:
        return url, f"не удалось раскрыть ({type(e).__name__})"


def parse(text, known_hosts=(), allow_touch=True, legit_domains=None):
    """Полный разбор сообщения: текст на входе, список целей на выходе."""
    urls = extract_urls(text)
    hint = lures(text)
    known = set(known_hosts)
    out = []
    legit_count = 0
    for u in urls:
        final, note = expand(u, allow_touch)
        host = (urllib.parse.urlparse(final).hostname or "").lower()
        legit = is_legit_domain(final, legit_domains)
        brand_match = looks_like_goldapple(text, final)
        warning = ""
        if legit:
            legit_count += 1
            warning = "Официальный домен «Золотого Яблока» — отправка жалобы запрещена"
        elif not brand_match:
            warning = "Ссылка и текст не похожи на «Золотое Яблоко» — проверьте перед отправкой"
        out.append({
            "url": final,
            "host": host,
            "domain": fs.registrable_domain(host) if host else "",
            "original": u if final != u else None,
            "brand": TARGET_BRAND,
            "brand_match": brand_match,
            "is_legit": legit,
            "warning": warning,
            "note": note,
            "already_reported": host in known,
        })
    parts = [f"Найдено ссылок: {len(out)}"]
    if hint:
        parts.append(f"признаков фишинга: {len(hint)}")
    if legit_count:
        parts.append(f"официальных доменов (заблокировано): {legit_count}")
    return {
        "targets": out,
        "lures": hint,
        "summary": ", ".join(parts),
    }


def selftest():
    sms_ru = (
        "Золотое Яблоко: срочно подтвердите получение приза! "
        "Вы выиграли бьюти-бокс в розыгрыше, доставка бесплатная: "
        "hxxps://gold-apple-prize[.]top/gift?id=77 или оформите возврат по ссылке."
    )
    got = extract_urls(sms_ru)
    assert got == ["https://gold-apple-prize.top/gift?id=77"], got
    assert guess_brand(sms_ru) == "goldapple"
    L = lures(sms_ru)
    for expect in (
        "просит подтвердить данные",
        "искусственная срочность",
        "приманка (приз, розыгрыш, скидка)",
        "фейковая доставка, возврат или оплата",
    ):
        assert expect in L, (expect, L)

    sample_domains = [
        ("Скидки от Золотого Яблока: goldapple-sale.ru/promo", "https://goldapple-sale.ru/promo"),
        ("Ваш заказ в КЗ: gold-apple-delivery.kz/pay", "https://gold-apple-delivery.kz/pay"),
        ("Аккаунт заблокирован, вход: goldapple-auth.by/login", "https://goldapple-auth.by/login"),
        ("Распродажа 90%: goldapple-box.shop/order", "https://goldapple-box.shop/order"),
        ("Приз: goldapple-gift.top/win", "https://goldapple-gift.top/win"),
        ("ОАЭ: goldapple-vip.ae/claim", "https://goldapple-vip.ae/claim"),
        ("Саудовская Аравия: goldapple-promo.sa/box", "https://goldapple-promo.sa/box"),
        ("Катар: goldapple-bonus.qa/start", "https://goldapple-bonus.qa/start"),
        ("Зона su: goldapple-check.su/auth", "https://goldapple-check.su/auth"),
        ("Кириллица: https://золотое-яблоко-приз.рф/box", "https://золотое-яблоко-приз.рф/box"),
    ]
    for msg, expected_url in sample_domains:
        urls = extract_urls(msg)
        assert urls == [expected_url], (msg, urls, expected_url)

    for official in (
        "https://goldapple.ru",
        "https://shop.goldapple.ru/catalog",
        "https://m.goldapple.kz/cart",
        "https://goldapple.by/",
        "https://goldapple.sa",
        "https://goldapple.qa",
        "https://goldapple.ae",
    ):
        assert is_legit_domain(official) is True, official

    for fake in (
        "https://goldapple.ru.fake-site.top/login",
        "https://mygoldapple.ru/promo",
        "https://gold-apple.ru/sale",
        "https://goldapple-ru.shop/box",
    ):
        assert is_legit_domain(fake) is False, fake

    for variant in (
        "go to evil (dot) com now",
        "go to evil[dot]com now",
        "go to evil dot com now",
        "go to evil[.]com now",
        "перейди на evil(точка)ru прямо сейчас",
    ):
        res = extract_urls(variant)
        assert res and res[0].startswith("https://evil."), (variant, res)
    assert deobfuscate("hxxp://a") == "http://a" and deobfuscate("hxxps://a") == "https://a"
    assert extract_urls("hxxp://bad{.}xyz/a") == ["http://bad.xyz/a"]
    assert extract_urls("пишите на someone@gmail.com") == []
    assert len(extract_urls("a.top/1 и a.top/2")) == 1

    assert is_shortener("https://bit.ly/abc") and is_shortener("https://clck.ru/3abc")
    assert not is_shortener("https://evil.top/x")
    assert expand("https://evil.top/x", allow_touch=True) == ("https://evil.top/x", "")

    p = parse(
        "Золотое Яблоко: https://goldapple.ru/info и фейк https://goldapple.ru.fake-site.top/win",
        known_hosts=["goldapple.ru.fake-site.top"],
        allow_touch=False,
    )
    assert len(p["targets"]) == 2
    assert p["targets"][0]["is_legit"] is True
    assert p["targets"][0]["warning"]
    assert p["targets"][1]["is_legit"] is False
    assert p["targets"][1]["already_reported"] is True
    assert p["targets"][1]["brand"] == "goldapple"

    unrelated = parse("Смотри сюда https://random-promo-site.shop/123", allow_touch=False)
    assert unrelated["targets"][0]["is_legit"] is False
    assert unrelated["targets"][0]["brand_match"] is False
    assert unrelated["targets"][0]["brand"] == "goldapple"
    assert unrelated["targets"][0]["warning"]

    print("intake selftest OK")


if __name__ == "__main__":
    selftest()