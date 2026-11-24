"""Драйвер Playwright для заполнения форм жалоб вендоров.

Для каждого сайта параллельно (по 5 вкладок):
1. открывает форму жалобы и отклоняет cookie-баннер
2. заполняет текстовые поля (URL / email / имя / комментарий)
3. выбирает тип угрозы («Phishing», «Fraud», «Malicious»...) и бренд («Другое» при отсутствии ЗЯ)
4. воспроизводит шаги из сохранённого рецепта (recipes/<site>.json)
5. определяет наличие CAPTCHA
6. ОСТАНАВЛИВАЕТСЯ. Ничего не отправляется до нажатия «Отправить все».

Не переходит на сам фишинговый сайт. Работает в отдельном профиле браузера.
"""
import asyncio
import json
import os
import re
import shutil
from datetime import datetime, timezone

import reactor as fs
from sites import SITES

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(HERE, ".browser-profile")
RECIPES_DIR = os.path.join(HERE, "recipes")
LOG_PATH = os.path.join(HERE, "reports", "log.jsonl")
RECORDER_JS = os.path.join(HERE, "recorder.js")
MAX_PARALLEL = 5

BRAND_LABEL = fs.TARGET_BRAND_LABEL

# ---- классификация полей формы --------------------------------------------
PATTERNS = [
    ("email",   re.compile(r"e-?mail|contact|почт", re.I)),
    ("url",     re.compile(r"\burl\b|website|web site|\bsite\b|address|domain|link|search|query|\bq\b|ссылк|сайт|домен|адрес", re.I)),
    ("comment", re.compile(r"comment|descri|detail|message|reason|note|additional|explain|remark|коммент|описан|причин|подробн|сообщен", re.I)),
    ("name",    re.compile(r"(^|[^a-zа-яё])name([^a-zа-яё]|$)|full.?name|your.?name|ваше имя|фио|\bимя\b", re.I)),
]
SKIP_PAT = re.compile(r"captcha|password|card|phone|subscribe|newsletter|капча|парол|карт|телефон", re.I)

# ---- тип угрозы / категории (сначала самые точные) ------------------------
THREAT_WORDS = [
    r"phish", r"фишинг", r"credential.?(theft|harvest)", r"deceptive", r"fraud", r"scam",
    r"мошеннич", r"spoof", r"impersonat", r"malicious", r"вредонос", r"\bmalware\b",
    r"security risk", r"suspicious", r"подозрительн", r"spam", r"compromis",
]
THREAT_RE = [re.compile(w, re.I) for w in THREAT_WORDS]
NEGATIVE_RE = re.compile(
    r"not |false positive|clean|safe|benign|remove|unblock|legitimate|dispute this|не фишинг|безопасн|ложное",
    re.I,
)

# ---- списки брендов на формах вендоров ------------------------------------
BRAND_SELECT_RE = re.compile(
    r"brand|target|company|organi[sz]ation|victim|impersonat|affected|бренд|организ|компан|сервис",
    re.I,
)
GOLDAPPLE_OPTION_RE = re.compile(r"gold\s*-?\s*apple|золот\w*\s+яблок", re.I)
OTHER_OPTION_RE = re.compile(
    r"(^|\b)(other|others|not listed|not in list|none of the above|другое|другой|иное|нет в списке)(\b|$)",
    re.I,
)

CAPTCHA_JS = """
() => {
  const sels = ['iframe[src*="recaptcha"]','iframe[src*="hcaptcha"]','iframe[src*="turnstile"]',
                'iframe[title*="captcha" i]','.g-recaptcha','.h-captcha','[data-sitekey]','#captcha',
                'img[src*="captcha" i]','input[name*="captcha" i]'];
  return sels.some(s => { const e = document.querySelector(s);
    return e && (e.offsetParent !== null || e.tagName === 'IFRAME'); });
}
"""

COLLECT_JS = """
() => Array.from(document.querySelectorAll('input, textarea')).map((el, i) => {
  const r = el.getBoundingClientRect();
  let label = '';
  if (el.labels) for (const l of el.labels) label += ' ' + (l.innerText || '');
  if (el.id) { const fl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
               if (fl) label += ' ' + (fl.innerText || ''); }
  const p = el.closest('label, .form-group, .field, td, li, div');
  return { i, type: (el.type || el.tagName).toLowerCase(),
    visible: r.width > 0 && r.height > 0 && el.offsetParent !== null,
    disabled: el.disabled || el.readOnly, filled: !!el.value,
    sig: [el.name, el.id, el.placeholder, el.getAttribute('aria-label'),
          el.getAttribute('title'), label, p ? (p.innerText||'').slice(0,120) : ''
         ].filter(Boolean).join(' ') };
})
"""

# Все <select> (с текстом подписей и опций) и все radio с подписями.
CHOICES_JS = """
() => {
  const out = {selects: [], radios: []};
  document.querySelectorAll('select').forEach((el, i) => {
    const r = el.getBoundingClientRect();
    if (!(r.width > 0 && r.height > 0) || el.disabled) return;
    let label = '';
    if (el.labels) for (const l of el.labels) label += ' ' + (l.innerText || '');
    if (el.id) { const fl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
                 if (fl) label += ' ' + (fl.innerText || ''); }
    const p = el.closest('label, .form-group, .field, td, li, div');
    const sig = [el.name, el.id, el.getAttribute('aria-label'), label,
                 p ? (p.innerText||'').slice(0,80) : ''].filter(Boolean).join(' ');
    out.selects.push({ i, name: el.name || el.id || '', sig,
      chosen: el.selectedIndex,
      options: Array.from(el.options).map(o => ({v: o.value, t: (o.text||'').trim()})) });
  });
  document.querySelectorAll('input[type=radio]').forEach((el, i) => {
    const r = el.getBoundingClientRect();
    if (!(r.width > 0 && r.height > 0) || el.disabled) return;
    let label = '';
    if (el.labels) for (const l of el.labels) label += ' ' + (l.innerText || '');
    const p = el.closest('label, .form-check, .radio, li, td, div');
    out.radios.push({ i, group: el.name || '', checked: el.checked,
      text: [label, el.value, el.getAttribute('aria-label'),
             p ? (p.innerText||'').slice(0,80) : ''].filter(Boolean).join(' ').trim() });
  });
  return out;
}
"""

HARVEST_JS = "() => { try { return JSON.parse(sessionStorage.getItem('__fsrec') || '[]'); } catch(e) { return []; } }"

SUBMIT_SELECTORS = [
    "button[type=submit]", "input[type=submit]",
    "button:has-text('Submit Report')", "button:has-text('Send Report')",
    "button:has-text('Submit')", "button:has-text('Send')",
    "button:has-text('Report')", "button:has-text('Отправить')", "button:has-text('Пожаловаться')",
    # lookup-first вендоры: первая кнопка запускает проверку
    "button:has-text('Check')", "button:has-text('Look up')", "button:has-text('Lookup')",
    "button:has-text('Search')", "button:has-text('Проверить')",
    "a[role=button]:has-text('Submit')",
]

DECLINE_COOKIES = [
    "button:has-text('Reject all')", "button:has-text('Reject All')",
    "button:has-text('Decline')", "button:has-text('Only necessary')",
    "button:has-text('Necessary only')", "button:has-text('Deny')",
    "button:has-text('Отклонить')",
    "#onetrust-reject-all-handler", ".ot-pc-refuse-all-handler",
]


def ensure_brand_in_comment(comment, brand_label=BRAND_LABEL):
    """Гарантирует, что в комментарии формы указан бренд «Золотое Яблоко (goldapple.ru)»."""
    text = (comment or "").strip()
    if not text:
        return f"Phishing site impersonating {brand_label}."
    if GOLDAPPLE_OPTION_RE.search(text):
        return text
    return f"Бренд: {brand_label}. {text}"


def prepare_values(values):
    """Нормализует значения формы: фиксирует бренд «Золотое Яблоко» и добавляет его в комментарий."""
    out = dict(values or {})
    out["brand"] = BRAND_LABEL
    out["comment"] = ensure_brand_in_comment(out.get("comment", ""), BRAND_LABEL)
    return out


def classify(field):
    if field["disabled"] or not field["visible"] or field["filled"]:
        return None
    if field["type"] in ("hidden", "submit", "button", "checkbox", "radio", "file", "password"):
        return None
    sig = field["sig"]
    if SKIP_PAT.search(sig):
        return None
    if field["type"] == "email":
        return "email"
    if field["type"] == "textarea" and not sig.strip():
        return "comment"
    for kind, pat in PATTERNS:
        if pat.search(sig):
            return kind
    return "comment" if field["type"] == "textarea" else None


def best_threat_option(texts):
    """Индекс опции, лучше всего обозначающей фишинг. None, если совпадений нет."""
    best, best_rank = None, len(THREAT_RE)
    for idx, t in enumerate(texts):
        if not t or NEGATIVE_RE.search(t):
            continue
        for rank, pat in enumerate(THREAT_RE):
            if pat.search(t) and rank < best_rank:
                best, best_rank = idx, rank
                break
    return best


def best_brand_option(texts):
    """Выбирает «Золотое Яблоко» в списке брендов; если его нет — «Другое» / Other.

    Возвращает кортеж (index, mode), где mode in ('exact', 'other', None).
    """
    for idx, t in enumerate(texts):
        if t and GOLDAPPLE_OPTION_RE.search(t):
            return idx, "exact"
    for idx, t in enumerate(texts):
        if t and OTHER_OPTION_RE.search(t):
            return idx, "other"
    return None, None


# ---- рецепты --------------------------------------------------------------

def recipe_path(site_id):
    return os.path.join(RECIPES_DIR, f"{site_id}.json")


def load_recipe(site_id):
    p = recipe_path(site_id)
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f).get("steps", [])
    except Exception:
        return []


def tokenize(value, values):
    """Заменяет специфичные для цели значения на токены {{url}}, {{domain}}, {{brand}} и др."""
    if not isinstance(value, str) or not value.strip():
        return value
    out = value
    if values.get("comment") and out.strip() == str(values["comment"]).strip():
        return "{{comment}}"
    # Сначала самые длинные значения, чтобы URL заменился раньше домена.
    for kind in sorted(("url", "email", "comment", "name", "brand", "domain"),
                       key=lambda k: -len(str(values.get(k) or ""))):
        actual = str(values.get(kind) or "")
        if len(actual) >= 3:
            out = re.sub(re.escape(actual), "{{%s}}" % kind, out, flags=re.I)
    if "{{" not in out and len(out) > 120:
        return "{{typed}}"
    return out


def detokenize(value, values):
    if not isinstance(value, str):
        return value
    if value == "{{typed}}":
        return values.get("comment", "")
    for kind in ("url", "email", "comment", "name", "brand", "domain"):
        value = value.replace("{{%s}}" % kind, str(values.get(kind) or ""))
    return value


def generalizes_as(text, values):
    """Определяет, как переносить сохранённый выбор на следующую жалобу."""
    t = (text or "").strip()
    if not t:
        return "sticky"
    low = t.lower()
    for kind in ("url", "domain", "email"):
        v = str(values.get(kind) or "")
        if len(v) >= 4 and v.lower() in low:
            return "target"
    brand = str(values.get("brand") or "")
    if (len(brand) >= 3 and brand.lower() in low) or GOLDAPPLE_OPTION_RE.search(t):
        return "brand"
    if not NEGATIVE_RE.search(t) and any(p.search(t) for p in THREAT_RE):
        return "threat"
    return "sticky"


def save_recipe(site_id, steps, values):
    if not steps:
        return 0
    os.makedirs(RECIPES_DIR, exist_ok=True)
    norm = prepare_values(values)
    clean, seen = [], set()
    for s in steps:
        act = s.get("act")
        if act == "fill":
            s = {**s, "value": tokenize(s.get("value"), norm),
                 "gen": generalizes_as(s.get("value"), norm)}
        elif act in ("select", "check"):
            s = {**s, "gen": generalizes_as(s.get("text"), norm),
                 "text": tokenize(s.get("text"), norm)}
        key = (act, s.get("sel"), str(s.get("value")), str(s.get("checked")))
        if key in seen:
            continue
        seen.add(key)
        clean.append(s)
    payload = {
        "site": site_id,
        "updated": datetime.now(timezone.utc).isoformat(),
        "learned_from_brand": BRAND_LABEL,
        "steps": clean,
    }
    with open(recipe_path(site_id), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return len(clean)


async def pick_option_matching(loc, wanted, fallback_other=False):
    """Выбирает опцию <select>, содержащую `wanted`; при fallback_other выбирает «Другое»/Other."""
    try:
        opts = await loc.evaluate("el => Array.from(el.options).map(o => [o.value, (o.text || '').trim()])")
    except Exception:
        return None, None
    texts = [t for _, t in opts]
    if wanted:
        for value, text in opts:
            if wanted.lower() in text.lower():
                await loc.select_option(value=value, timeout=2500)
                return text, "exact"
    if fallback_other:
        idx, mode = best_brand_option(texts)
        if idx is not None:
            value, text = opts[idx]
            await loc.select_option(value=value, timeout=2500)
            return text, mode
    return None, None


async def replay(page, steps, values):
    """Воспроизводит обученные шаги. Возвращает (steps_applied, flags)."""
    done, flags = 0, []
    for st in steps:
        gen = st.get("gen", "sticky")
        try:
            loc = page.locator(st["sel"]).first
            if not await loc.is_visible(timeout=1200):
                continue
            act = st.get("act")

            if act == "fill":
                await loc.fill(detokenize(st.get("value", ""), values), timeout=2500)

            elif act == "select":
                if gen == "threat":
                    await loc.select_option(value=st.get("value"), timeout=2500)
                elif gen == "brand":
                    hit, mode = await pick_option_matching(loc, values.get("brand", ""), fallback_other=True)
                    if not hit:
                        flags.append("список брендов: не найдено «Золотое Яблоко» и «Другое» — выберите вручную")
                        continue
                    if mode == "other":
                        values["comment"] = ensure_brand_in_comment(values.get("comment", ""), BRAND_LABEL)
                elif gen == "target":
                    wanted = values.get("domain") or ""
                    hit, _ = await pick_option_matching(loc, wanted, fallback_other=False) if wanted else (None, None)
                    if not hit:
                        flags.append(f"список цели: нет варианта для «{wanted}» — проверьте вручную")
                        continue
                else:
                    await loc.select_option(value=st.get("value"), timeout=2500)
                    flags.append(f"повторён прошлый ответ «{(st.get('text') or '')[:32]}» — проверьте")

            elif act == "check":
                if gen in ("brand", "target"):
                    flags.append("пропущен выбор, привязанный к прошлой цели — отметьте вручную")
                    continue
                if st.get("checked", True):
                    await loc.check(timeout=2500)
                if gen == "sticky":
                    flags.append(f"повторён прошлый флажок «{(st.get('text') or '')[:32]}» — проверьте")

            elif act == "click":
                if re.search(r"submit|send|report now|отправить|пожаловаться", st.get("text", ""), re.I):
                    continue  # автонажатие отправки из рецепта запрещено
                await loc.click(timeout=2500)
            else:
                continue

            done += 1
            await page.wait_for_timeout(250)
        except Exception:
            continue
    return done, flags


# ---- работа со страницей --------------------------------------------------

async def recording(page, on):
    """Запись действий включена только пока вкладка находится в руках специалиста."""
    try:
        await page.evaluate(f"() => {{ window.__fsrec_on = {'true' if on else 'false'}; }}")
    except Exception:
        pass


async def decline_cookies(page):
    for sel in DECLINE_COOKIES:
        try:
            btn = page.locator(sel).first
            if await btn.is_visible(timeout=350):
                await btn.click(timeout=1500)
                return
        except Exception:
            pass


async def fill_text(page, values):
    try:
        fields = await page.evaluate(COLLECT_JS)
    except Exception:
        return []
    boxes = page.locator("input, textarea")
    done, used = [], set()
    for f in fields:
        kind = classify(f)
        if not kind or kind in used or not values.get(kind):
            continue
        try:
            await boxes.nth(f["i"]).fill(values[kind], timeout=3000)
            used.add(kind)
            done.append(kind)
        except Exception:
            continue
    return done


async def pick_threats(page, values=None):
    """Выбирает тип угрозы («Phishing» и аналоги) и бренд («Золотое Яблоко» или «Другое»)."""
    picked = []
    try:
        ch = await page.evaluate(CHOICES_JS)
    except Exception:
        return picked
    selects = page.locator("select")
    for s in ch["selects"]:
        opt_texts = [o["t"] for o in s["options"]]
        idx = best_threat_option(opt_texts)
        if idx is not None:
            if idx == s["chosen"]:
                continue
            try:
                await selects.nth(s["i"]).select_option(value=s["options"][idx]["v"], timeout=2500)
                picked.append(f"{s['name'] or 'список'}={s['options'][idx]['t']}")
            except Exception:
                continue
            continue

        # Если это список брендов — ищем «Золотое Яблоко», иначе выбираем «Другое» / Other
        if BRAND_SELECT_RE.search(s.get("sig", "")):
            b_idx, mode = best_brand_option(opt_texts)
            if b_idx is not None and b_idx != s["chosen"]:
                try:
                    await selects.nth(s["i"]).select_option(value=s["options"][b_idx]["v"], timeout=2500)
                    picked.append(f"{s['name'] or 'бренд'}={s['options'][b_idx]['t']}")
                    if mode == "other" and values is not None:
                        values["comment"] = ensure_brand_in_comment(values.get("comment", ""), BRAND_LABEL)
                except Exception:
                    continue

    radios = page.locator("input[type=radio]")
    by_group, seen_groups = {}, set()
    for r in ch["radios"]:
        by_group.setdefault(r["group"], []).append(r)
    for group, members in by_group.items():
        if group in seen_groups or any(m["checked"] for m in members):
            continue
        idx = best_threat_option([m["text"] for m in members])
        if idx is None:
            continue
        try:
            await radios.nth(members[idx]["i"]).check(timeout=2500)
            picked.append(f"{group or 'radio'}={members[idx]['text'][:32]}")
            seen_groups.add(group)
        except Exception:
            continue
    return picked


async def has_captcha(page):
    try:
        return bool(await page.evaluate(CAPTCHA_JS))
    except Exception:
        return True  # если нельзя проверить — считаем, что CAPTCHA есть


async def find_submit(page):
    for sel in SUBMIT_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.count() and await loc.is_visible(timeout=800):
                return loc
        except Exception:
            continue
    return None


def expand(template, url):
    import urllib.parse
    p = urllib.parse.urlparse(url)
    return template.format(url=url, qurl=urllib.parse.quote(url, safe=""),
                           domain=p.hostname or url)


async def prepare(ctx, site, url, values, recorder_src, sem, entry_cb):
    entry = {"site": site["id"], "name": site["name"], "kind": site["kind"],
             "filled": [], "picked": [], "replayed": 0, "captcha": None,
             "can_autosubmit": False, "submitted": False, "verified": False,
             "stage": 1, "flags": [], "status": "открытие",
             "note": site["note"], "ts": datetime.now(timezone.utc).isoformat(),
             "reported_url": url, "recipe_steps": len(load_recipe(site["id"]))}
    page = None
    async with sem:
        try:
            page = await ctx.new_page()
            await page.add_init_script(recorder_src)
            target = expand(site["prefill"], url) if site["prefill"] else site["url"]
            entry["opened"] = target
            await page.goto(target, wait_until="domcontentloaded", timeout=45000)
            await recording(page, False)
            await decline_cookies(page)
            await page.wait_for_timeout(1500)

            entry["picked"] = await pick_threats(page, values)
            entry["filled"] = await fill_text(page, values)
            if not entry["filled"]:
                # SPA-страницы отрисовывают поля с задержкой. Повторяем один раз.
                await page.wait_for_timeout(4000)
                await decline_cookies(page)
                entry["picked"] = list(dict.fromkeys(entry["picked"] + await pick_threats(page, values)))
                entry["filled"] = await fill_text(page, values)

            entry["replayed"], entry["flags"] = await replay(page, load_recipe(site["id"]), values)
            if entry["replayed"]:
                entry["picked"] = list(dict.fromkeys(entry["picked"] + await pick_threats(page, values)))
                newly_filled = await fill_text(page, values)
                entry["filled"] = list(dict.fromkeys(entry["filled"] + newly_filled))

            entry["captcha"] = await has_captcha(page)
            entry["can_autosubmit"] = (not entry["captcha"]) and bool(await find_submit(page))
            bits = []
            if entry["filled"]:
                bits.append("заполнено: " + "+".join(entry["filled"]))
            if entry["picked"]:
                bits.append(f"выбрано: {len(entry['picked'])}")
            if entry["replayed"]:
                bits.append(f"шагов рецепта: {entry['replayed']}")
            if entry["flags"]:
                bits.append(f"проверить: {len(entry['flags'])}")
            entry["status"] = ", ".join(bits) or "открыто, нечего автозаполнять"
            await recording(page, True)
            if entry["captcha"]:
                entry["status"] += " — CAPTCHA, отправьте вручную"
            elif entry["can_autosubmit"]:
                entry["status"] += " — готово к отправке"
        except Exception as e:
            entry["status"] = f"FAIL: {type(e).__name__}: {str(e)[:110]}"
    entry_cb(entry)
    return page, entry


# Строгий паттерн подтверждения: кроме текста проверяем исчезновение кнопки отправки.
DONE_RE = re.compile(
    r"thank you for (your |the )?(report|submission|feedback)|"
    r"(report|submission|request|url)[^.]{0,40}(has been|was) (received|submitted|sent)|"
    r"we have received your|successfully submitted|submission (was )?successful|"
    r"спасибо за (обращение|жалобу|сообщение)|жалоба (успешно )?(принята|отправлена)",
    re.I,
)


async def submit_one(page, entry, values):
    """Один клик за нажатие. Для двухшаговых форм заполняет следующий шаг и ждёт нового нажатия."""
    if entry["captcha"]:
        entry["status"] = "пропущено — требуется прохождение CAPTCHA"
        return entry
    try:
        await page.bring_to_front()
        await page.wait_for_timeout(300)
    except Exception:
        pass
    btn = await find_submit(page)
    if not btn:
        entry["status"] = "пропущено — кнопка отправки не найдена, завершите вручную"
        return entry
    before = page.url
    try:
        await recording(page, False)
        await btn.click(timeout=6000)
        await page.wait_for_timeout(4000)
        await recording(page, False)
        body = ""
        try:
            body = (await page.inner_text("body"))[:2500]
        except Exception:
            pass

        gone = await find_submit(page) is None
        if gone:
            await recording(page, True)
        if DONE_RE.search(body) and gone:
            entry["submitted"] = entry["verified"] = True
            entry["status"] = f"отправлено — confirmed сайтом (шаг {entry['stage']})"
            return entry
        if gone and page.url != before:
            entry["submitted"] = True
            entry["status"] = "нажато, форма закрылась — вероятно отправлено, проверьте вкладку"
            return entry

        # Подтверждения нет — проверяем, появился ли следующий этап формы.
        entry["stage"] += 1
        newly = await pick_threats(page, values)
        entry["filled"] = await fill_text(page, values) or entry["filled"]
        entry["picked"] = list(dict.fromkeys(entry["picked"] + newly))
        entry["captcha"] = await has_captcha(page)
        entry["can_autosubmit"] = (not entry["captcha"]) and bool(await find_submit(page))
        await recording(page, True)

        if entry["can_autosubmit"] and (newly or page.url != before):
            bits = f"шаг {entry['stage']} готов"
            if newly:
                bits += " — выбрано: " + "; ".join(newly)
            entry["status"] = bits + " — нажмите «Отправить все» ещё раз"
        elif entry["captcha"]:
            entry["status"] = f"шаг {entry['stage']} — появилась CAPTCHA, завершите вручную"
        else:
            entry["submitted"] = True
            entry["status"] = (
                "нажато, страница сменилась без подтверждения — проверьте вкладку"
                if page.url != before
                else "нажато, видимых изменений нет — проверьте вкладку"
            )
    except Exception as e:
        entry["status"] = f"FAIL при отправке: {type(e).__name__}: {str(e)[:80]}"
    return entry


async def open_all(url, values, site_ids=None, headless=False,
                   stop_event=None, submit_event=None, on_result=None, learn=True):
    if fs.is_legit_domain(url):
        raise fs.OfficialDomainError(
            f"Отказ: {url} — официальный домен «Золотого Яблока». Формы вендоров не открываются."
        )

    from playwright.async_api import async_playwright

    norm_values = prepare_values(values)
    chosen = [s for s in SITES if (s["id"] in site_ids if site_ids else not s.get("skip"))]
    recorder_src = ""
    if learn and os.path.exists(RECORDER_JS):
        with open(RECORDER_JS, "r", encoding="utf-8") as f:
            recorder_src = f.read()
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    entries, pages = {}, {}

    def publish(e):
        entries[e["site"]] = e
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        except Exception:
            pass
        if on_result:
            on_result(dict(e))

    async with async_playwright() as pw:
        async def launch():
            return await pw.chromium.launch_persistent_context(
                PROFILE_DIR, headless=headless, viewport={"width": 1280, "height": 900},
                args=["--disable-blink-features=AutomationControlled"])
        try:
            ctx = await launch()
        except Exception:
            for f in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
                try:
                    os.unlink(os.path.join(PROFILE_DIR, f))
                except OSError:
                    pass
            ctx = await launch()
        sem = asyncio.Semaphore(MAX_PARALLEL)
        done = await asyncio.gather(*[
            prepare(ctx, s, url, dict(norm_values), recorder_src, sem, publish) for s in chosen],
            return_exceptions=True)
        for res in done:
            if isinstance(res, tuple):
                page, entry = res
                if page:
                    pages[entry["site"]] = page

        ready = [e for e in entries.values() if e["can_autosubmit"]]
        print(f"\nПодготовлено вкладок: {len(entries)}. "
              f"Готовы к автоотправке: {len(ready)}, остальные требуют ручного участия.")
        for e in entries.values():
            print(f"  [{e['status'][:52]:<52}] {e['name']}")

        async def harvest():
            saved = 0
            for sid, page in list(pages.items()):
                try:
                    steps = await page.evaluate(HARVEST_JS)
                except Exception:
                    continue
                n = save_recipe(sid, steps, norm_values)
                if n and entries.get(sid, {}).get("learned") != n:
                    entries[sid]["learned"] = n
                    publish(entries[sid])
                    saved += n
            return saved

        if stop_event is not None:
            ticks = 0
            while not stop_event.is_set():
                ticks += 1
                if learn and ticks % 40 == 0:
                    await harvest()
                if submit_event is not None and submit_event.is_set():
                    submit_event.clear()
                    for sid, page in list(pages.items()):
                        e = entries.get(sid)
                        if not e or e.get("submitted"):
                            continue
                        publish(await submit_one(page, e, dict(norm_values)))
                await asyncio.sleep(0.4)
        else:
            input("\nНажмите Enter, чтобы отправить вкладки без CAPTCHA, или Ctrl-C для выхода: ")
            for sid, page in list(pages.items()):
                publish(await submit_one(page, entries[sid], dict(norm_values)))
            input("Завершите вкладки с CAPTCHA вручную, затем нажмите Enter для закрытия: ")

        if learn:
            await harvest()

        await ctx.close()
    return list(entries.values())


def run(url, values, site_ids=None, headless=False, stop_event=None,
        submit_event=None, on_result=None, learn=True):
    return asyncio.run(open_all(url, values, site_ids, headless, stop_event,
                                submit_event, on_result, learn))


def selftest():
    # Классификация полей (английские и русские подписи)
    assert classify({"type": "text", "visible": True, "disabled": False, "filled": False,
                     "sig": "Enter the phishing URL", "i": 0}) == "url"
    assert classify({"type": "text", "visible": True, "disabled": False, "filled": False,
                     "sig": "Ссылка на мошеннический сайт", "i": 0}) == "url"
    assert classify({"type": "text", "visible": True, "disabled": False, "filled": True,
                     "sig": "url", "i": 0}) is None
    assert classify({"type": "text", "visible": True, "disabled": False, "filled": False,
                     "sig": "captcha code", "i": 0}) is None

    # Выбор категории угрозы
    assert best_threat_option(["Select one", "Spam", "Phishing", "Malware"]) == 2
    assert best_threat_option(["Select", "This is NOT phishing", "Fraud"]) == 2
    assert best_threat_option(["Выберите", "Фишинг", "Спам"]) == 1
    assert best_threat_option(["Blue", "Green"]) is None
    assert best_threat_option(["Select a category", "Malicious Site"]) == 1

    # Выбор бренда в выпадающем списке: если нет «Золотого Яблока», выбирается «Другое» / Other
    assert best_brand_option(["Select brand", "Apple", "PayPal", "Other"]) == (3, "other")
    assert best_brand_option(["Выберите бренд", "Банк", "Другое"]) == (2, "other")
    assert best_brand_option(["Select brand", "Gold Apple", "Other"]) == (1, "exact")
    assert best_brand_option(["Select brand", "Золотое Яблоко", "Другое"]) == (1, "exact")
    assert best_brand_option(["Option A", "Option B"]) == (None, None)

    # Автоматическое добавление бренда в комментарий
    c1 = ensure_brand_in_comment("Фейковый розыгрыш бьюти-бокса")
    assert BRAND_LABEL in c1, c1
    c2 = ensure_brand_in_comment(f"Фишинг {BRAND_LABEL}: кража карты")
    assert c2.count("goldapple.ru") == 1, c2

    # Проверка подтверждений отправки
    assert DONE_RE.search("Thank you for your submission")
    assert DONE_RE.search("Your report has been received")
    assert DONE_RE.search("Спасибо за обращение! Жалоба успешно принята.")
    assert not DONE_RE.search("Please complete the form below")
    assert not DONE_RE.search("Terms of Service. Categories submitted by users are reviewed."), \
        "boilerplate containing 'submitted' must not read as a confirmation"

    # Перенос обучения между разными фишинговыми доменами под «Золотое Яблоко»
    ga1 = prepare_values({
        "url": "https://goldapple-prize.top/gift",
        "domain": "goldapple-prize.top",
        "brand": BRAND_LABEL,
        "email": "drp@example.com",
        "name": "Аналитик ЗЯ",
        "comment": f"Фейковый розыгрыш {BRAND_LABEL}",
    })
    ga2 = prepare_values({
        "url": "https://gold-apple-sale.shop/pay",
        "domain": "gold-apple-sale.shop",
        "brand": BRAND_LABEL,
        "email": "drp@example.com",
        "name": "Аналитик ЗЯ",
        "comment": f"Фейковая распродажа {BRAND_LABEL}",
    })

    assert tokenize("https://goldapple-prize.top/gift", ga1) == "{{url}}"
    got = tokenize(f"Фишинг {BRAND_LABEL} на домене goldapple-prize.top", ga1)
    assert got == "Фишинг {{brand}} на домене {{domain}}", got
    out = detokenize(got, ga2)
    assert out == f"Фишинг {BRAND_LABEL} на домене gold-apple-sale.shop", out
    assert "goldapple-prize.top" not in out.lower(), "предыдущий фишинговый домен утёк в новую жалобу"
    assert tokenize("x" * 130, ga1) == "{{typed}}"
    assert tokenize("Credential harvesting", ga1) == "Credential harvesting"

    assert generalizes_as("Phishing", ga1) == "threat"
    assert generalizes_as(BRAND_LABEL, ga1) == "brand"
    assert generalizes_as("goldapple-prize.top", ga1) == "target"
    assert generalizes_as("Retail", ga1) == "sticky"
    assert generalizes_as("This is not phishing", ga1) == "sticky"

    import tempfile
    global RECIPES_DIR
    keep = RECIPES_DIR
    tmp_dir = tempfile.mkdtemp()
    RECIPES_DIR = tmp_dir
    try:
        save_recipe("t", [
            {"act": "fill", "sel": "#u", "value": "https://goldapple-prize.top/gift"},
            {"act": "fill", "sel": "#c", "value": f"Фишинг {BRAND_LABEL} на goldapple-prize.top"},
            {"act": "select", "sel": "#cat", "value": "ph", "text": "Phishing"},
            {"act": "select", "sel": "#brand", "value": "other", "text": BRAND_LABEL},
            {"act": "check", "sel": "#r1", "checked": True, "text": "Credential phishing"},
        ], ga1)
        steps = load_recipe("t")
        by = {x["sel"]: x for x in steps}
        assert by["#u"]["value"] == "{{url}}"
        assert by["#c"]["value"] == "Фишинг {{brand}} на {{domain}}"
        assert by["#cat"]["gen"] == "threat"
        assert by["#brand"]["gen"] == "brand"
        assert by["#r1"]["gen"] == "threat"
        blob = json.dumps(steps, ensure_ascii=False).lower()
        assert "goldapple-prize.top" not in blob, "домен цели не должен хардкодиться в рецепте: " + blob
    finally:
        RECIPES_DIR = keep
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Блокировка официального домена при попытке открыть формы
    blocked = False
    try:
        run("https://shop.goldapple.ru/catalog", ga1)
    except fs.OfficialDomainError:
        blocked = True
    assert blocked, "automate.run должен блокировать официальные домены «Золотого Яблока»"

    assert expand("https://x/?u={qurl}&d={domain}", "https://www.bad.top/a?b=1") == \
        "https://x/?u=https%3A%2F%2Fwww.bad.top%2Fa%3Fb%3D1&d=www.bad.top"
    print("automate selftest OK")


if __name__ == "__main__":
    selftest()