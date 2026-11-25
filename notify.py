"""Уведомления на рабочем столе для фонового мониторинга.

Работает только на macOS (osascript). На остальных ОС тихо ничего не делает —
отсутствие уведомлений никогда не должно ломать работу инструмента.
"""
import json
import os
import platform
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
SEEN = os.path.join(HERE, "reports", ".notified.json")

# Только эти переходы статусов достойны отдельного уведомления.
WORTH_TELLING = {
    ("live", "blocked"): "теперь заблокирован — браузеры показывают предупреждение",
    ("live-flagged", "blocked"): "теперь заблокирован — браузеры показывают предупреждение",
    ("unknown", "blocked"): "теперь заблокирован — браузеры показывают предупреждение",
    ("live", "live-flagged"): "попал в блок-листы",
    ("unknown", "live-flagged"): "попал в блок-листы",
    ("live", "suspended"): "ПРИОСТАНОВЛЕН регистратором (suspended)",
    ("live-flagged", "suspended"): "ПРИОСТАНОВЛЕН регистратором (suspended)",
    ("blocked", "suspended"): "ПРИОСТАНОВЛЕН регистратором (suspended)",
    ("offline", "suspended"): "ПРИОСТАНОВЛЕН регистратором (suspended)",
    ("unknown", "suspended"): "ПРИОСТАНОВЛЕН регистратором (suspended)",
    ("live", "offline"): "перестал резолвиться — домен ещё зарегистрирован и может вернуться",
    ("live-flagged", "offline"): "перестал резолвиться — домен ещё зарегистрирован и может вернуться",
    ("blocked", "offline"): "перестал резолвиться — домен ещё зарегистрирован и может вернуться",
    ("unknown", "offline"): "перестал резолвиться — домен ещё зарегистрирован и может вернуться",
    ("offline", "live"): "снова резолвится — сайт перенесли на новый хост",
    ("offline", "blocked"): "снова доступен и снова заблокирован",
    ("blocked", "live"): "снова активен — предупреждение о блокировке снято",
    ("suspended", "live"): "снова работает — приостановка домена снята",
}


def _clean(s):
    # osascript принимает строку AppleScript; кавычки и слэши не должны её ломать
    return re.sub(r'[\\"]', "", str(s))[:230]


def send(title, message, subtitle=""):
    if platform.system() != "Darwin":
        return False
    script = f'display notification "{_clean(message)}" with title "{_clean(title)}"'
    if subtitle:
        script += f' subtitle "{_clean(subtitle)}"'
    try:
        subprocess.run(["osascript", "-e", script], timeout=8,
                       capture_output=True, check=False)
        return True
    except Exception:
        return False


def _load():
    try:
        with open(SEEN, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(d):
    os.makedirs(os.path.dirname(SEEN), exist_ok=True)
    with open(SEEN, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1, ensure_ascii=False)


def transition(host, old, new):
    """Текст уведомления при смене статуса или None, если уведомлять не о чем."""
    if old == new:
        return None
    return WORTH_TELLING.get((old or "unknown", new))


def on_state(host, url, old, new, enabled=True):
    msg = transition(host, old, new)
    if not msg or not enabled:
        return None
    send("Reactor", f"{host}: {msg}", url or "")
    return msg


def once(key, title, message, subtitle="", enabled=True):
    """Показывает уведомление не более одного раза для данного ключа."""
    seen = _load()
    if key in seen or not enabled:
        return False
    seen[key] = True
    _save(seen)
    return send(title, message, subtitle)


def selftest():
    assert transition("a", "live", "blocked").startswith("теперь заблокирован")
    assert transition("a", "blocked", "blocked") is None, "нет уведомления, если статус не изменился"
    assert transition("a", "blocked", "live-flagged") is None, "откат статуса не требует уведомления"
    assert "ПРИОСТАНОВЛЕН" in transition("a", "live", "suspended")
    assert transition("a", "blocked", "offline").startswith("перестал резолвиться")
    assert "ещё зарегистрирован" in transition("a", "live", "offline"), \
        "пропажа DNS не должна объявляться полным снятием домена"
    assert transition("a", "offline", "live").startswith("снова резолвится")
    assert transition("a", "blocked", "live").startswith("снова активен")
    assert '"' not in _clean('he said "hi" \\ there')
    assert len(_clean("x" * 500)) <= 230
    print("notify selftest OK")


if __name__ == "__main__":
    selftest()
