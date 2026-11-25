"""Национальные каналы подачи жалоб по странам.

В каждой записи фиксируется способ проверки (verified), чтобы нерабочие
ссылки не оставались в списке незаметно.

kind:
  email   - адрес автоматически добавляется в черновики писем
  form    - веб-форма; показывается как ссылка для заполнения
  hotline - телефон горячей линии; только для показа
"""
CHANNELS = {
    "MY": {
        "name": "Малайзия",
        "entries": [
            dict(
                id="mycert",
                kind="form",
                org="MyCERT Cyber999 (CyberSecurity Malaysia)",
                target="https://www.mycert.org.my/cyber999",
                when="всегда — национальный CERT, координирует блокировки",
                note="Технический канал. Они обращаются к хостеру и регистратору от вашего "
                     "имени и имеют больший вес, чем обычное частное лицо.",
                verified="HTTP 200",
            ),
            dict(
                id="mycert_mail",
                kind="email",
                org="MyCERT Cyber999",
                target="cyber999@cybersecurity.my",
                when="всегда — та же команда, что и в форме, но по e-mail",
                note="Почтовый домен принимает письма; адрес Cyber999 публиковался ранее, "
                     "но на странице напрямую не указан. Если письмо вернётся — используйте форму.",
                verified="MX присутствует для cybersecurity.my",
            ),
            dict(
                id="mcmc",
                kind="form",
                org="MCMC (Malaysian Communications and Multimedia Commission)",
                target="https://aduan.mcmc.gov.my/",
                when="всегда для фишинговых сайтов и поддельных SMS",
                note="Регулятор. Занимается блокировкой сайтов в Малайзии и жалобами "
                     "на подмену SMS, с которыми регистраторы доменов не работают.",
                verified="HTTP 200 (редирект с aduan.skmm.gov.my)",
            ),
            dict(
                id="semakmule",
                kind="form",
                org="PDRM Semak Mule",
                target="https://semakmule.rmp.gov.my/",
                when="если мошенники указали банковский счёт или номер телефона",
                note="Полицейская база счетов и номеров дропов. Проверьте счёт или номер "
                     "и отправьте жалобу, если их ещё нет в базе.",
                verified="HTTP 200",
            ),
            dict(
                id="nsrc",
                kind="hotline",
                org="National Scam Response Centre",
                target="997",
                when="ТОЛЬКО если деньги уже переведены — звонить немедленно",
                note="В первые часы иногда удаётся заморозить средства. "
                     "Остальные каналы не требуют такой срочности.",
                verified="горячая линия, недоступна для автоматической проверки",
            ),
            dict(
                id="cyber999_phone",
                kind="hotline",
                org="Cyber999 hotline",
                target="1-300-88-2999",
                when="если нужно обсудить инцидент голосом, а не заполнять форму",
                note="Номер опубликован на странице mycert.org.my/cyber999.",
                verified="взято с mycert.org.my/cyber999",
            ),
        ],
    },
}


def get(code):
    return CHANNELS.get((code or "").upper())


def countries():
    return sorted([(k, v["name"]) for k, v in CHANNELS.items()], key=lambda x: x[1])


def emails(code):
    """Пары (address, label) для автоматического добавления в черновики писем."""
    c = get(code)
    if not c:
        return []
    return [(e["target"], f"{e['org']} ({c['name']})")
            for e in c["entries"] if e["kind"] == "email"]


def forms(code):
    """Пары (label, url) для списка ручных форм."""
    c = get(code)
    if not c:
        return []
    return [(f"{e['org']} — {e['when']}", e["target"])
            for e in c["entries"] if e["kind"] == "form"]


def all_entries(code):
    c = get(code)
    return c["entries"] if c else []


def selftest():
    assert get("my")["name"] == "Малайзия"
    assert get("MY") is get("my"), "код страны не должен зависеть от регистра"
    assert get("ZZ") is None and emails("ZZ") == [] and forms("ZZ") == []

    addrs = [a for a, _ in emails("MY")]
    assert "cyber999@cybersecurity.my" in addrs
    # В почтовые черновики попадают только записи типа email
    assert all("@" in a for a in addrs)
    assert not any(t.startswith("http") or t.isdigit() for t in addrs)

    urls = [u for _, u in forms("MY")]
    assert "https://aduan.mcmc.gov.my/" in urls
    assert all(u.startswith("https://") for u in urls), urls
    # Экстренный канал — только горячая линия, без автоотправки
    nsrc = [e for e in all_entries("MY") if e["id"] == "nsrc"][0]
    assert nsrc["kind"] == "hotline" and "ТОЛЬКО если деньги" in nsrc["when"]
    # У каждой записи заполнен способ проверки
    assert all(e.get("verified") for e in all_entries("MY"))
    assert ("MY", "Малайзия") in countries()
    print("channels selftest OK")


if __name__ == "__main__":
    selftest()
