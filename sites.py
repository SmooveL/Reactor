"""Сайты вендоров (блок-листы и сервисы репутации) и способы перехода к их формам жалоб.

kind:
  report  - страница сразу является формой жалобы на вредоносный URL
  lookup  - страница проверки репутации; сначала проверяется URL, затем
            нажимается кнопка пересмотра / обратной связи (dispute / feedback)
prefill:
  шаблон с {url}, {qurl} (percent-encoded), {domain}. Открывает страницу уже с
  подставленным URL — вводить вручную не нужно.
note:
  что специалисту остаётся нажать вручную после открытия вкладки. Показывается в интерфейсе.
"""

SITES = [
    dict(id="google", name="Google Safe Browsing", kind="report",
         url="https://safebrowsing.google.com/safebrowsing/report_phish/",
         prefill="https://safebrowsing.google.com/safebrowsing/report_phish/?url={qurl}",
         note="URL уже подставлен. Пройдите CAPTCHA и нажмите Submit Report."),

    dict(id="microsoft", name="Microsoft SmartScreen", kind="report",
         url="https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest",
         prefill="https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest?url={qurl}",
         note="Выберите тип угрозы Phishing, пройдите CAPTCHA и нажмите Submit."),

    dict(id="fortiguard", name="Fortiguard (Fortinet)", kind="lookup",
         url="https://www.fortiguard.com/webfilter", prefill=None,
         note="После загрузки рейтинга нажмите иконку карандаша / Request Reclassification, "
              "выберите Phishing, укажите ваш e-mail и нажмите Submit."),

    dict(id="brightcloud", name="BrightCloud (Webroot)", kind="lookup",
         url="https://www.brightcloud.com/tools/url-ip-lookup.php", prefill=None,
         note="Нажмите Check URL, затем Request a Reclassification -> Phishing."),

    dict(id="crdf", name="CRDF Threat Center", kind="report",
         url="https://threatcenter.crdf.fr/submit_url.html", prefill=None,
         note="Поле URL заполнено. Решите CAPTCHA и нажмите Submit."),

    dict(id="netcraft", name="Netcraft", kind="report",
         url="https://report.netcraft.com/report", prefill=None,
         note="Ссылка уже отправлена через API — используйте эту вкладку, только если API вернул SKIP/FAIL."),

    dict(id="paloalto", name="Palo Alto Networks URL Filtering", kind="lookup",
         url="https://urlfiltering.paloaltonetworks.com/", prefill=None,
         note="Найдите URL, затем нажмите Request Change -> предложите категорию Phishing."),

    dict(id="eset", name="ESET", kind="report",
         url="https://phishing.eset.com/en-us/report", prefill=None,
         note="URL и ваш e-mail заполнены. Пройдите CAPTCHA и нажмите Submit."),

    dict(id="trendmicro", name="Trend Micro Site Safety", kind="lookup",
         url="https://global.sitesafety.trendmicro.com/", prefill=None,
         note="Нажмите Check, затем Give Feedback -> запросите категорию Disease Vector / Phishing."),

    dict(id="bitdefender", name="Bitdefender", kind="lookup",
         url="https://www.bitdefender.com/consumer/support/answer/29358/", prefill=None,
         note="Это страница с инструкцией Bitdefender — прямой формы нет. "
              "Следуйте инструкции или отправьте URL на submit@bitdefender.com."),

    dict(id="mcafee", name="McAfee / Trellix SiteLookup", kind="lookup",
         url="https://sitelookup.mcafee.com/", prefill=None,
         note="Введите URL, нажмите Check URL, затем Submit URL for review с категорией Phishing."),

    dict(id="forcepoint", name="Forcepoint CSI", kind="lookup",
         url="https://csi.forcepoint.com/", prefill=None, skip=True,
         note="Домен csi.forcepoint.com не резолвится (ошибка DNS на стороне Forcepoint, "
              "проверено 2026-09-05). Отключено по умолчанию. Включите снова, если заработает, "
              "или отправьте URL в их поддержку."),

    dict(id="symantec", name="Symantec / Broadcom Site Review", kind="lookup",
         url="https://sitereview.symantec.com/", prefill="https://sitereview.symantec.com/#/?search={qurl}",
         note="Примите условия, проверьте сайт, затем нажмите Submit a Dispute -> Phishing и укажите e-mail."),

    dict(id="spam404", name="Spam404", kind="report",
         url="https://www.spam404.com/report.html", prefill=None,
         note="URL и e-mail заполнены. Решите CAPTCHA и нажмите Submit."),

    dict(id="kaspersky", name="Kaspersky OpenTIP", kind="lookup",
         url="https://opentip.kaspersky.com/", prefill="https://opentip.kaspersky.com/{qurl}/?tab=lookup",
         note="Проверка бесплатна; для отправки вердикта нужен бесплатный аккаунт Kaspersky. "
              "Либо отправьте ссылку на newvirus@kaspersky.com."),

    dict(id="talos", name="Cisco Talos", kind="lookup",
         url="https://talosintelligence.com/reputation_center/",
         prefill="https://talosintelligence.com/reputation_center/lookup?search={domain}",
         note="Проверьте репутацию, затем используйте ссылку Submit a Dispute / поддержку "
              "на talosintelligence.com/reputation_center/support."),
]

for _s in SITES:
    _s.setdefault("skip", False)   # skip=True: заведомо нерабочий сайт, снят по умолчанию

BY_ID = {s["id"]: s for s in SITES}