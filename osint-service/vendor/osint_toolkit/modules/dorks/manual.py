"""Manual dork links: Google / Yandex / Bing URLs for every spelling variant and dork group.

Offline: nothing is sent anywhere. The links are opened only by the user's click (TUI finding
card, HTML report), so the search engine receives the query from the user's own browser —
including Google, which offers no usable public search API for new customers.
"""

from __future__ import annotations

from typing import ClassVar

from osint_toolkit.config import Settings
from osint_toolkit.core.models import Confidence, JsonValue, Target, TargetType
from osint_toolkit.dorks import build_dorks, manual_links, variants_for
from osint_toolkit.integrations.search import select_providers
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput

SOURCE_URL = "urn:osint-toolkit:dork-builder"


class ManualDorksModule(BaseModule):
    name = "dorks.manual"
    title = "Ссылки для ручного поиска (дорки)"
    description = (
        "Готовые запросы-дорки по всем вариантам записи идентификатора со ссылками для Google, "
        "Яндекса и Bing. Офлайн: открываются только по вашему клику."
    )
    target_types = frozenset(
        {TargetType.EMAIL, TargetType.PHONE, TargetType.NAME, TargetType.USERNAME}
    )
    limitations: ClassVar[tuple[str, ...]] = (
        "При переходе по ссылке поисковик увидит запрос и ваш IP — это ваш обычный поиск в "
        "браузере. Результаты такого поиска программа не видит и не сохраняет.",
    )

    def enabled_by_default(self, settings: Settings) -> bool:
        # With a search provider the dorks are executed by mentions.* and only the ones with
        # results are shown; the full list of manual links is then available on request (-m).
        return not select_providers(settings)

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        settings = ctx.settings
        variants = variants_for(target)
        dorks = build_dorks(
            target,
            supports_or=True,
            default_region=settings.default_region,
            enabled_groups=settings.enabled_dork_groups(),
        )
        out.findings.append(
            self.finding(
                target,
                "dork.variants",
                list(variants),
                Confidence.CONFIRMED,
                "Генератор вариантов osint-toolkit",
                SOURCE_URL,
                f"Варианты записи, по которым строятся запросы ({len(variants)}). Формы, которые "
                "поисковики читают одинаково (например, с «+» и без), объединены.",
            )
        )
        if target.type is TargetType.PHONE and not target.details.get("region_known"):
            out.limitations.append(
                "Страна номера неизвестна — вариантов записи нет. Укажите "
                "номер с «+» или задайте OSINT_DEFAULT_REGION."
            )
        for dork in dorks:
            links = manual_links(dork.query)
            value: dict[str, JsonValue] = {"group": dork.title, "query": dork.query, **links}
            out.findings.append(
                self.finding(
                    target,
                    "dork.manual_query",
                    value,
                    Confidence.CONFIRMED,
                    f"Дорк «{dork.title}»",
                    links["google"],
                    f"Запрос для ручной проверки ({dork.title}); покрывает варианты: "
                    f"{', '.join(dork.variants)}. Ссылки открываются только по вашему клику.",
                )
            )
        return out
