"""Offline email address validation and normalisation.

Uses ``email-validator`` (Unlicense) with DNS checks disabled: syntax per RFC 5321/5322, SMTPUTF8
(RFC 6531), IDNA domains and special-use domain rejection — no network access. DNS/MX checks belong
to a separate, network-declaring module (stage 2).
"""

from __future__ import annotations

from importlib.metadata import version

from email_validator import EmailNotValidError, validate_email

from osint_toolkit.core.models import Confidence, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput

VALIDATOR_URL = "https://github.com/JoshData/python-email-validator"
RFC5233_URL = "https://www.rfc-editor.org/rfc/rfc5233"
RFC2142_URL = "https://www.rfc-editor.org/rfc/rfc2142"
GMAIL_DOTS_URL = "https://support.google.com/mail/answer/7436150"

GMAIL_DOMAINS = frozenset({"gmail.com", "googlemail.com"})

# RFC 2142 §3–5 mailbox names.
RFC2142_MAILBOXES = frozenset(
    {
        "info",
        "marketing",
        "sales",
        "support",
        "abuse",
        "noc",
        "security",
        "postmaster",
        "hostmaster",
        "usenet",
        "news",
        "webmaster",
        "www",
        "uucp",
        "ftp",
    }
)
# Widespread shared-mailbox names not defined by RFC 2142.
COMMON_SHARED_MAILBOXES = frozenset(
    {
        "admin",
        "administrator",
        "contact",
        "hello",
        "help",
        "billing",
        "office",
        "hr",
        "jobs",
        "careers",
        "team",
        "mail",
        "noreply",
        "no-reply",
        "donotreply",
        "press",
        "privacy",
        "legal",
        "accounts",
        "service",
        "feedback",
        "root",
    }
)


def split_subaddress(local_part: str) -> tuple[str, str | None]:
    """Split ``user+tag`` (RFC 5233). Quoted local parts are not split."""
    if local_part.startswith('"') or "+" not in local_part:
        return local_part, None
    base, _, tag = local_part.partition("+")
    return (base, tag) if base else (local_part, None)


class EmailSyntaxModule(BaseModule):
    name = "email.syntax"
    title = "Синтаксис и нормализация email"
    description = (
        "Проверка адреса по RFC 5321/5322/6531, IDNA-нормализация домена, субадреса (+tag), "
        "служебные ящики. Без сетевых запросов."
    )
    target_types = frozenset({TargetType.EMAIL})
    limitations = (
        "Синтаксически корректный адрес не обязательно существует: проверка DNS/MX выполняется "
        "отдельным модулем.",
        "Служебный адрес (info@, support@ …) обычно используется группой людей и не указывает "
        "на конкретного человека.",
    )

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        source = f"email-validator {version('email-validator')}"
        try:
            info = validate_email(
                target.normalized,
                check_deliverability=False,
                allow_smtputf8=True,
                allow_quoted_local=True,
                allow_domain_literal=False,
                globally_deliverable=True,
                strict=True,  # enforce the RFC 5321 64-octet local-part limit
            )
        except EmailNotValidError as exc:
            out.findings.append(
                self.finding(
                    target,
                    "email.valid",
                    False,
                    Confidence.CONFIRMED,
                    source,
                    VALIDATOR_URL,
                    f"Адрес не соответствует стандартам: {exc}",
                    exclusive=True,
                )
            )
            return out

        f = out.findings.append
        f(
            self.finding(
                target,
                "email.valid",
                True,
                Confidence.CONFIRMED,
                source,
                VALIDATOR_URL,
                "Адрес синтаксически корректен (RFC 5321/5322; домен — IDNA 2008), домен "
                "не относится к зарезервированным special-use именам.",
                exclusive=True,
            )
        )
        f(
            self.finding(
                target,
                "email.normalized",
                info.normalized,
                Confidence.CONFIRMED,
                source,
                VALIDATOR_URL,
                "Нормализованная форма: домен в нижнем регистре и IDNA, "
                "локальная часть приведена к Unicode NFC.",
                exclusive=True,
            )
        )
        if info.ascii_email and info.ascii_email != info.normalized:
            f(
                self.finding(
                    target,
                    "email.ascii_form",
                    info.ascii_email,
                    Confidence.CONFIRMED,
                    source,
                    VALIDATOR_URL,
                    "ASCII-форма адреса с punycode-доменом.",
                    exclusive=True,
                )
            )
        f(
            self.finding(
                target,
                "email.smtputf8_required",
                bool(info.smtputf8),
                Confidence.CONFIRMED,
                source,
                "https://www.rfc-editor.org/rfc/rfc6531",
                "Требуется ли поддержка SMTPUTF8 (не-ASCII символы в локальной части).",
                exclusive=True,
            )
        )

        local = info.local_part
        domain = info.ascii_domain.lower()
        base, tag = split_subaddress(local)
        if tag is not None:
            f(
                self.finding(
                    target,
                    "email.subaddress",
                    {"base": base, "tag": tag},
                    Confidence.LIKELY,
                    "RFC 5233 (subaddress extension)",
                    RFC5233_URL,
                    f"Локальная часть содержит тег «+{tag}». Многие провайдеры доставляют "
                    f"такие письма в ящик «{base}», но это зависит от провайдера.",
                )
            )

        if domain in GMAIL_DOMAINS:
            canonical = f"{base.replace('.', '').lower()}@gmail.com"
            if canonical != info.normalized.lower():
                f(
                    self.finding(
                        target,
                        "email.provider_canonical",
                        canonical,
                        Confidence.LIKELY,
                        "Gmail Help: «Dots don't matter in Gmail addresses»",
                        GMAIL_DOTS_URL,
                        "По документации Gmail точки в имени не учитываются, а "
                        "googlemail.com — тот же сервис; тег «+…» отброшен по RFC 5233. "
                        "Скорее всего, это тот же ящик.",
                        exclusive=True,
                    )
                )

        role = base.lower()
        if role in RFC2142_MAILBOXES:
            f(
                self.finding(
                    target,
                    "email.role_mailbox",
                    role,
                    Confidence.CONFIRMED,
                    "RFC 2142",
                    RFC2142_URL,
                    f"Имя «{role}» входит в список служебных ящиков RFC 2142.",
                )
            )
        elif role in COMMON_SHARED_MAILBOXES:
            f(
                self.finding(
                    target,
                    "email.role_mailbox",
                    role,
                    Confidence.LIKELY,
                    "Распространённые имена общих ящиков",
                    RFC2142_URL,
                    f"Имя «{role}» часто используется для общих или служебных ящиков.",
                )
            )
        return out
