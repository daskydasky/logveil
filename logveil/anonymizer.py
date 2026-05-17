"""Deterministic anonymization for mail server log lines."""

from __future__ import annotations

import hmac
import ipaddress
import re
from collections import Counter
from hashlib import sha256
from typing import Match


TOKEN_HEX_LEN = 12


class MailLogAnonymizer:
    """Anonymize sensitive values in Postfix/Dovecot/Rspamd style log lines."""

    SYSLOG_PREFIX_RE = re.compile(
        r"^(?P<prefix>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)"
        r"(?P<host>\S+)"
        r"(?P<suffix>\s+)"
    )
    MESSAGE_ID_RE = re.compile(
        r"(?P<prefix>\bmessage-id=<|Message-ID:\s*<)(?P<value>[^>\s]+)(?P<suffix>>)",
        re.IGNORECASE,
    )
    SASL_USERNAME_RE = re.compile(r"(?P<prefix>\bsasl_username=)(?P<value>[^,\s]+)")
    BRACKET_HOST_RE = re.compile(
        r"(?P<prefix>\b(?:client|relay)=)"
        r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)"
        r"\[(?P<ip>[^\]]+)\]"
    )
    CONNECT_FROM_RE = re.compile(
        r"(?P<prefix>\bconnect from\s+)"
        r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)"
        r"\[(?P<ip>[^\]]+)\]"
    )
    HELO_RE = re.compile(
        r"(?P<prefix>\bhelo=<)"
        r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)"
        r"(?P<suffix>>)",
        re.IGNORECASE,
    )
    EMAIL_RE = re.compile(
        r"(?<![\w.+-])"
        r"(?P<email>[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})"
        r"(?![\w.-])"
    )
    IPV4_RE = re.compile(r"(?<![\w.])(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
    IPV6_RE = re.compile(
        r"(?<![\w:])"
        r"(?P<ip>(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?:%[A-Za-z0-9_.-]+)?)"
        r"(?![\w:])"
    )
    GENERATED_RE = re.compile(r"^(?:email|ip|host|user|msgid)_[0-9a-f]{12}$")
    GENERATED_EMAIL_USER_RE = re.compile(r"^user_[0-9a-f]{12}@")

    def __init__(self, key: bytes, preserve_email_domain: bool = False) -> None:
        self.key = key
        self.preserve_email_domain = preserve_email_domain
        self.stats: Counter[str] = Counter()

    def anonymize_line(self, line: str) -> str:
        """Return an anonymized copy of one log line, preserving its newline."""
        line = self.SYSLOG_PREFIX_RE.sub(self._replace_syslog_host, line, count=1)
        line = self.MESSAGE_ID_RE.sub(self._replace_message_id, line)
        line = self.SASL_USERNAME_RE.sub(self._replace_sasl_username, line)
        line = self.BRACKET_HOST_RE.sub(self._replace_bracket_host, line)
        line = self.CONNECT_FROM_RE.sub(self._replace_connect_from, line)
        line = self.HELO_RE.sub(self._replace_helo, line)
        line = self.EMAIL_RE.sub(self._replace_email_match, line)
        line = self.IPV4_RE.sub(self._replace_ipv4_match, line)
        line = self.IPV6_RE.sub(self._replace_ipv6_match, line)
        return line

    def token(self, prefix: str, value: str) -> str:
        digest = hmac.new(self.key, value.encode("utf-8"), sha256).hexdigest()
        return f"{prefix}_{digest[:TOKEN_HEX_LEN]}"

    def _counted_token(self, prefix: str, value: str, stat: str | None = None) -> str:
        self.stats[stat or prefix] += 1
        return self.token(prefix, value)

    def _replace_syslog_host(self, match: Match[str]) -> str:
        host = match.group("host")
        if self._is_generated_token(host):
            return match.group(0)
        return (
            match.group("prefix")
            + self._counted_token("host", host)
            + match.group("suffix")
        )

    def _replace_message_id(self, match: Match[str]) -> str:
        value = match.group("value")
        if self._is_generated_token(value):
            return match.group(0)
        return match.group("prefix") + self._counted_token("msgid", value) + match.group("suffix")

    def _replace_sasl_username(self, match: Match[str]) -> str:
        value = match.group("value")
        if self._is_generated_token(value) or self.GENERATED_EMAIL_USER_RE.match(value):
            return match.group(0)
        if "@" in value:
            replacement = self._email_token(value)
        else:
            replacement = self._counted_token("user", value)
        return match.group("prefix") + replacement

    def _replace_bracket_host(self, match: Match[str]) -> str:
        host = self._host_token(match.group("host"))
        ip = self._ip_token_if_valid(match.group("ip"))
        return f"{match.group('prefix')}{host}[{ip}]"

    def _replace_connect_from(self, match: Match[str]) -> str:
        host = self._host_token(match.group("host"))
        ip = self._ip_token_if_valid(match.group("ip"))
        return f"{match.group('prefix')}{host}[{ip}]"

    def _replace_helo(self, match: Match[str]) -> str:
        return match.group("prefix") + self._host_token(match.group("host")) + match.group("suffix")

    def _replace_email_match(self, match: Match[str]) -> str:
        value = match.group("email")
        if self.GENERATED_EMAIL_USER_RE.match(value):
            return value
        return self._email_token(value)

    def _replace_ipv4_match(self, match: Match[str]) -> str:
        return self._ip_token_if_valid(match.group("ip"))

    def _replace_ipv6_match(self, match: Match[str]) -> str:
        return self._ip_token_if_valid(match.group("ip"))

    def _email_token(self, value: str) -> str:
        if self.preserve_email_domain:
            _, _, domain = value.rpartition("@")
            self.stats["email"] += 1
            return f"{self.token('user', value)}@{domain}"
        return self._counted_token("email", value)

    def _host_token(self, value: str) -> str:
        if self._is_generated_token(value):
            return value
        return self._counted_token("host", value)

    def _ip_token_if_valid(self, value: str) -> str:
        candidate = value.strip()
        try:
            ipaddress.ip_address(candidate.split("%", 1)[0])
        except ValueError:
            return value
        if self._is_generated_token(candidate):
            return value
        return self._counted_token("ip", value)

    def _is_generated_token(self, value: str) -> bool:
        return bool(self.GENERATED_RE.match(value))
