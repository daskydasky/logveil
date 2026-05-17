from logveil.anonymizer import MailLogAnonymizer


KEY = bytes.fromhex("00" * 32)


def token(prefix, value):
    return MailLogAnonymizer(KEY).token(prefix, value)


def test_acceptance_client_sasl_line():
    anonymizer = MailLogAnonymizer(KEY)
    original = (
        "May 17 10:12:01 s3 postfix/smtpd[1234]: ABC123: "
        "client=mail.example.com[1.2.3.4], sasl_method=PLAIN, "
        "sasl_username=john@example.com\n"
    )

    expected = (
        f"May 17 10:12:01 {token('host', 's3')} postfix/smtpd[1234]: ABC123: "
        f"client={token('host', 'mail.example.com')}[{token('ip', '1.2.3.4')}], "
        f"sasl_method=PLAIN, sasl_username={token('email', 'john@example.com')}\n"
    )

    assert anonymizer.anonymize_line(original) == expected


def test_acceptance_from_line():
    anonymizer = MailLogAnonymizer(KEY)
    original = (
        "May 17 10:12:05 s3 postfix/qmgr[2222]: ABC123: "
        "from=<john@example.com>, size=1234, nrcpt=1\n"
    )

    expected = (
        f"May 17 10:12:05 {token('host', 's3')} postfix/qmgr[2222]: ABC123: "
        f"from=<{token('email', 'john@example.com')}>, size=1234, nrcpt=1\n"
    )

    assert anonymizer.anonymize_line(original) == expected


def test_acceptance_to_relay_line():
    anonymizer = MailLogAnonymizer(KEY)
    original = (
        "May 17 10:12:06 s3 postfix/smtp[3333]: ABC123: "
        "to=<alice@example.net>, relay=mx.example.net[5.6.7.8]:25, "
        "delay=1.2, delays=0.1/0.1/0.5/0.5, dsn=2.0.0, status=sent\n"
    )

    expected = (
        f"May 17 10:12:06 {token('host', 's3')} postfix/smtp[3333]: ABC123: "
        f"to=<{token('email', 'alice@example.net')}>, "
        f"relay={token('host', 'mx.example.net')}[{token('ip', '5.6.7.8')}]:25, "
        "delay=1.2, delays=0.1/0.1/0.5/0.5, dsn=2.0.0, status=sent\n"
    )

    assert anonymizer.anonymize_line(original) == expected


def test_message_id_gets_msgid_token_not_email_token():
    anonymizer = MailLogAnonymizer(KEY)
    original = "May 17 10:12:07 s3 postfix/cleanup[4444]: Message-ID: <abc123@example.com>\n"

    result = anonymizer.anonymize_line(original)

    assert f"Message-ID: <{token('msgid', 'abc123@example.com')}>" in result
    assert token("email", "abc123@example.com") not in result


def test_rfc3339_syslog_hostname_is_anonymized():
    anonymizer = MailLogAnonymizer(KEY)
    original = "2026-05-17T10:12:01+00:00 mx1.example.org postfix/smtpd[1234]: connect\n"

    expected = (
        f"2026-05-17T10:12:01+00:00 {token('host', 'mx1.example.org')} "
        "postfix/smtpd[1234]: connect\n"
    )

    assert anonymizer.anonymize_line(original) == expected


def test_rfc3339_fractional_syslog_hostname_is_anonymized_with_existing_tokens():
    anonymizer = MailLogAnonymizer(KEY)
    original = (
        "2026-05-10T00:46:46.249924+00:00 s3 "
        "postfix/submissions/smtpd[1058622]: connect from "
        "host_ed7133a1ab3a[ip_9f565312a970]\n"
    )

    expected = (
        f"2026-05-10T00:46:46.249924+00:00 {token('host', 's3')} "
        "postfix/submissions/smtpd[1058622]: connect from "
        "host_ed7133a1ab3a[ip_9f565312a970]\n"
    )

    assert anonymizer.anonymize_line(original) == expected


def test_rfc3339_fractional_warning_hostname_is_anonymized_with_existing_tokens():
    anonymizer = MailLogAnonymizer(KEY)
    original = (
        "2026-05-10T00:46:48.486489+00:00 s3 "
        "postfix/submissions/smtpd[1058622]: warning: "
        "unknown[ip_9f565312a970]: SASL LOGIN authentication failed: "
        "(reason unavailable), sasl_username=email_8ad1f308411e\n"
    )

    expected = (
        f"2026-05-10T00:46:48.486489+00:00 {token('host', 's3')} "
        "postfix/submissions/smtpd[1058622]: warning: "
        "unknown[ip_9f565312a970]: SASL LOGIN authentication failed: "
        "(reason unavailable), sasl_username=email_8ad1f308411e\n"
    )

    assert anonymizer.anonymize_line(original) == expected


def test_postfix_reject_from_hostname_is_anonymized():
    anonymizer = MailLogAnonymizer(KEY)
    original = (
        "May 17 10:12:08 s3 postfix/smtpd[1234]: NOQUEUE: reject: RCPT "
        "from mail.example.com[1.2.3.4]: 554 5.7.1 blocked; "
        "from=<bad@example.com> to=<user@example.net> helo=<mail.example.com>\n"
    )

    result = anonymizer.anonymize_line(original)

    assert "mail.example.com" not in result
    assert "1.2.3.4" not in result
    assert f"from {token('host', 'mail.example.com')}[{token('ip', '1.2.3.4')}]" in result
    assert f"helo=<{token('host', 'mail.example.com')}>" in result


def test_preserve_email_domain_mode():
    anonymizer = MailLogAnonymizer(KEY, preserve_email_domain=True)

    result = anonymizer.anonymize_line("from=<john@example.com>\n")

    assert result == f"from=<{token('user', 'john@example.com')}@example.com>\n"


def test_ipv6_is_anonymized():
    anonymizer = MailLogAnonymizer(KEY)

    result = anonymizer.anonymize_line("rip=2001:db8::1, lip=::1\n")

    assert token("ip", "2001:db8::1") in result
    assert token("ip", "::1") in result


def test_keeps_original_newline_ending():
    anonymizer = MailLogAnonymizer(KEY)

    result = anonymizer.anonymize_line("from=<john@example.com>\r\n")

    assert result.endswith("\r\n")
