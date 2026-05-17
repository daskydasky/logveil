# logveil

`logveil` anonymizes existing log files while keeping the original line structure useful for troubleshooting and statistical analysis.

The first version is focused on Postfix, Dovecot, Rspamd, and similar mail logs such as:

- `/var/log/mail.log`
- `mail.log.1`
- `mail.log.1.gz`

The tool streams input line by line. It does not process live logs in this first version.

## What Gets Replaced

Sensitive values are replaced with deterministic tokens:

- Email addresses: `email_ab12cd34ef56`
- IP addresses: `ip_ab12cd34ef56`
- Hostnames: `host_ab12cd34ef56`
- SASL usernames: `user_ab12cd34ef56` or `email_ab12cd34ef56`
- Message IDs: `msgid_ab12cd34ef56`

The syslog hostname field is also anonymized. Timestamps, service names, process IDs, queue IDs, status text, delays, DSNs, spam scores, and similar analytics fields are preserved.

The goal is to make anonymized logs remain useful for statistical analysis. Counts, delivery outcomes, timing distributions, queue-flow analysis, relay behavior, and spam-score summaries should still work because the tool replaces sensitive values without rewriting the surrounding mail-log syntax.

## Why HMAC

The tool uses HMAC-SHA256 with a secret key instead of plain SHA256.

Plain hashes are vulnerable to guessing attacks. For example, an attacker could hash common email addresses or IP addresses and compare them against the anonymized output. HMAC requires the secret key, so the same input still produces the same stable token, but outsiders cannot easily build a matching dictionary without the key.

Keep the key file safe. Anyone with the original logs and the key can reproduce the anonymized tokens.

## Usage

```bash
python3 logveil.py INPUT OUTPUT --key-file KEYFILE
```

Examples:

```bash
python3 logveil.py /var/log/mail.log anonymized/mail.log --key-file anonymized.key
python3 logveil.py mail.log.1.gz anonymized/mail.log.1 --key-file anonymized.key
python3 logveil.py mail.log anonymized/mail.log --key-file anonymized.key --stats
python3 logveil.py mail.log unused.out --key-file anonymized.key --dry-run
```

If the key file does not exist, the tool creates a random 32-byte key and saves it with mode `600` where the platform supports it.

The tool refuses to run if `OUTPUT` is the same path as `INPUT`. Parent directories for `OUTPUT` are created automatically.

## Options

`--preserve-email-domain` keeps email domains while anonymizing the original full email into the local part:

```text
john@example.com -> user_ab12cd34ef56@example.com
```

`--preserve-ip-prefix` is reserved for future subnet-preserving IP anonymization. Passing it currently exits with a clear “not supported yet” error.

`--dry-run` writes anonymized output to stdout instead of writing `OUTPUT`.

`--stats` prints replacement counts to stderr.

`--verbose` prints progress information to stderr. It never prints original sensitive values.

## Examples

Before:

```text
May 17 10:12:01 s3 postfix/smtpd[1234]: ABC123: client=mail.example.com[1.2.3.4], sasl_method=PLAIN, sasl_username=john@example.com
```

After:

```text
May 17 10:12:01 host_7f9a3c2d1e00 postfix/smtpd[1234]: ABC123: client=host_ab12cd34ef56[ip_d34db33f1200], sasl_method=PLAIN, sasl_username=email_8b91df559a0c
```

Before:

```text
May 17 10:12:06 s3 postfix/smtp[3333]: ABC123: to=<alice@example.net>, relay=mx.example.net[5.6.7.8]:25, delay=1.2, delays=0.1/0.1/0.5/0.5, dsn=2.0.0, status=sent
```

After:

```text
May 17 10:12:06 host_7f9a3c2d1e00 postfix/smtp[3333]: ABC123: to=<email_9fb3190c22aa>, relay=host_13b1ad661afe[ip_31119869b643]:25, delay=1.2, delays=0.1/0.1/0.5/0.5, dsn=2.0.0, status=sent
```

Actual token values depend on your key file.

## Statistical Analysis

Statistical analysis is a primary use case for `logveil`.

Because timestamps, queue IDs, service names, process IDs, delays, status values, DSNs, spam scores, and relay field structure are preserved, anonymized logs should remain useful with tools such as `pflogsumm` and other mail log statistics workflows.

Stable HMAC tokens also preserve grouping. The same email address, IP address, hostname, username, or message ID becomes the same token every time when the same key is used, so frequency counts and correlation across lines remain possible without exposing the original value.

Run the anonymizer first, then run your statistics tool on the anonymized output:

```bash
python3 logveil.py mail.log anonymized/mail.log --key-file anonymized.key
pflogsumm anonymized/mail.log
```

## Security Notes

This is pseudonymization, not full GDPR deletion. Stable tokens intentionally preserve relationships across lines, which is useful for analytics but still means the anonymized data may remain personal data in some contexts.

Protect the key file, control access to both original and anonymized logs, and review output before sharing it externally.

## Development

Install test dependencies:

```bash
python3 -m pip install -e ".[test]"
```

Run tests:

```bash
python3 -m pytest
```
