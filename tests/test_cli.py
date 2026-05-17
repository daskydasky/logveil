import gzip
import os

import pytest

from logveil.cli import main


KEY = bytes.fromhex("00" * 32)


def test_cli_writes_output_and_creates_key(tmp_path):
    input_path = tmp_path / "mail.log"
    output_path = tmp_path / "out" / "mail.log"
    key_path = tmp_path / "keys" / "anon.key"
    input_path.write_text("May 17 10:12:05 s3 postfix/qmgr[2222]: from=<john@example.com>\n")

    assert main([str(input_path), str(output_path), "--key-file", str(key_path)]) == 0

    assert output_path.exists()
    assert key_path.exists()
    assert "john@example.com" not in output_path.read_text()
    if os.name != "nt":
        assert (key_path.stat().st_mode & 0o777) == 0o600


def test_cli_reads_gzip_input(tmp_path):
    input_path = tmp_path / "mail.log.1.gz"
    output_path = tmp_path / "anon.log"
    key_path = tmp_path / "anon.key"
    key_path.write_bytes(KEY)
    with gzip.open(input_path, "wt", encoding="utf-8") as gz_file:
        gz_file.write("connect from mail.example.com[1.2.3.4]\n")

    main([str(input_path), str(output_path), "--key-file", str(key_path)])

    output = output_path.read_text()
    assert "mail.example.com" not in output
    assert "1.2.3.4" not in output
    assert "host_" in output
    assert "ip_" in output


def test_cli_refuses_same_input_output(tmp_path):
    input_path = tmp_path / "mail.log"
    key_path = tmp_path / "anon.key"
    input_path.write_text("hello\n")
    key_path.write_bytes(KEY)

    with pytest.raises(SystemExit):
        main([str(input_path), str(input_path), "--key-file", str(key_path)])


def test_cli_dry_run_writes_stdout_not_output(tmp_path, capsys):
    input_path = tmp_path / "mail.log"
    output_path = tmp_path / "unused.log"
    key_path = tmp_path / "anon.key"
    input_path.write_text("from=<john@example.com>\n")
    key_path.write_bytes(KEY)

    main([str(input_path), str(output_path), "--key-file", str(key_path), "--dry-run"])

    captured = capsys.readouterr()
    assert "john@example.com" not in captured.out
    assert "email_" in captured.out
    assert not output_path.exists()


def test_cli_stats_go_to_stderr(tmp_path, capsys):
    input_path = tmp_path / "mail.log"
    output_path = tmp_path / "out.log"
    key_path = tmp_path / "anon.key"
    input_path.write_text("from=<john@example.com>\n")
    key_path.write_bytes(KEY)

    main([str(input_path), str(output_path), "--key-file", str(key_path), "--stats"])

    captured = capsys.readouterr()
    assert "lines=1" in captured.err
    assert "email=1" in captured.err


def test_preserve_ip_prefix_is_clear_error(tmp_path):
    input_path = tmp_path / "mail.log"
    output_path = tmp_path / "out.log"
    key_path = tmp_path / "anon.key"
    input_path.write_text("hello\n")
    key_path.write_bytes(KEY)

    with pytest.raises(SystemExit):
        main(
            [
                str(input_path),
                str(output_path),
                "--key-file",
                str(key_path),
                "--preserve-ip-prefix",
            ]
        )
