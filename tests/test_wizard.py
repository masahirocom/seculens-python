from pathlib import Path

import pytest
from docx import Document

from seculens.cli import main
from seculens.wizard import wizard

ROOT = Path(__file__).resolve().parents[1]


def answers(monkeypatch, values):
    iterator = iter(values)

    def respond(prompt):
        print(prompt, end="")
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr("builtins.input", respond)


@pytest.mark.parametrize("lang", ["en", "ja"])
def test_bare_command_and_localized_customer_report(monkeypatch, tmp_path, capsys, lang):
    values = [
        "" if lang == "en" else "ja",
        "",
        str(ROOT / "examples/cyclonedx.json"),
        "",
        str(ROOT / "examples/database.json"),
        "",
        "",
        "Example Customer",
        "Example System",
        "Example Team",
        "",
        str(tmp_path),
        "",
        "",
    ]
    answers(monkeypatch, values)
    assert main([]) == 0
    doc = Document(tmp_path / "report.docx")
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "Example Customer" in text and "Example Team" in text
    assert ("評価" if lang == "ja" else "Assessment") in text
    output = capsys.readouterr().out
    assert ("設定内容の確認" if lang == "ja" else "Review your settings (en)") in output
    assert ("レポート:" if lang == "ja" else "Reports:") in output


def test_invalid_choices_paths_retry_and_cancel(monkeypatch, tmp_path, capsys):
    output = tmp_path / "must-not-exist"
    answers(
        monkeypatch,
        [
            "fr",
            "",
            "9",
            "",
            "missing.json",
            str(ROOT / "examples/cyclonedx.json"),
            "",
            str(ROOT / "examples/database.json"),
            "",
            "",
            "",
            "",
            "",
            "",
            str(output),
            "",
            "n",
        ],
    )
    assert main([]) == 0
    assert not output.exists()
    text = capsys.readouterr().out
    assert "Enter one of the listed choices" in text
    assert "Enter an existing file path" in text
    assert "Cancelled" in text


def test_fetch_explicit_and_optional_fields(monkeypatch, capsys):
    answers(
        monkeypatch,
        [
            "",
            str(ROOT / "examples/cyclonedx.json"),
            "2",
            str(ROOT / "examples/policy.json"),
            str(ROOT / "examples"),
            "Client",
            "System",
            "Team",
            "2",
            "out",
            "y",
            "y",
        ],
    )
    args, lang = wizard("ja")
    assert lang == "ja"
    assert "--fetch-osv" in args and "--db" not in args
    assert "--policy" in args and "--source" in args and "--fail-on-findings" in args
    assert args[args.index("--report-style") + 1] == "standard"
    assert "OSVへパッケージ名" in capsys.readouterr().out


def test_generation_options(monkeypatch):
    answers(monkeypatch, ["2", str(ROOT), "2", "custom-syft", "out.json", "y"])
    args, lang = wizard("en")
    assert lang == "en"
    assert args == [
        "sbom",
        str(ROOT),
        "--format",
        "spdx",
        "--syft",
        "custom-syft",
        "--output",
        "out.json",
    ]


def test_eof_and_interrupt_cancel(monkeypatch, tmp_path):
    answers(monkeypatch, [])
    assert main([]) == 0

    def interrupt(prompt):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupt)
    assert main([]) == 130


def test_explicit_wizard_language(monkeypatch):
    answers(monkeypatch, [])
    assert main(["wizard", "--lang", "ja"]) == 0
