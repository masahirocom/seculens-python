"""Bilingual interactive option collection; normal CLI executes the result."""

from __future__ import annotations

from pathlib import Path

MESSAGES = {
    "en": {
        "welcome": "SecuLens setup wizard",
        "hint": "Press Enter to accept defaults. Ctrl+C cancels.",
        "task": "Task: 1 = scan an existing SBOM, 2 = generate an SBOM",
        "sbom": "SBOM JSON file",
        "dbmode": "Vulnerability database: 1 = local snapshot, 2 = fetch from OSV",
        "db": "Local OSV database JSON file",
        "network": "OSV receives package names and ecosystems. Source code is not sent.",
        "policy": "License policy JSON file (optional)",
        "source": "Source directory for AST review (optional)",
        "customer": "Customer name",
        "target": "System / project name",
        "issuer": "Report preparer (optional)",
        "style": "Report style: 1 = customer, 2 = standard",
        "output": "Report output directory",
        "fail": "Return exit code 1 for actionable findings? (y/n)",
        "project": "Project directory",
        "format": "SBOM format: 1 = CycloneDX, 2 = SPDX",
        "sbomoutput": "SBOM output file",
        "syft": "Syft executable (must be installed)",
        "summary": "Review your settings",
        "start": "Start?",
        "cancel": "Cancelled. No assessment or generation was started.",
        "invalid": "Enter one of the listed choices.",
        "required": "A value is required.",
        "file": "Enter an existing file path.",
        "directory": "Enter an existing directory path.",
        "yes": "yes",
        "no": "no",
        "running": "Starting...",
    },
    "ja": {
        "welcome": "SecuLens 設定ウィザード",
        "hint": "Enterで既定値を選択できます。Ctrl+Cで中止します。",
        "task": "操作: 1 = 既存SBOMを検査、2 = SBOMを生成",
        "sbom": "SBOMのJSONファイル",
        "dbmode": "脆弱性DB: 1 = 保存済みDB、2 = OSVから取得",
        "db": "保存済みOSV DBのJSONファイル",
        "network": "OSVへパッケージ名とエコシステムを送信します。ソースコードは送信しません。",
        "policy": "ライセンスポリシーJSONファイル（任意）",
        "source": "AST解析するソースフォルダー（任意）",
        "customer": "顧客名",
        "target": "対象システム・プロジェクト名",
        "issuer": "報告書の作成者（任意）",
        "style": "レポート形式: 1 = 顧客提出用、2 = 標準",
        "output": "レポートの出力フォルダー",
        "fail": "対応対象の指摘があれば終了コード1にしますか？ (y/n)",
        "project": "プロジェクトフォルダー",
        "format": "SBOM形式: 1 = CycloneDX、2 = SPDX",
        "sbomoutput": "SBOMの出力ファイル",
        "syft": "Syftの実行ファイル（事前インストールが必要）",
        "summary": "設定内容の確認",
        "start": "開始しますか？",
        "cancel": "中止しました。検査・生成は開始していません。",
        "invalid": "表示された選択肢を入力してください。",
        "required": "入力が必要です。",
        "file": "存在するファイルのパスを入力してください。",
        "directory": "存在するフォルダーのパスを入力してください。",
        "yes": "はい",
        "no": "いいえ",
        "running": "開始しています…",
    },
}


def wizard(language: str | None = None) -> tuple[list[str] | None, str]:
    lang = language or "en"

    def ask(label: str, fallback: str = "", required: bool = False) -> str:
        while True:
            value = input(f"{label}{f' [{fallback}]' if fallback else ''}: ").strip() or fallback
            if value or not required:
                return value
            print(MESSAGES[lang]["required"])

    def choice(label: str, choices: tuple[str, ...], fallback: str) -> str:
        while True:
            value = ask(label, fallback).lower()
            if value in choices:
                return value
            print(MESSAGES[lang]["invalid"])

    try:
        if language is None:
            lang = choice("Language / 言語 (en / ja)", ("en", "ja"), "en")
        m = MESSAGES[lang]
        print(f"\n{m['welcome']}\n{m['hint']}")
        settings: list[tuple[str, str]] = []

        def field(
            key: str, fallback: str = "", required: bool = False, kind: str | None = None
        ) -> str:
            while True:
                value = ask(m[key], fallback, required)
                if kind and len(value) > 1 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                if required and not value:
                    print(m["required"])
                    continue
                if kind and value:
                    try:
                        valid = Path(value).is_file() if kind == "file" else Path(value).is_dir()
                    except (OSError, ValueError):
                        valid = False
                    if not valid:
                        print(m[kind])
                        continue
                if value:
                    settings.append((m[key], value))
                return value

        def select(
            key: str, values: tuple[str, ...], fallback: str, display: dict[str, str] | None = None
        ) -> str:
            value = choice(m[key], values, fallback)
            settings.append((m[key], (display or {}).get(value, value)))
            return value

        task = select("task", ("1", "2"), "1")
        if task == "2":
            project = field("project", required=True, kind="directory")
            fmt = select("format", ("1", "2"), "1", {"1": "CycloneDX", "2": "SPDX"})
            syft = field("syft", "syft", True)
            output = field("sbomoutput", "sbom.json", True)
            args = [
                "sbom",
                project,
                "--format",
                "cyclonedx" if fmt == "1" else "spdx",
                "--syft",
                syft,
                "--output",
                output,
            ]
        else:
            sbom = field("sbom", required=True, kind="file")
            args = ["scan", sbom]
            mode = select("dbmode", ("1", "2"), "1")
            if mode == "1":
                args += ["--db", field("db", required=True, kind="file")]
            else:
                print(m["network"])
                args += ["--fetch-osv"]
            for key in ("policy", "source"):
                value = field(key, kind="directory" if key == "source" else "file")
                if value:
                    args += [f"--{key}", value]
            args += ["--customer", field("customer", "顧客" if lang == "ja" else "Customer", True)]
            args += ["--target", field("target", Path(sbom).name, True)]
            issuer = field("issuer")
            if issuer:
                args += ["--issuer", issuer]
            style = select("style", ("1", "2"), "1")
            args += ["--report-style", "customer" if style == "1" else "standard", "--lang", lang]
            args += ["--output", field("output", "reports", True)]
            fail = select("fail", ("y", "n"), "n", {"y": m["yes"], "n": m["no"]})
            if fail == "y":
                args += ["--fail-on-findings"]
        print(f"\n{m['summary']} ({lang})")
        for label, value in settings:
            print(f"  {label}: {value}")
        if choice(f"{m['start']} (y/n)", ("y", "n"), "y") == "n":
            print(m["cancel"])
            return None, lang
        print(m["running"])
        return args, lang
    except EOFError:
        print(f"\n{MESSAGES[lang]['cancel']}")
        return None, lang
