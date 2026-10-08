"""Python syntax-tree review candidates and function complexity measurements."""

from __future__ import annotations

import ast
import tokenize
from pathlib import Path
from typing import Any

_IGNORED = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
}
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_BRANCHES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.IfExp,
    ast.ExceptHandler,
    ast.comprehension,
)


def _qualified(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _complexity(function: ast.AST) -> tuple[int, int]:
    complexity, deepest = 1, 0

    def count(node: ast.AST, depth: int) -> None:
        nonlocal complexity, deepest
        if node is not function and isinstance(node, _FUNCTIONS):
            return
        branch = isinstance(node, _BRANCHES)
        if branch:
            complexity += 1
        if isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        if isinstance(node, ast.comprehension):
            complexity += len(node.ifs)
        if isinstance(node, ast.match_case) and not (
            isinstance(node.pattern, ast.MatchAs)
            and node.pattern.pattern is None
            and node.pattern.name is None
        ):
            complexity += 1
            branch = True
        depth += int(branch)
        deepest = max(deepest, depth)
        for child in ast.iter_child_nodes(node):
            count(child, depth)

    # Function defaults and decorators are outside its executed body.
    if isinstance(function, ast.Lambda):
        count(function.body, 0)
    else:
        for node in function.body:
            count(node, 0)
    return complexity, deepest


def analyze(directory: str | Path) -> list[dict[str, Any]]:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError("Source must be a directory")
    files: list[Path] = []

    def collect(folder: Path) -> None:
        for path in sorted(folder.iterdir()):
            if path.is_symlink() or path.name in _IGNORED:
                continue
            if path.is_dir():
                collect(path)
            elif path.is_file() and path.suffix == ".py":
                files.append(path)

    collect(root)
    findings: list[dict[str, Any]] = []
    for file in files:
        relative = file.relative_to(root).as_posix()
        try:
            with tokenize.open(file) as stream:
                source = stream.read()
            tree = ast.parse(source, filename=relative)
        except (SyntaxError, UnicodeError, LookupError) as error:
            findings.append(
                {
                    "category": "coverage",
                    "ruleId": "PY-PARSE-ERROR",
                    "subject": relative,
                    "status": "unassessed",
                    "summary": "Source could not be completely parsed",
                    "evidence": str(error),
                    "recommendation": "Resolve the syntax error and repeat the analysis.",
                    "file": relative,
                }
            )
            continue
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".")[0]] = (
                        item.name if item.asname else item.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                for item in node.names:
                    if item.name != "*":
                        aliases[item.asname or item.name] = f"{node.module}.{item.name}"

        def add(
            node: ast.AST,
            category: str,
            rule: str,
            summary: str,
            evidence: str | None = None,
            *,
            relative: str = relative,
            source: str = source,
        ) -> None:
            findings.append(
                {
                    "category": category,
                    "ruleId": rule,
                    "subject": relative,
                    "status": "review",
                    "summary": summary,
                    "evidence": evidence
                    if evidence is not None
                    else (ast.get_source_segment(source, node) or "")[:300],
                    "recommendation": "Review the call and trace untrusted input before deciding whether it is exploitable."
                    if category == "security"
                    else "Consider simplifying the function and adding focused tests.",
                    "file": relative,
                    "line": node.lineno,
                }
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _qualified(node.func, aliases)
                if name in ("eval", "exec", "builtins.eval", "builtins.exec"):
                    add(
                        node,
                        "security",
                        "PY-DYNAMIC-EXECUTION",
                        "Dynamic code execution requires review",
                    )
                elif name in ("os.system", "os.popen"):
                    add(node, "security", "PY-OS-SHELL", "Shell command execution requires review")
                elif name in {
                    f"subprocess.{method}"
                    for method in ("run", "Popen", "call", "check_call", "check_output")
                } and any(
                    k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                    for k in node.keywords
                ):
                    add(
                        node,
                        "security",
                        "PY-SUBPROCESS-SHELL",
                        "subprocess shell=True requires review",
                    )
                elif name in ("pickle.load", "pickle.loads"):
                    add(
                        node,
                        "security",
                        "PY-PICKLE",
                        "Pickle deserialization requires trusted data",
                    )
                elif name == "yaml.load":
                    loaders = [
                        _qualified(k.value, aliases) for k in node.keywords if k.arg == "Loader"
                    ]
                    if len(node.args) > 1:
                        loaders.append(_qualified(node.args[1], aliases))
                    if not any(
                        loader in ("yaml.SafeLoader", "yaml.CSafeLoader") for loader in loaders
                    ):
                        add(
                            node,
                            "security",
                            "PY-YAML-LOAD",
                            "YAML load without an explicit safe loader requires review",
                        )
            if isinstance(node, _FUNCTIONS):
                complexity, depth = _complexity(node)
                if complexity > 10 or depth > 4:
                    add(
                        node,
                        "quality",
                        "PY-COMPLEXITY",
                        "Function complexity exceeds the baseline",
                        f"cyclomatic={complexity}; nesting={depth}; thresholds=10,4",
                    )
    return sorted(findings, key=lambda f: (f["file"], f.get("line", 0), f["ruleId"]))
