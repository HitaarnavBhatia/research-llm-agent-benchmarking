#!/usr/bin/env python3

"""
verify_benchmark.py

Verify whether TaintP2X detected a specific known CVE.

INPUTS
------
1. test_source.json
   Contains multiple repository/version/commit entries.

2. research_benchmark_sheet.csv
   Ground-truth benchmark containing:
       CVE_ID
       Repository
       Version
       Vulnerability Class1
       Vulnerability Class2
       Vulnerability Description
       Affected_Component
       Sink location
       ObservedFailure/ Vulnerable behaviour
       etc.

3. taint-output.json
   TaintP2X output.
   ONLY records with:
       "kind": "issue"
   are considered.

PRIMARY VERIFICATION
--------------------
Find the benchmark row for the supplied CVE.

Then:

    benchmark vulnerable path
              VS
    TaintP2X kind=issue findings

The verifier checks:

    - repository
    - version
    - vulnerable function/component
    - sink
    - vulnerability type

A generic unrelated issue is NOT counted as detection.

SECONDARY VERIFICATION
----------------------
The exact CVE is queried from:

    - NVD
    - OSV

This is supporting evidence only.

USAGE
-----

From inside your TaintP2X directory:

python3 "../verify_benchmark.py" \
  --csv "../research_benchmark_sheet.csv" \
  --pysa "pysa_result/pysa-runs_langchain-ai__langchain_0.0.131_c7b083a/taint-output.json" \
  --cve "CVE-2023-29374" \
  --json-out "../verifier_outputs/langchain_0.0.131_CVE-2023-29374.json"
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Tuple


# ============================================================
# CONFIG
# ============================================================

USER_AGENT = "TaintP2X-Benchmark-Verifier/6.0"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/vulns/{}"


# TaintP2X / Pysa vulnerability codes
CODE_TO_TYPE = {
    "5001": "code execution",
    "5005": "command injection",
    "5007": "email injection",
    "5008": "sql injection",
    "5010": "file operation",
    "5015": "ssrf",
}


# Known sinks
SINK_ALIASES = {
    "exec": {
        "exec",
        "builtins.exec",
    },
    "eval": {
        "eval",
        "builtins.eval",
    },
    "subprocess.run": {
        "subprocess.run",
    },
    "subprocess.call": {
        "subprocess.call",
    },
    "subprocess.popen": {
        "subprocess.popen",
        "subprocess.popen.__init__",
    },
    "os.system": {
        "os.system",
    },
    "requests.get": {
        "requests.get",
        "requests.api.get",
    },
    "open": {
        "open",
        "builtins.open",
        "io.open",
        "pathlib.Path.open",
    },
    "sql": {
        "cursor.execute",
        "run_sql",
        "sqlite_utils.database.query",
        "execute",
    },
    "sendmail": {
        "smtplib.sendmail",
        "sendmail",
    },
}


# Generic terms that should not count as strong component evidence
STOPWORDS = {
    "self",
    "call",
    "init",
    "callable",
    "function",
    "method",
    "source",
    "sink",
    "issue",
    "data",
    "result",
    "output",
    "input",
    "run",
    "execute",
    "execution",
    "request",
    "response",
    "llm",
    "python",
    "code",
    "query",
    "tool",
    "tools",
    "core",
    "utils",
    "util",
    "main",
    "test",
    "tests",
    "app",
    "application",
    "server",
    "project",
    "module",
    "package",
    "prompt",
    "user",
    "content",
    "text",
    "string",
    "value",
    "args",
    "kwargs",
    "task",
    "tasks",
    "handler",
    "process",
    "get",
    "set",
    "create",
    "make",
    "generate",
    "predict",
    "apply",
    "parse",
    "true",
    "false",
    "none",
    "unknown",
    "src",
    "lib",
    "base",
    "vanna",
    "langchain",
}


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class Finding:
    line_number: int
    callable: str
    callable_line: Any
    code: str
    source_text: str
    sink_text: str
    forward_text: str
    backward_text: str
    filename: str
    message: str
    raw: Dict[str, Any]


@dataclass
class Candidate:
    finding_line: int
    callable: str
    filename: str
    code: str
    sink_matches: List[str]
    component_matches: List[str]
    type_match: bool
    score: int
    verdict: str
    evidence: List[Dict[str, str]]
    reasons: List[str]


# ============================================================
# HELPERS
# ============================================================

def clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def norm(value: Any) -> str:
    s = clean(value).lower()
    s = s.replace("\\", "/")
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def normalize_repo(value: Any) -> str:
    s = norm(value)
    s = s.rstrip("/")
    s = re.sub(
        r"^https?://github\.com/",
        "",
        s,
    )
    return s.removesuffix(".git")


def normalize_version(value: Any) -> str:
    return norm(value).lstrip("v")


def repo_matches(a: str, b: str) -> bool:
    a = normalize_repo(a)
    b = normalize_repo(b)

    if not a or not b:
        return False

    if a == b:
        return True

    return a.split("/")[-1] == b.split("/")[-1]


def version_matches(a: str, b: str) -> bool:
    return normalize_version(a) == normalize_version(b)


def flatten(value: Any) -> str:
    """
    Safely flatten dicts/lists from Pysa traces.
    """

    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, (int, float, bool)):
        return str(value)

    if isinstance(value, list):
        return " ".join(
            flatten(item)
            for item in value
        )

    if isinstance(value, dict):
        return " ".join(
            f"{key} {flatten(val)}"
            for key, val in value.items()
        )

    return str(value)


# ============================================================
# ONLINE REQUEST
# ============================================================

def request_json(
    url: str,
    retries: int = 2,
    timeout: int = 25,
) -> Dict[str, Any]:

    last_error = None

    for attempt in range(retries + 1):

        try:

            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json",
                },
            )

            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:

                raw = response.read().decode(
                    "utf-8",
                    errors="replace",
                )

                return json.loads(raw)

        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            TimeoutError,
            json.JSONDecodeError,
        ) as exc:

            last_error = str(exc)

            if attempt < retries:
                time.sleep(2 ** attempt)

    raise RuntimeError(
        last_error or "Unknown HTTP error"
    )


# ============================================================
# TEST SOURCE
# ============================================================

def load_test_source(
    path: Path,
) -> List[Dict[str, Any]]:
    """
    Load ALL entries from test_source.json.
    """

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:

        data = json.load(file)

    if not isinstance(data, list) or not data:
        raise ValueError(
            "test_source.json must contain "
            "a non-empty JSON array."
        )

    entries = []

    for index, item in enumerate(data):

        if not isinstance(item, dict):
            continue

        repo = clean(
            item.get("nameWithOwner")
            or item.get("repository")
        )

        version = clean(
            item.get("version")
        )

        commit = clean(
            item.get("commit_hash")
        )

        url = clean(
            item.get("url")
        )

        if not repo or not version or not commit:
            continue

        entries.append(
            {
                "index": index,
                "repository": repo,
                "version": version,
                "commit_hash": commit,
                "url": url,
                "raw": item,
            }
        )

    if not entries:
        raise ValueError(
            "No valid entries were found in test_source.json."
        )

    return entries


def select_test_source(
    entries: List[Dict[str, Any]],
    repository: str,
    version: str,
) -> Dict[str, Any]:

    matches = [
        entry
        for entry in entries
        if repo_matches(
            entry["repository"],
            repository,
        )
        and version_matches(
            entry["version"],
            version,
        )
    ]

    if not matches:
        raise ValueError(
            "No matching test_source.json entry for "
            f"{repository} {version}"
        )

    if len(matches) > 1:

        indexes = ", ".join(
            str(entry["index"])
            for entry in matches
        )

        raise ValueError(
            "Multiple test_source.json entries match "
            f"{repository} {version}. "
            f"Indexes: {indexes}"
        )

    return matches[0]


# ============================================================
# BENCHMARK CSV
# ============================================================

def load_csv(
    path: Path,
) -> List[Dict[str, str]]:

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:

        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError(
                "Benchmark CSV has no header."
            )

        rows = []

        for raw_row in reader:

            row = {}

            for key, value in raw_row.items():

                if key is None:
                    continue

                key = key.strip()

                if not key:
                    continue

                if key.lower().startswith(
                    "unnamed:"
                ):
                    continue

                row[key] = clean(value)

            rows.append(row)

    required = {
        "CVE_ID",
        "Repository",
        "Version",
        "Sink location",
    }

    actual = set(
        rows[0].keys()
        if rows
        else []
    )

    missing = required - actual

    if missing:
        raise ValueError(
            "Benchmark CSV is missing columns: "
            + ", ".join(sorted(missing))
        )

    return rows


def select_benchmark(
    rows: List[Dict[str, str]],
    cve: str,
) -> Dict[str, str]:

    matches = [
        row
        for row in rows
        if clean(
            row.get("CVE_ID", "")
        ).upper()
        == cve.upper()
    ]

    if not matches:
        raise ValueError(
            f"No benchmark row found for {cve}"
        )

    if len(matches) > 1:
        details = [
            (
                row.get("Repository", ""),
                row.get("Version", ""),
            )
            for row in matches
        ]

        raise ValueError(
            f"Multiple benchmark rows found for "
            f"{cve}: {details}"
        )

    return matches[0]


# ============================================================
# TAINT OUTPUT
# ============================================================

def load_findings(
    path: Path,
) -> List[Finding]:
    """
    Read taint-output.json.

    Only kind == issue is retained.
    """

    findings = []

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:

        for line_number, line in enumerate(
            file,
            1,
        ):

            line = line.strip()

            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if obj.get("kind") != "issue":
                continue

            data = obj.get("data") or {}

            if not isinstance(data, dict):
                continue

            # TaintP2X's traces are commonly a LIST:
            #
            # [
            #   {"name": "forward", ...},
            #   {"name": "backward", ...}
            # ]
            #
            # Handle both list and dict forms.
            traces = data.get("traces") or []

            forward = {}
            backward = {}

            if isinstance(traces, list):

                for trace in traces:

                    if not isinstance(trace, dict):
                        continue

                    name = norm(
                        trace.get("name")
                    )

                    if name == "forward":
                        forward = trace

                    elif name == "backward":
                        backward = trace

            elif isinstance(traces, dict):

                forward = (
                    traces.get("forward")
                    or {}
                )

                backward = (
                    traces.get("backward")
                    or {}
                )

            finding = Finding(
                line_number=line_number,

                callable=clean(
                    data.get("callable")
                ),

                callable_line=data.get(
                    "callable_line"
                ),

                code=clean(
                    data.get("code")
                ),

                source_text=flatten(
                    forward.get("roots")
                    if isinstance(
                        forward,
                        dict,
                    )
                    else forward
                ),

                sink_text=flatten(
                    backward.get("roots")
                    if isinstance(
                        backward,
                        dict,
                    )
                    else backward
                ),

                forward_text=flatten(
                    forward
                ),

                backward_text=flatten(
                    backward
                ),

                filename=clean(
                    data.get("filename")
                ),

                message=clean(
                    data.get("message")
                ),

                raw=obj,
            )

            findings.append(
                finding
            )

    return findings


# ============================================================
# BENCHMARK PROFILE
# ============================================================

def extract_tokens(
    text: str,
) -> List[str]:

    pieces = re.findall(
        r"[A-Za-z_][A-Za-z0-9_]*"
        r"(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
        clean(text),
    )

    result = []
    seen = set()

    for item in pieces:

        for part in item.split("."):

            p = part.strip("_")

            if len(p) < 4:
                continue

            if p.lower() in STOPWORDS:
                continue

            if p.lower() in seen:
                continue

            seen.add(p.lower())
            result.append(p)

    return result


def extract_function_calls(
    text: str,
) -> List[str]:

    matches = re.findall(
        r"(?:[A-Za-z_][\w]*\.)*"
        r"[A-Za-z_][\w]*"
        r"\s*\(\s*\)",
        clean(text),
    )

    return [
        re.sub(
            r"\s*\(.*",
            "",
            item,
        )
        for item in matches
    ]


def benchmark_profile(
    benchmark: Dict[str, str],
) -> Dict[str, Any]:

    affected = benchmark.get(
        "Affected_Component",
        "",
    )

    sink_location = benchmark.get(
        "Sink location",
        "",
    )

    description = benchmark.get(
        "Vulnerability Description",
        "",
    )

    behaviour = benchmark.get(
        "ObservedFailure/ Vulnerable behaviour",
        "",
    )

    path_text = (
        affected
        + " "
        + sink_location
    )

    return {
        "affected_component": affected,
        "sink_location": sink_location,
        "description": description,
        "behaviour": behaviour,

        "functions": list(
            dict.fromkeys(
                extract_function_calls(
                    path_text
                )
            )
        ),

        "tokens": list(
            dict.fromkeys(
                extract_tokens(
                    path_text
                )
            )
        ),

        "combined": norm(
            path_text
            + " "
            + description
            + " "
            + behaviour
        ),
    }


# ============================================================
# FINDING TEXT
# ============================================================

def finding_text(
    finding: Finding,
) -> str:

    return norm(
        " ".join(
            [
                finding.callable,
                finding.message,
                finding.source_text,
                finding.sink_text,
                finding.forward_text,
                finding.backward_text,
                finding.filename,
                CODE_TO_TYPE.get(
                    finding.code,
                    "",
                ),
            ]
        )
    )


# ============================================================
# SINK MATCH
# ============================================================

def get_expected_sinks(
    benchmark: Dict[str, str],
) -> List[str]:

    text = norm(
        " ".join(
            [
                benchmark.get(
                    "Sink location",
                    "",
                ),
                benchmark.get(
                    "Affected_Component",
                    "",
                ),
                benchmark.get(
                    "Vulnerability Description",
                    "",
                ),
                benchmark.get(
                    "ObservedFailure/ Vulnerable behaviour",
                    "",
                ),
            ]
        )
    )

    expected = []

    for canonical, aliases in SINK_ALIASES.items():

        if any(
            alias in text
            for alias in aliases
        ):

            expected.append(
                canonical
            )

    return expected


def match_sinks(
    finding: Finding,
    expected_sinks: List[str],
) -> List[str]:

    text = finding_text(
        finding
    )

    result = []

    for sink in expected_sinks:

        aliases = SINK_ALIASES.get(
            sink,
            {sink},
        )

        if any(
            alias in text
            for alias in aliases
        ):

            result.append(
                sink
            )

    return result


# ============================================================
# VULNERABILITY TYPE
# ============================================================

def match_type(
    finding: Finding,
    benchmark: Dict[str, str],
) -> bool:

    expected = norm(
        " ".join(
            [
                benchmark.get(
                    "Vulnerability Class1",
                    "",
                ),
                benchmark.get(
                    "Vulnerability Class2",
                    "",
                ),
                benchmark.get(
                    "Vulnerability Description",
                    "",
                ),
            ]
        )
    )

    actual = CODE_TO_TYPE.get(
        finding.code,
        "",
    )

    if not actual:
        return False

    mappings = {

        "code execution": [
            "code injection",
            "arbitrary code",
            "remote code",
            "rce",
            "ace",
            "code execution",
        ],

        "command injection": [
            "command injection",
            "remote command",
            "rce",
        ],

        "sql injection": [
            "sql injection",
            "sqli",
            "sql",
        ],

        "file operation": [
            "file read",
            "file write",
            "file access",
            "file operation",
            "path traversal",
        ],

        "ssrf": [
            "ssrf",
            "server-side request forgery",
            "request forgery",
        ],

        "email injection": [
            "email injection",
            "email",
        ],
    }

    return any(
        term in expected
        for term in mappings.get(
            actual,
            [actual],
        )
    )


# ============================================================
# COMPONENT/FUNCTION MATCH
# ============================================================

def value_variants(
    benchmark_value: str,
) -> List[str]:
    """
    Generate conservative variants.

    Example:

        langchain.chains.llm_math.base.LLMMathChain._call
        LLMMathChain._call
        _call

    Vanna:
        vanna.ask
        VannaBase.ask
    """

    value = clean(
        benchmark_value
    )

    if not value:
        return []

    variants = {
        value
    }

    lower = norm(value)

    # Public API ↔ implementation correspondence
    if lower == "vanna.ask":
        variants.add(
            "VannaBase.ask"
        )

    elif lower == "vannabase.ask":
        variants.add(
            "vanna.ask"
        )

    # Remove module prefixes
    if "." in value:

        pieces = value.split(".")

        if len(pieces) >= 2:

            variants.add(
                ".".join(
                    pieces[-2:]
                )
            )

            variants.add(
                pieces[-1]
            )

    return list(
        variants
    )


def match_components(
    finding: Finding,
    profile: Dict[str, Any],
) -> Tuple[
    List[str],
    List[Dict[str, str]],
]:
    """
    Compare benchmark functions/components against
    the TaintP2X callable + trace text.

    IMPORTANT:
    This does not require exact equality.
    """

    text = finding_text(
        finding
    )

    matches = []
    evidence = []

    benchmark_values = []

    benchmark_values.extend(
        profile["functions"]
    )

    benchmark_values.extend(
        profile["tokens"]
    )

    seen = set()

    for benchmark_value in benchmark_values:

        if (
            norm(
                benchmark_value
            )
            in seen
        ):
            continue

        for variant in value_variants(
            benchmark_value
        ):

            variant_norm = norm(
                variant
            )

            if len(variant_norm) < 4:
                continue

            if variant_norm not in text:
                continue

            seen.add(
                norm(
                    benchmark_value
                )
            )

            matches.append(
                benchmark_value
            )

            if (
                variant_norm
                == norm(
                    benchmark_value
                )
            ):

                match_type = (
                    "exact/normalized"
                )

            else:

                match_type = (
                    "qualified-name/API-implementation"
                )

            evidence.append(
                {
                    "benchmark_value":
                        benchmark_value,

                    "taintp2x_value":
                        variant,

                    "match_type":
                        match_type,
                }
            )

            break

    # Explicit Vanna mapping.
    benchmark_path = norm(
        profile[
            "affected_component"
        ]
        + " "
        + profile[
            "sink_location"
        ]
    )

    if (
        "vanna.ask" in benchmark_path
        and "vannabase.ask" in text
    ):

        already = any(
            norm(
                item[
                    "benchmark_value"
                ]
            )
            == "vanna.ask"
            for item in evidence
        )

        if not already:

            matches.append(
                "vanna.ask()"
            )

            evidence.append(
                {
                    "benchmark_value":
                        "vanna.ask()",

                    "taintp2x_value":
                        finding.callable,

                    "match_type":
                        "public-api/internal-implementation",
                }
            )

    return (
        list(
            dict.fromkeys(
                matches
            )
        ),
        evidence,
    )


# ============================================================
# SCORE ONE FINDING
# ============================================================

def evaluate_finding(
    finding: Finding,
    benchmark: Dict[str, str],
    profile: Dict[str, Any],
) -> Candidate:

    sinks = match_sinks(
        finding,
        get_expected_sinks(
            benchmark
        ),
    )

    components, evidence = (
        match_components(
            finding,
            profile,
        )
    )

    type_ok = match_type(
        finding,
        benchmark,
    )

    score = 0
    reasons = []

    # --------------------------
    # Sink
    # --------------------------

    if sinks:

        score += 5

        reasons.append(
            "sink matches benchmark"
        )

    # --------------------------
    # Component / function
    # --------------------------

    if len(components) >= 2:

        score += 5

        reasons.append(
            "multiple component/function "
            "identifiers match"
        )

    elif len(components) == 1:

        score += 3

        reasons.append(
            "component/function "
            "identifier matches"
        )

    # --------------------------
    # Vulnerability type
    # --------------------------

    if type_ok:

        score += 2

        reasons.append(
            "vulnerability type matches"
        )

    # --------------------------
    # Verdict
    # --------------------------
    #
    # DETECTED
    #     sink + component/function + type
    #
    # POSSIBLE_MATCH
    #     sink + component/function
    #
    # RELATED
    #     only one important dimension
    #
    # NO_MATCH
    #     nothing useful
    #

    if (
        sinks
        and components
        and type_ok
    ):

        verdict = "DETECTED"

    elif (
        sinks
        and components
    ):

        verdict = "POSSIBLE_MATCH"

    elif (
        sinks
        or components
    ):

        verdict = (
            "RELATED_BUT_NOT_CONFIRMED"
        )

    else:

        verdict = "NO_MATCH"

    return Candidate(
        finding_line=finding.line_number,
        callable=finding.callable,
        filename=finding.filename,
        code=finding.code,
        sink_matches=sinks,
        component_matches=components,
        type_match=type_ok,
        score=score,
        verdict=verdict,
        evidence=evidence,
        reasons=reasons,
    )


# ============================================================
# ONLINE CVE VERIFICATION
# ============================================================

def fetch_nvd(
    cve: str,
) -> Dict[str, Any]:

    return request_json(
        NVD_URL
        + "?cveId="
        + urllib.parse.quote(
            cve
        )
    )


def fetch_osv(
    cve: str,
) -> Dict[str, Any]:

    return request_json(
        OSV_URL.format(
            urllib.parse.quote(
                cve
            )
        )
    )


def online_cross_check(
    cve: str,
    benchmark: Dict[str, str],
) -> Dict[str, Any]:

    result = {
        "cve": cve,
        "nvd": None,
        "osv": None,
        "errors": [],
    }

    # -------------------------
    # NVD
    # -------------------------

    try:

        data = fetch_nvd(
            cve
        )

        vulnerabilities = (
            data.get(
                "vulnerabilities"
            )
            or []
        )

        if vulnerabilities:

            cve_data = (
                vulnerabilities[0]
                .get(
                    "cve"
                )
                or {}
            )

            descriptions = (
                cve_data.get(
                    "descriptions"
                )
                or []
            )

            description = next(
                (
                    item.get(
                        "value",
                        "",
                    )
                    for item in descriptions
                    if item.get(
                        "lang"
                    ) == "en"
                ),
                "",
            )

            references = [
                item.get(
                    "url"
                )
                for item in (
                    cve_data.get(
                        "references"
                    )
                    or []
                )
                if item.get("url")
            ]

            result["nvd"] = {
                "found": True,
                "id": cve_data.get(
                    "id",
                    "",
                ),
                "description": description,
                "references": references,
            }

        else:

            result["nvd"] = {
                "found": False
            }

    except Exception as exc:

        result[
            "errors"
        ].append(
            f"NVD: {exc}"
        )

    # -------------------------
    # OSV
    # -------------------------

    try:

        data = fetch_osv(
            cve
        )

        result["osv"] = {
            "found": bool(data),

            "id": data.get(
                "id",
                "",
            ),

            "summary": data.get(
                "summary",
                "",
            ),

            "details": data.get(
                "details",
                "",
            ),

            "aliases": data.get(
                "aliases",
                [],
            ),

            "references": [
                item.get(
                    "url"
                )
                for item in (
                    data.get(
                        "references"
                    )
                    or []
                )
                if item.get("url")
            ],

            "affected": data.get(
                "affected",
                [],
            ),
        }

    except Exception as exc:

        result[
            "errors"
        ].append(
            f"OSV: {exc}"
        )

    # -------------------------
    # Supporting evidence
    # -------------------------

    external_text = norm(
        " ".join(
            [
                (
                    result.get(
                        "nvd"
                    )
                    or {}
                ).get(
                    "description",
                    "",
                ),

                (
                    result.get(
                        "osv"
                    )
                    or {}
                ).get(
                    "summary",
                    "",
                ),

                (
                    result.get(
                        "osv"
                    )
                    or {}
                ).get(
                    "details",
                    "",
                ),
            ]
        )
    )

    profile = benchmark_profile(
        benchmark
    )

    online_identifiers = [
        token
        for token in profile["tokens"]
        if (
            len(token) >= 5
            and token.lower()
            in external_text
        )
    ]

    result[
        "supporting_evidence"
    ] = {

        "repository":
            benchmark.get(
                "Repository",
                "",
            ),

        "version":
            benchmark.get(
                "Version",
                "",
            ),

        "repo_name_mentioned":
            normalize_repo(
                benchmark.get(
                    "Repository",
                    "",
                )
            )
            .split("/")[-1]
            .lower()
            in external_text,

        "version_mentioned":
            normalize_version(
                benchmark.get(
                    "Version",
                    "",
                )
            )
            in external_text,

        "benchmark_identifiers_found":
            online_identifiers[:20],
    }

    return result


# ============================================================
# PRINT ONLY RELEVANT OUTPUT
# ============================================================

def print_match(
    candidate: Candidate,
    finding: Finding,
    benchmark: Dict[str, str],
) -> None:

    print(
        "\nMATCHED FINDING"
    )

    print(
        "-" * 72
    )

    print(
        "Exact taint-output.json line:"
    )

    print(
        f"  {candidate.finding_line}"
    )

    print()

    print(
        "TaintP2X callable:"
    )

    print(
        f"  {finding.callable}"
    )

    print()

    print(
        "TaintP2X file:"
    )

    print(
        f"  {finding.filename}"
    )

    print()

    print(
        "TaintP2X vulnerability code:"
    )

    print(
        f"  {finding.code} "
        f"({CODE_TO_TYPE.get(finding.code, 'unknown')})"
    )

    print()

    print(
        "MATCH EVIDENCE"
    )

    print(
        "-" * 72
    )

    for item in candidate.evidence:

        print(
            "Benchmark:"
        )

        print(
            f"  {item['benchmark_value']}"
        )

        print(
            "TaintP2X:"
        )

        print(
            f"  {item['taintp2x_value']}"
        )

        print(
            "Match type:"
        )

        print(
            f"  {item['match_type']}"
        )

        print()

    print(
        "Sink comparison:"
    )

    print(
        f"  Benchmark: "
        f"{benchmark.get('Sink location', '<blank>')}"
    )

    print(
        f"  TaintP2X: "
        f"{', '.join(candidate.sink_matches) or '<none>'}"
    )

    print()

    print(
        "Vulnerability type:"
    )

    print(
        f"  Benchmark: "
        f"{benchmark.get('Vulnerability Class1', '<blank>')}"
    )

    print(
        f"  TaintP2X: "
        f"{finding.code} / "
        f"{CODE_TO_TYPE.get(finding.code, 'unknown')}"
    )

    print(
        "-" * 72
    )

    print(
        "Cross-check this exact line manually:"
    )

    print(
        f"  taint-output.json line "
        f"{candidate.finding_line}"
    )


def print_possible(
    candidate: Candidate,
    finding: Finding,
) -> None:

    print(
        "\n⚠️ POSSIBLE MATCH"
    )

    print(
        "-" * 72
    )

    print(
        f"taint-output.json line: "
        f"{candidate.finding_line}"
    )

    print(
        f"Callable: "
        f"{finding.callable}"
    )

    print(
        f"Code: "
        f"{candidate.code} "
        f"({CODE_TO_TYPE.get(candidate.code, 'unknown')})"
    )

    print(
        "This needs manual review."
    )

    print(
        "-" * 72
    )


def print_related(
    candidate: Candidate,
    finding: Finding,
) -> None:

    print(
        "\nClosest related finding"
    )

    print(
        "-" * 72
    )

    print(
        f"taint-output.json line: "
        f"{candidate.finding_line}"
    )

    print(
        f"Callable: "
        f"{finding.callable}"
    )

    print(
        f"Code: "
        f"{candidate.code} "
        f"({CODE_TO_TYPE.get(candidate.code, 'unknown')})"
    )

    print(
        "NOT counted as detection."
    )

    print(
        "-" * 72
    )


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Verify TaintP2X against a benchmark CSV."
        )
    )

    parser.add_argument(
        "--csv",
        required=True,
        help="Benchmark CSV",
    )

    parser.add_argument(
        "--pysa",
        required=True,
        help="TaintP2X taint-output.json",
    )

    parser.add_argument(
        "--cve",
        required=True,
        help="Target CVE",
    )

    parser.add_argument(
        "--test-source",
        default="test_source.json",
        help=(
            "Path to test_source.json. "
            "Default: test_source.json"
        ),
    )

    parser.add_argument(
        "--no-online",
        action="store_true",
        help="Skip NVD/OSV verification",
    )

    parser.add_argument(
        "--json-out",
        help="Path for JSON report",
    )

    args = parser.parse_args()

    # ========================================================
    # PATHS
    # ========================================================

    csv_path = (
        Path(args.csv)
        .expanduser()
        .resolve()
    )

    pysa_path = (
        Path(args.pysa)
        .expanduser()
        .resolve()
    )

    test_source_path = (
        Path(args.test_source)
        .expanduser()
        .resolve()
    )

    required_files = [
        (
            csv_path,
            "CSV",
        ),
        (
            pysa_path,
            "TaintP2X output",
        ),
        (
            test_source_path,
            "test_source.json",
        ),
    ]

    for path, label in required_files:

        if not path.exists():

            print(
                f"ERROR: {label} not found:"
                f" {path}",
                file=sys.stderr,
            )

            return 2

    # ========================================================
    # LOAD
    # ========================================================

    try:

        print(
            "[*] Reading benchmark..."
        )

        benchmark_rows = load_csv(
            csv_path
        )

        benchmark = select_benchmark(
            benchmark_rows,
            args.cve,
        )

        benchmark_repo = benchmark.get(
            "Repository",
            "",
        )

        benchmark_version = benchmark.get(
            "Version",
            "",
        )

        print(
            f"    CVE:        {args.cve}"
        )

        print(
            f"    Repository: {benchmark_repo}"
        )

        print(
            f"    Version:    {benchmark_version}"
        )

        print(
            "[*] Reading test_source.json..."
        )

        entries = load_test_source(
            test_source_path
        )

        print(
            f"    Found {len(entries)} "
            "entries"
        )

        test_source = select_test_source(
            entries,
            benchmark_repo,
            benchmark_version,
        )

        print(
            f"    Selected: "
            f"{test_source['repository']} "
            f"{test_source['version']}"
        )

        print(
            f"    Commit: "
            f"{test_source['commit_hash']}"
        )

        print(
            "[*] Reading TaintP2X output..."
        )

        findings = load_findings(
            pysa_path
        )

        print(
            f"    Loaded "
            f"{len(findings)} "
            'kind="issue" finding(s)'
        )

    except Exception as exc:

        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return 2

    # ========================================================
    # IDENTITY
    # ========================================================

    repo_match = repo_matches(
        test_source["repository"],
        benchmark_repo,
    )

    version_match = version_matches(
        test_source["version"],
        benchmark_version,
    )

    # ========================================================
    # EVALUATE
    # ========================================================

    profile = benchmark_profile(
        benchmark
    )

    candidates = [
        evaluate_finding(
            finding,
            benchmark,
            profile,
        )
        for finding in findings
    ]

    # Sort strongest first
    candidates = sorted(
        candidates,
        key=lambda item: item.score,
        reverse=True,
    )

    # ========================================================
    # PRIMARY RESULT
    # ========================================================

    detected = [
        candidate
        for candidate in candidates
        if candidate.verdict
        == "DETECTED"
    ]

    possible = [
        candidate
        for candidate in candidates
        if candidate.verdict
        == "POSSIBLE_MATCH"
    ]

    related = [
        candidate
        for candidate in candidates
        if candidate.verdict
        == "RELATED_BUT_NOT_CONFIRMED"
    ]

    if (
        repo_match
        and version_match
        and detected
    ):

        primary_result = "DETECTED"

    elif (
        repo_match
        and version_match
        and possible
    ):

        primary_result = "POSSIBLE_MATCH"

    else:

        primary_result = "NOT_DETECTED"

    # ========================================================
    # SECONDARY ONLINE
    # ========================================================

    online = None

    if not args.no_online:

        print(
            "[*] Running secondary online "
            f"cross-check for {args.cve}..."
        )

        online = online_cross_check(
            args.cve,
            benchmark,
        )

    # ========================================================
    # CONCISE OUTPUT
    # ========================================================

    print()
    print("=" * 72)
    print(
        "TAINTP2X BENCHMARK VERIFICATION"
    )
    print("=" * 72)

    print(
        f"CVE:          {args.cve}"
    )

    print(
        f"Repository:   {test_source['repository']}"
    )

    print(
        f"Version:      {test_source['version']}"
    )

    print(
        f"Commit:       {test_source['commit_hash']}"
    )

    print(
        f"Repository:   "
        f"{'MATCH ✅' if repo_match else 'MISMATCH ❌'}"
    )

    print(
        f"Version:      "
        f"{'MATCH ✅' if version_match else 'MISMATCH ❌'}"
    )

    print(
        "-" * 72
    )

    # --------------------------------------------------------
    # DETECTED
    # --------------------------------------------------------

    if detected:

        # Only show the strongest detection.
        best = detected[0]

        finding = next(
            item
            for item in findings
            if item.line_number
            == best.finding_line
        )

        print(
            "RESULT: ✅ DETECTED"
        )

        print_match(
            best,
            finding,
            benchmark,
        )

    # --------------------------------------------------------
    # POSSIBLE
    # --------------------------------------------------------

    elif possible:

        best = possible[0]

        finding = next(
            item
            for item in findings
            if item.line_number
            == best.finding_line
        )

        print_possible(
            best,
            finding,
        )

    # --------------------------------------------------------
    # NOT DETECTED
    # --------------------------------------------------------

    else:

        print(
            "RESULT: ❌ NOT DETECTED"
        )

        print()

        print(
            "No kind=issue finding matched "
            "the benchmark strongly enough."
        )

        if related:

            closest = related[0]

            finding = next(
                item
                for item in findings
                if item.line_number
                == closest.finding_line
            )

            print_related(
                closest,
                finding,
            )

    # ========================================================
    # ONLINE OUTPUT
    # ========================================================

    if online is not None:

        print()
        print(
            "SECONDARY ONLINE CROSS-CHECK"
        )

        print(
            "-" * 72
        )

        nvd_found = bool(
            (
                online.get(
                    "nvd"
                )
                or {}
            ).get(
                "found"
            )
        )

        osv_found = bool(
            (
                online.get(
                    "osv"
                )
                or {}
            ).get(
                "found"
            )
        )

        print(
             "NVD: "
            + ("FOUND ✅" if nvd_found else "NOT FOUND")
        )

        print(
            "OSV: "
            + ("FOUND ✅" if osv_found else "NOT FOUND")
        )

        description = (
            (
                online.get(
                    "nvd"
                )
                or {}
            ).get(
                "description",
                "",
            )
        )

        if description:

            print()

            print(
                "NVD summary:"
            )

            print(
                re.sub(
                    r"\s+",
                    " ",
                    description,
                )[:700]
            )

        online_errors = (
            online.get(
                "errors"
            )
            or []
        )

        for error in online_errors:

            print(
                f"Online error: {error}"
            )

    # ========================================================
    # FINAL
    # ========================================================

    print()
    print(
        "=" * 72
    )

    print(
        f"FINAL RESULT: "
        f"{primary_result}"
    )

    print(
        "=" * 72
    )

    # ========================================================
    # JSON REPORT
    # ========================================================

    report = {

        "tool":
            "TaintP2X",

        "cve":
            args.cve,

        "primary_result":
            primary_result,

        "repository_identity":
            {
                "benchmark":
                    benchmark_repo,

                "test_source":
                    test_source[
                        "repository"
                    ],

                "match":
                    repo_match,
            },

        "version_identity":
            {
                "benchmark":
                    benchmark_version,

                "test_source":
                    test_source[
                        "version"
                    ],

                "match":
                    version_match,
            },

        "test_source":
            {
                "repository":
                    test_source[
                        "repository"
                    ],

                "version":
                    test_source[
                        "version"
                    ],

                "commit_hash":
                    test_source[
                        "commit_hash"
                    ],

                "url":
                    test_source[
                        "url"
                    ],
            },

        "benchmark":
            benchmark,

        "issue_count":
            len(findings),

        "findings":
            [
                {
                    "taint_output_line":
                        finding.line_number,

                    "callable":
                        finding.callable,

                    "callable_line":
                        finding.callable_line,

                    "code":
                        finding.code,

                    "filename":
                        finding.filename,

                    "message":
                        finding.message,

                    "source":
                        finding.source_text,

                    "sink":
                        finding.sink_text,
                }

                for finding
                in findings
            ],

        "candidates":
            [
                asdict(
                    candidate
                )

                for candidate
                in candidates
            ],

        "online_cross_check":
            online,
    }

    if args.json_out:

        output = (
            Path(
                args.json_out
            )
            .expanduser()
            .resolve()
        )

        output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output.write_text(
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        print(
            f"[*] JSON report written to:"
            f"\n{output}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )