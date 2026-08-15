#!/usr/bin/env python3

"""
verifying_benchmark.py

Two-stage TaintP2X verification.

STAGE 1
-------
For every TaintP2X kind="issue" finding:

    TaintP2X finding
          ↓
    Search online
          ↓
    Candidate CVE #1
    Alternative CVE #2
          ↓
    Explain evidence for each

IMPORTANT:
    No online candidate is automatically declared "the CVE".

The online score is an evidence score out of 100.
It is NOT a probability.

STAGE 2
-------
Compare each plausible online CVE candidate against the user's
benchmark row:

    - CVE
    - repository
    - version
    - vulnerability type
    - affected component/function
    - sink
    - vulnerable behaviour

The benchmark comparison is a separate validation layer.

IMPORTANT:
    The existence of a CVE online does NOT prove that TaintP2X
    detected it.

Usage:

python3 "../verifying_benchmark.py" \
  --csv "../research_benchmark_sheet.csv" \
  --pysa "pysa_result/pysa-runs_vanna-ai__vanna_0.3.3_7da87cc/taint-output.json" \
  --cve "CVE-2024-5826" \
  --json-out "../verifier_outputs/vanna_0.3.3_CVE-2024-5826_attribution.json"
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
from typing import Any, Dict, List, Optional


# ============================================================
# CONFIGURATION
# ============================================================

USER_AGENT = "TaintP2X-Attribution-Verifier/9.0"

NVD_API = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

OSV_QUERY_API = (
    "https://api.osv.dev/v1/query"
)

NVD_DELAY = 0.7

# How many online CVEs may be collected.
MAX_ONLINE_CANDIDATES = 30

# How many TaintP2X findings to print.
MAX_DISPLAYED_FINDINGS = 10

# Show alternative if it is close enough to candidate #1.
ALTERNATIVE_SCORE_RATIO = 0.70


# ============================================================
# TAINTP2X VULNERABILITY CODES
# ============================================================

CODE_TO_TYPE = {
    "5001": "code execution",
    "5005": "command injection",
    "5007": "email injection",
    "5008": "sql injection",
    "5010": "file operation",
    "5015": "ssrf",
}


# ============================================================
# SINK ALIASES
# ============================================================

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
        "execute",
        "duckdb.execute",
        "connection.execute",
    },

    "sendmail": {
        "smtplib.sendmail",
        "sendmail",
    },
}


# ============================================================
# GENERIC WORDS
# ============================================================

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
    "github",
    "com",
}


# ============================================================
# ONLINE SCORING
# ============================================================

# Total = 100
WEIGHTS = {
    "repository": 15,
    "version": 15,
    "type": 15,
    "callable": 25,
    "sink": 15,
    "file": 10,
    "trace": 5,
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
    filename: str
    message: str
    source_text: str
    sink_text: str
    forward_text: str
    backward_text: str
    raw: Dict[str, Any]


@dataclass
class OnlineCandidate:
    cve: str
    source: str
    summary: str
    details: str
    references: List[str]
    score: float
    confidence: str
    evidence: List[str]
    dimension_scores: Dict[str, float]


@dataclass
class BenchmarkComparison:
    field: str
    benchmark_value: str
    online_value: str
    result: str
    reason: str


# ============================================================
# GENERAL HELPERS
# ============================================================

def clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def norm(value: Any) -> str:
    value = clean(value)

    value = value.lower()
    value = value.replace("\\", "/")

    value = re.sub(
        r"\s+",
        " ",
        value,
    )

    return value.strip()


def normalize_repo(value: Any) -> str:
    value = norm(value)

    value = re.sub(
        r"^https?://github\.com/",
        "",
        value,
    )

    value = value.rstrip("/")
    value = value.removesuffix(".git")

    return value


def repo_name(value: Any) -> str:
    repo = normalize_repo(value)

    if "/" in repo:
        return repo.split("/")[-1]

    return repo


def normalize_version(value: Any) -> str:
    return norm(value).lstrip("v")


def repo_matches(
    a: str,
    b: str,
) -> bool:

    a = normalize_repo(a)
    b = normalize_repo(b)

    if not a or not b:
        return False

    if a == b:
        return True

    return (
        a.split("/")[-1]
        == b.split("/")[-1]
    )


def version_matches(
    a: str,
    b: str,
) -> bool:

    return (
        normalize_version(a)
        ==
        normalize_version(b)
    )


def flatten(value: Any) -> str:

    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(
        value,
        (int, float, bool),
    ):
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


def unique(
    values: List[str],
) -> List[str]:

    result = []
    seen = set()

    for value in values:

        key = norm(value)

        if not key:
            continue

        if key in seen:
            continue

        seen.add(key)
        result.append(value)

    return result


def tokenize(
    text: str,
) -> List[str]:

    words = re.findall(
        r"[A-Za-z_][A-Za-z0-9_]*",
        norm(text),
    )

    return unique(
        [
            word
            for word in words
            if (
                len(word) >= 4
                and word not in STOPWORDS
            )
        ]
    )


# ============================================================
# HTTP / JSON
# ============================================================

def request_json(
    url: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    retries: int = 2,
    timeout: int = 25,
) -> Dict[str, Any]:

    body = None

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    if payload is not None:

        body = json.dumps(
            payload
        ).encode("utf-8")

        headers[
            "Content-Type"
        ] = "application/json"

    last_error = None

    for attempt in range(
        retries + 1
    ):

        try:

            request = urllib.request.Request(
                url,
                data=body,
                headers=headers,
                method=method,
            )

            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:

                raw = response.read().decode(
                    "utf-8",
                    errors="replace",
                )

                return json.loads(
                    raw
                )

        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
        ) as exc:

            last_error = str(exc)

            if attempt < retries:

                time.sleep(
                    2 ** attempt
                )

    raise RuntimeError(
        last_error
        or
        "Unknown network error"
    )


# ============================================================
# TEST SOURCE
# ============================================================

def load_test_source(
    path: Path,
) -> List[Dict[str, Any]]:

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:

        data = json.load(
            file
        )

    if (
        not isinstance(data, list)
        or not data
    ):

        raise ValueError(
            "test_source.json must contain "
            "a non-empty JSON array."
        )

    entries = []

    for index, item in enumerate(
        data
    ):

        if not isinstance(
            item,
            dict,
        ):
            continue

        repository = clean(
            item.get(
                "nameWithOwner"
            )
            or item.get(
                "repository"
            )
        )

        version = clean(
            item.get(
                "version"
            )
        )

        commit_hash = clean(
            item.get(
                "commit_hash"
            )
        )

        url = clean(
            item.get(
                "url"
            )
        )

        if (
            repository
            and version
            and commit_hash
        ):

            entries.append(
                {
                    "index": index,
                    "repository": repository,
                    "version": version,
                    "commit_hash": commit_hash,
                    "url": url,
                }
            )

    if not entries:

        raise ValueError(
            "No valid test_source entries found."
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
        if (
            repo_matches(
                entry["repository"],
                repository,
            )
            and
            version_matches(
                entry["version"],
                version,
            )
        )
    ]

    if not matches:

        raise ValueError(
            "No test_source entry matches "
            f"{repository} {version}."
        )

    if len(matches) > 1:

        raise ValueError(
            "Multiple test_source entries match "
            f"{repository} {version}."
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

        reader = csv.DictReader(
            file
        )

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

                if (
                    not key
                    or key.lower().startswith(
                        "unnamed:"
                    )
                ):
                    continue

                row[key] = clean(value)

            rows.append(
                row
            )

    if not rows:

        raise ValueError(
            "Benchmark CSV is empty."
        )

    required = {
        "CVE_ID",
        "Repository",
        "Version",
        "Sink location",
    }

    missing = (
        required
        -
        set(
            rows[0].keys()
        )
    )

    if missing:

        raise ValueError(
            "Benchmark CSV is missing: "
            + ", ".join(
                sorted(missing)
            )
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
            row.get(
                "CVE_ID",
                "",
            )
        ).upper()
        == cve.upper()
    ]

    if not matches:

        raise ValueError(
            f"No benchmark row found for {cve}."
        )

    if len(matches) > 1:

        details = ", ".join(
            f"{row.get('Repository', '')} "
            f"{row.get('Version', '')}"
            for row in matches
        )

        raise ValueError(
            f"Multiple benchmark rows for "
            f"{cve}: {details}"
        )

    return matches[0]


# ============================================================
# TAINTP2X FINDINGS
# ============================================================

def load_findings(
    path: Path,
) -> List[Finding]:

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
                obj = json.loads(
                    line
                )

            except json.JSONDecodeError:
                continue

            if obj.get(
                "kind"
            ) != "issue":

                continue

            data = obj.get(
                "data"
            ) or {}

            if not isinstance(
                data,
                dict,
            ):

                continue

            traces = data.get(
                "traces"
            ) or []

            forward = {}
            backward = {}

            if isinstance(
                traces,
                list,
            ):

                for trace in traces:

                    if not isinstance(
                        trace,
                        dict,
                    ):
                        continue

                    name = norm(
                        trace.get(
                            "name"
                        )
                    )

                    if name == "forward":

                        forward = trace

                    elif name == "backward":

                        backward = trace

            elif isinstance(
                traces,
                dict,
            ):

                forward = (
                    traces.get(
                        "forward"
                    )
                    or {}
                )

                backward = (
                    traces.get(
                        "backward"
                    )
                    or {}
                )

            findings.append(
                Finding(
                    line_number=
                        line_number,

                    callable=
                        clean(
                            data.get(
                                "callable"
                            )
                        ),

                    callable_line=
                        data.get(
                            "callable_line"
                        ),

                    code=
                        clean(
                            data.get(
                                "code"
                            )
                        ),

                    filename=
                        clean(
                            data.get(
                                "filename"
                            )
                        ),

                    message=
                        clean(
                            data.get(
                                "message"
                            )
                        ),

                    source_text=
                        flatten(
                            (
                                forward.get(
                                    "roots"
                                )
                                if isinstance(
                                    forward,
                                    dict,
                                )
                                else forward
                            )
                        ),

                    sink_text=
                        flatten(
                            (
                                backward.get(
                                    "roots"
                                )
                                if isinstance(
                                    backward,
                                    dict,
                                )
                                else backward
                            )
                        ),

                    forward_text=
                        flatten(
                            forward
                        ),

                    backward_text=
                        flatten(
                            backward
                        ),

                    raw=
                        obj,
                )
            )

    return findings


def finding_signals(
    finding: Finding,
) -> Dict[str, Any]:

    callable_parts = [
        part
        for part in finding.callable.split(
            "."
        )
        if part
    ]

    text = norm(
        " ".join(
            [
                finding.callable,
                finding.filename,
                finding.message,
                finding.source_text,
                finding.sink_text,
                finding.forward_text,
                finding.backward_text,
                CODE_TO_TYPE.get(
                    finding.code,
                    "",
                ),
            ]
        )
    )

    sinks = []

    for canonical, aliases in (
        SINK_ALIASES.items()
    ):

        if any(
            alias in text
            for alias in aliases
        ):

            sinks.append(
                canonical
            )

    return {
        "class":
            (
                callable_parts[-2]
                if len(
                    callable_parts
                ) >= 2
                else ""
            ),

        "method":
            (
                callable_parts[-1]
                if callable_parts
                else ""
            ),

        "callable_parts":
            callable_parts,

        "filename_tokens":
            tokenize(
                finding.filename
            ),

        "trace_terms":
            tokenize(
                " ".join(
                    [
                        finding.source_text,
                        finding.sink_text,
                        finding.forward_text,
                        finding.backward_text,
                    ]
                )
            ),

        "sinks":
            unique(sinks),

        "type":
            CODE_TO_TYPE.get(
                finding.code,
                "",
            ),
    }


# ============================================================
# ONLINE DATA
# ============================================================

def query_osv_package(
    package_name: str,
) -> List[Dict[str, Any]]:

    try:

        result = request_json(
            OSV_QUERY_API,
            method="POST",
            payload={
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI",
                }
            },
        )

        return (
            result.get(
                "vulns"
            )
            or []
        )

    except Exception as exc:

        print(
            f"[!] OSV lookup failed: {exc}"
        )

        return []


def nvd_search(
    query: str,
) -> List[Dict[str, Any]]:

    try:

        time.sleep(
            NVD_DELAY
        )

        url = (
            NVD_API
            + "?keywordSearch="
            + urllib.parse.quote(
                query
            )
        )

        result = request_json(
            url
        )

        return (
            result.get(
                "vulnerabilities"
            )
            or []
        )

    except Exception as exc:

        print(
            f"[!] NVD lookup failed for "
            f"'{query}': {exc}"
        )

        return []


def nvd_to_candidate(
    record: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    cve_data = (
        record.get(
            "cve"
        )
        or {}
    )

    cve_id = clean(
        cve_data.get(
            "id"
        )
    )

    if not cve_id:
        return None

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
        if item.get(
            "url"
        )
    ]

    return {
        "cve":
            cve_id,

        "summary":
            "",

        "details":
            description,

        "references":
            references,

        "source":
            "NVD",
    }


def build_candidate_pool(
    repository: str,
    version: str,
    findings: List[Finding],
) -> List[Dict[str, Any]]:

    package = repo_name(
        repository
    )

    candidate_map = {}

    # --------------------------------------------------------
    # OSV
    # --------------------------------------------------------

    osv_vulns = query_osv_package(
        package
    )

    for vuln in osv_vulns:

        aliases = (
            vuln.get(
                "aliases"
            )
            or []
        )

        cve = next(
            (
                alias
                for alias in aliases
                if alias.upper().startswith(
                    "CVE-"
                )
            ),
            clean(
                vuln.get(
                    "id"
                )
            ),
        )

        if not cve:
            continue

        candidate_map[
            cve
        ] = {
            "cve":
                cve,

            "summary":
                clean(
                    vuln.get(
                        "summary"
                    )
                ),

            "details":
                clean(
                    vuln.get(
                        "details"
                    )
                ),

            "references":
                [
                    item.get(
                        "url"
                    )
                    for item in (
                        vuln.get(
                            "references"
                        )
                        or []
                    )
                    if item.get(
                        "url"
                    )
                ],

            "source":
                "OSV",
        }

    # --------------------------------------------------------
    # NVD
    # --------------------------------------------------------

    queries = [
        package,
        f"{package} {version}",
    ]

    representative_terms = []

    for finding in findings:

        signals = finding_signals(
            finding
        )

        representative_terms.extend(
            [
                signals["class"],
                signals["method"],
            ]
        )

        representative_terms.extend(
            signals["sinks"]
        )

    for term in unique(
        representative_terms
    )[:4]:

        if term:

            queries.append(
                f"{package} {version} {term}"
            )

    for query in unique(
        queries
    ):

        records = nvd_search(
            query
        )

        for record in records:

            candidate = (
                nvd_to_candidate(
                    record
                )
            )

            if not candidate:
                continue

            cve = candidate[
                "cve"
            ]

            if cve in candidate_map:

                existing = (
                    candidate_map[
                        cve
                    ]
                )

                existing[
                    "source"
                ] = "OSV+NVD"

                if not existing.get(
                    "details"
                ):

                    existing[
                        "details"
                    ] = candidate.get(
                        "details",
                        "",
                    )

                existing[
                    "references"
                ] = unique(
                    existing.get(
                        "references",
                        [],
                    )
                    +
                    candidate.get(
                        "references",
                        [],
                    )
                )

            else:

                candidate_map[
                    cve
                ] = candidate

    return list(
        candidate_map.values()
    )[
        :MAX_ONLINE_CANDIDATES
    ]


# ============================================================
# ONLINE SCORING
# ============================================================

def candidate_text(
    candidate: Dict[str, Any],
) -> str:

    return norm(
        " ".join(
            [
                candidate.get(
                    "summary",
                    "",
                ),

                candidate.get(
                    "details",
                    "",
                ),

                candidate.get(
                    "affected",
                    "",
                ),

                flatten(
                    candidate.get(
                        "references",
                        [],
                    )
                ),
            ]
        )
    )


def version_appears(
    text: str,
    version: str,
) -> bool:

    version = normalize_version(
        version
    )

    if not version:
        return False

    return (
        version in text
        or
        f"v{version}" in text
    )


def type_aliases(
    vulnerability_type: str,
) -> List[str]:

    mapping = {

        "code execution": [
            "code execution",
            "arbitrary code",
            "remote code",
            "rce",
            "code injection",
        ],

        "command injection": [
            "command injection",
            "remote command",
        ],

        "sql injection": [
            "sql injection",
            "sqli",
        ],

        "file operation": [
            "file read",
            "file write",
            "file access",
            "path traversal",
        ],

        "ssrf": [
            "ssrf",
            "server-side request forgery",
            "request forgery",
        ],

        "email injection": [
            "email injection",
        ],
    }

    return mapping.get(
        vulnerability_type,
        [vulnerability_type],
    )


def score_candidate(
    finding: Finding,
    candidate: Dict[str, Any],
    repository: str,
    version: str,
) -> OnlineCandidate:
    """
    Evidence score out of 100.

    This is NOT a probability.

    Important:
        It is used for ranking only.
        It does not automatically prove attribution.
    """

    signals = finding_signals(
        finding
    )

    text = candidate_text(
        candidate
    )

    scores = {
        name: 0.0
        for name in WEIGHTS
    }

    evidence = []

    # --------------------------------------------------------
    # Repository = 15
    # --------------------------------------------------------

    package = repo_name(
        repository
    )

    if (
        package
        and package in text
    ):

        scores[
            "repository"
        ] = 15

        evidence.append(
            f"repository '{package}' matched"
        )

    # --------------------------------------------------------
    # Version = 15
    # --------------------------------------------------------

    if version_appears(
        text,
        version,
    ):

        scores[
            "version"
        ] = 15

        evidence.append(
            f"version '{version}' matched"
        )

    # --------------------------------------------------------
    # Vulnerability type = 15
    # --------------------------------------------------------

    type_hits = [
        alias
        for alias in type_aliases(
            signals["type"]
        )
        if alias in text
    ]

    if type_hits:

        scores[
            "type"
        ] = 15

        evidence.append(
            "vulnerability type matched: "
            + ", ".join(
                type_hits
            )
        )

    # --------------------------------------------------------
    # Callable/function = 25
    # --------------------------------------------------------

    callable_hits = []

    callable_class = norm(
        signals["class"]
    )

    callable_method = norm(
        signals["method"]
    )

    if (
        callable_class
        and callable_class in text
    ):

        callable_hits.append(
            signals["class"]
        )

    if (
        callable_method
        and
        len(
            callable_method
        ) >= 4
        and
        callable_method in text
    ):

        callable_hits.append(
            signals["method"]
        )

    # Known public API / implementation relationship.
    if (
        "vannabase.ask"
        in norm(
            finding.callable
        )
        and
        "vanna.ask"
        in text
    ):

        callable_hits.append(
            "vanna.ask"
        )

    callable_hits = unique(
        callable_hits
    )

    if callable_hits:

        scores[
            "callable"
        ] = 25

        evidence.append(
            "callable/function matched: "
            + ", ".join(
                callable_hits
            )
        )

    # --------------------------------------------------------
    # Sink = 15
    # --------------------------------------------------------

    sink_hits = []

    for sink in signals[
        "sinks"
    ]:

        aliases = SINK_ALIASES.get(
            sink,
            {sink},
        )

        if any(
            alias in text
            for alias in aliases
        ):

            sink_hits.append(
                sink
            )

    sink_hits = unique(
        sink_hits
    )

    if sink_hits:

        scores[
            "sink"
        ] = 15

        evidence.append(
            "sink matched: "
            + ", ".join(
                sink_hits
            )
        )

    # --------------------------------------------------------
    # File/path = 10
    # --------------------------------------------------------

    file_hits = [
        token
        for token in signals[
            "filename_tokens"
        ]
        if token in text
    ]

    if file_hits:

        scores[
            "file"
        ] = (
            10
            if len(
                file_hits
            ) >= 2
            else 5
        )

        evidence.append(
            "file/path terms matched: "
            + ", ".join(
                unique(
                    file_hits
                )[:6]
            )
        )

    # --------------------------------------------------------
    # Trace = 5
    # --------------------------------------------------------

    trace_hits = [
        token
        for token in signals[
            "trace_terms"
        ]
        if (
            len(token) >= 5
            and token in text
        )
    ]

    if trace_hits:

        scores[
            "trace"
        ] = (
            5
            if len(
                trace_hits
            ) >= 3
            else 2.5
        )

        evidence.append(
            "trace terms matched: "
            + ", ".join(
                unique(
                    trace_hits
                )[:6]
            )
        )

    total = round(
        sum(
            scores.values()
        ),
        1,
    )

    active_dimensions = sum(
        1
        for value in scores.values()
        if value > 0
    )

    if (
        total >= 80
        and
        active_dimensions >= 5
    ):

        confidence = "HIGH"

    elif (
        total >= 60
        and
        active_dimensions >= 4
    ):

        confidence = "MEDIUM"

    elif (
        total >= 35
        and
        active_dimensions >= 2
    ):

        confidence = "LOW"

    else:

        confidence = "VERY_LOW"

    return OnlineCandidate(
        cve=
            candidate.get(
                "cve",
                "",
            ),

        source=
            candidate.get(
                "source",
                "",
            ),

        summary=
            candidate.get(
                "summary",
                "",
            ),

        details=
            candidate.get(
                "details",
                "",
            ),

        references=
            candidate.get(
                "references",
                [],
            ),

        score=
            total,

        confidence=
            confidence,

        evidence=
            evidence,

        dimension_scores=
            scores,
    )


# ============================================================
# BENCHMARK COMPARISON
# ============================================================

def benchmark_function_terms(
    benchmark: Dict[str, str],
) -> List[str]:

    text = " ".join(
        [
            benchmark.get(
                "Affected_Component",
                "",
            ),

            benchmark.get(
                "Sink location",
                "",
            ),
        ]
    )

    matches = re.findall(
        r"(?:[A-Za-z_][\w]*\.)*"
        r"[A-Za-z_][\w]*"
        r"\s*\(",
        text,
    )

    return unique(
        [
            item
            .rstrip("(")
            .strip()
            for item in matches
        ]
    )


def benchmark_component_terms(
    benchmark: Dict[str, str],
) -> List[str]:

    text = " ".join(
        [
            benchmark.get(
                "Affected_Component",
                "",
            ),

            benchmark.get(
                "Sink location",
                "",
            ),
        ]
    )

    words = re.findall(
        r"[A-Za-z_][A-Za-z0-9_]*",
        text.lower(),
    )

    return unique(
        [
            word
            for word in words
            if (
                len(word) >= 5
                and
                word not in STOPWORDS
            )
        ]
    )


def compare_benchmark(
    benchmark: Dict[str, str],
    online: OnlineCandidate,
) -> List[BenchmarkComparison]:
    """
    Compare an online candidate with the benchmark.

    This does NOT decide whether TaintP2X detected the CVE.

    It tells us whether our manual benchmark agrees with
    the independently attributed online vulnerability.
    """

    text = candidate_text(
        {
            "summary":
                online.summary,

            "details":
                online.details,

            "affected":
                "",

            "references":
                online.references,
        }
    )

    comparisons = []

    # --------------------------------------------------------
    # CVE
    # --------------------------------------------------------

    benchmark_cve = clean(
        benchmark.get(
            "CVE_ID",
            "",
        )
    ).upper()

    online_cve = clean(
        online.cve
    ).upper()

    comparisons.append(
        BenchmarkComparison(
            field="CVE",

            benchmark_value=
                benchmark_cve,

            online_value=
                online_cve,

            result=(
                "MATCH"
                if
                benchmark_cve
                ==
                online_cve
                else
                "MISMATCH"
            ),

            reason=
                "Exact CVE comparison.",
        )
    )

    # --------------------------------------------------------
    # Repository
    # --------------------------------------------------------

    benchmark_repo = clean(
        benchmark.get(
            "Repository",
            "",
        )
    )

    package = repo_name(
        benchmark_repo
    )

    repo_result = (
        "MATCH"
        if (
            package
            and
            package in text
        )
        else
        "NOT_VERIFIABLE"
    )

    comparisons.append(
        BenchmarkComparison(
            field="Repository",

            benchmark_value=
                benchmark_repo,

            online_value=
                package
                if repo_result == "MATCH"
                else "",

            result=
                repo_result,

            reason=
                "Repository must be explicitly "
                "present online; it is not guessed.",
        )
    )

    # --------------------------------------------------------
    # Version
    # --------------------------------------------------------

    benchmark_version = clean(
        benchmark.get(
            "Version",
            "",
        )
    )

    version_result = (
        "MATCH"
        if version_appears(
            text,
            benchmark_version,
        )
        else
        "NOT_VERIFIABLE"
    )

    comparisons.append(
        BenchmarkComparison(
            field="Version",

            benchmark_value=
                benchmark_version,

            online_value=
                benchmark_version
                if version_result == "MATCH"
                else "",

            result=
                version_result,

            reason=
                "Version is not inferred "
                "when it is absent online.",
        )
    )

    # --------------------------------------------------------
    # Vulnerability type
    # --------------------------------------------------------

    benchmark_type = norm(
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
            ]
        )
    )

    mappings = {
        "code execution": [
            "code injection",
            "code execution",
            "rce",
            "arbitrary code",
        ],

        "sql injection": [
            "sql injection",
            "sqli",
        ],

        "ssrf": [
            "ssrf",
            "server-side request forgery",
        ],

        "command injection": [
            "command injection",
        ],

        "file operation": [
            "file read",
            "file write",
            "path traversal",
        ],
    }

    type_result = "NOT_VERIFIABLE"
    canonical_type = ""

    for canonical, aliases in mappings.items():

        if any(
            alias in benchmark_type
            for alias in aliases
        ):

            canonical_type = canonical

            if any(
                alias in text
                for alias in aliases
            ):

                type_result = "MATCH"

            else:

                type_result = "NO_MATCH"

            break

    comparisons.append(
        BenchmarkComparison(
            field="Vulnerability Type",

            benchmark_value=
                benchmark_type,

            online_value=
                canonical_type,

            result=
                type_result,

            reason=
                "Compares vulnerability terminology.",
        )
    )

    # --------------------------------------------------------
    # Component/function
    # --------------------------------------------------------

    benchmark_functions = (
        benchmark_function_terms(
            benchmark
        )
    )

    component_terms_from_benchmark = (
        benchmark_component_terms(
            benchmark
        )
    )

    all_component_terms = unique(
        benchmark_functions
        +
        component_terms_from_benchmark
    )

    component_hits = [
        term
        for term in all_component_terms
        if norm(term) in text
    ]

    if len(component_hits) >= 2:

        component_result = "MATCH"

    elif len(component_hits) == 1:

        component_result = "PARTIAL"

    else:

        component_result = "NO_MATCH"

    comparisons.append(
        BenchmarkComparison(
            field="Affected Component / Function",

            benchmark_value=
                (
                    benchmark.get(
                        "Affected_Component",
                        "",
                    )
                    + " | "
                    +
                    benchmark.get(
                        "Sink location",
                        "",
                    )
                ),

            online_value=
                ", ".join(
                    component_hits[:10]
                ),

            result=
                component_result,

            reason=
                (
                    "Manual component terminology "
                    "is treated as evidence, not "
                    "exact proof."
                ),
        )
    )

    # --------------------------------------------------------
    # Sink
    # --------------------------------------------------------

    benchmark_sink = norm(
        benchmark.get(
            "Sink location",
            "",
        )
    )

    sink_hits = []

    for canonical, aliases in (
        SINK_ALIASES.items()
    ):

        benchmark_has = any(
            alias in benchmark_sink
            for alias in aliases
        )

        online_has = any(
            alias in text
            for alias in aliases
        )

        if (
            benchmark_has
            and
            online_has
        ):

            sink_hits.append(
                canonical
            )

    comparisons.append(
        BenchmarkComparison(
            field="Sink",

            benchmark_value=
                benchmark.get(
                    "Sink location",
                    "",
                ),

            online_value=
                ", ".join(
                    sink_hits
                ),

            result=
                (
                    "MATCH"
                    if sink_hits
                    else
                    "NO_MATCH"
                ),

            reason=
                (
                    "Uses sink aliases instead "
                    "of exact string matching."
                ),
        )
    )

    # --------------------------------------------------------
    # Vulnerable behaviour
    # --------------------------------------------------------

    behaviour = benchmark.get(
        "ObservedFailure/ Vulnerable behaviour",
        "",
    )

    behaviour_terms = tokenize(
        behaviour
    )

    behaviour_hits = [
        term
        for term in behaviour_terms
        if term in text
    ]

    if len(
        behaviour_hits
    ) >= 2:

        behaviour_result = "MATCH"

    elif len(
        behaviour_hits
    ) == 1:

        behaviour_result = "PARTIAL"

    else:

        behaviour_result = "NO_MATCH"

    comparisons.append(
        BenchmarkComparison(
            field="Vulnerable Behaviour",

            benchmark_value=
                behaviour,

            online_value=
                ", ".join(
                    behaviour_hits[:10]
                ),

            result=
                behaviour_result,

            reason=
                (
                    "Uses meaningful terms from "
                    "the manual benchmark annotation."
                ),
        )
    )

    return comparisons


def comparison_summary(
    comparisons: List[BenchmarkComparison],
) -> str:

    cve_result = next(
        (
            item.result
            for item in comparisons
            if item.field == "CVE"
        ),
        "MISMATCH",
    )

    if cve_result != "MATCH":

        return "DISAGREES"

    if any(
        item.result == "MISMATCH"
        for item in comparisons
    ):

        return "DISAGREES"

    if any(
        item.result
        in {
            "NO_MATCH",
            "PARTIAL",
        }
        for item in comparisons
    ):

        return (
            "AGREES_WITH_UNCERTAINTY"
        )

    return "AGREES"


# ============================================================
# PRINTING
# ============================================================

def print_candidate(
    candidate: OnlineCandidate,
    finding: Finding,
    rank: int,
    is_alternative: bool,
    is_tied: bool,
) -> None:

    label = (
        "ALTERNATIVE ONLINE CANDIDATE"
        if is_alternative
        else
        f"ONLINE CANDIDATE #{rank}"
    )

    print()
    print(label)

    print(
        "-" * 72
    )

    print(
        f"CVE:        "
        f"{candidate.cve}"
    )

    print(
        f"Score:      "
        f"{candidate.score:.1f} / 100"
    )

    print(
        f"Confidence: "
        f"{candidate.confidence}"
    )

    print(
        f"Source:     "
        f"{candidate.source}"
    )

    if is_tied:

        print(
            "STATUS:     ⚠️ SCORE TIE"
        )

    print()

    print(
        "Dimension scores:"
    )

    for name, value in (
        candidate.dimension_scores.items()
    ):

        print(
            f"  {name:<12} "
            f"{value:>5.1f} / "
            f"{WEIGHTS[name]}"
        )

    print()

    print(
        "Why this CVE matched the TaintP2X finding:"
    )

    if candidate.evidence:

        for evidence in candidate.evidence:

            print(
                f"  ✅ {evidence}"
            )

    else:

        print(
            "  No strong matching evidence."
        )

    if candidate.summary:

        print()

        print(
            "Online summary:"
        )

        print(
            re.sub(
                r"\s+",
                " ",
                candidate.summary,
            )[:700]
        )

    elif candidate.details:

        print()

        print(
            "Online details:"
        )

        print(
            re.sub(
                r"\s+",
                " ",
                candidate.details,
            )[:700]
        )


def print_benchmark_comparison(
    comparisons: List[BenchmarkComparison],
) -> None:

    print()
    print(
        "=" * 72
    )

    print(
        "BENCHMARK COMPARISON"
    )

    print(
        "=" * 72
    )

    for comparison in comparisons:

        print()

        print(
            f"{comparison.field}: "
            f"{comparison.result}"
        )

        print(
            f"  Benchmark: "
            f"{comparison.benchmark_value[:180]}"
        )

        print(
            f"  Online:    "
            f"{comparison.online_value[:180]}"
        )

        print(
            f"  Reason:    "
            f"{comparison.reason}"
        )


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Independently attribute TaintP2X "
            "findings online and compare "
            "candidate CVEs with the benchmark."
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
        help="Benchmark CVE to compare against",
    )

    parser.add_argument(
        "--test-source",
        default="test_source.json",
        help="Path to test_source.json",
    )

    parser.add_argument(
        "--max-displayed-findings",
        type=int,
        default=MAX_DISPLAYED_FINDINGS,
        help="Maximum TaintP2X findings to display",
    )

    parser.add_argument(
        "--no-online",
        action="store_true",
        help="Skip online attribution",
    )

    parser.add_argument(
        "--json-out",
        help="JSON output path",
    )

    args = parser.parse_args()

    # ========================================================
    # PATHS
    # ========================================================

    csv_path = (
        Path(
            args.csv
        )
        .expanduser()
        .resolve()
    )

    pysa_path = (
        Path(
            args.pysa
        )
        .expanduser()
        .resolve()
    )

    test_source_path = (
        Path(
            args.test_source
        )
        .expanduser()
        .resolve()
    )

    for path, label in [

        (
            csv_path,
            "Benchmark CSV",
        ),

        (
            pysa_path,
            "TaintP2X output",
        ),

        (
            test_source_path,
            "test_source.json",
        ),
    ]:

        if not path.exists():

            print(
                f"ERROR: {label} not found: "
                f"{path}",
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

        rows = load_csv(
            csv_path
        )

        benchmark = select_benchmark(
            rows,
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
            f"    Benchmark CVE: "
            f"{args.cve}"
        )

        print(
            f"    Repository:    "
            f"{benchmark_repo}"
        )

        print(
            f"    Version:       "
            f"{benchmark_version}"
        )

        print(
            "[*] Reading test_source.json..."
        )

        entries = load_test_source(
            test_source_path
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
            f'    Loaded {len(findings)} '
            'kind="issue" finding(s)'
        )

    except Exception as exc:

        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return 2

    # ========================================================
    # STAGE 1
    # ========================================================

    online_results = []

    if not args.no_online:

        print()
        print(
            "=" * 72
        )

        print(
            "STAGE 1 — ONLINE ATTRIBUTION"
        )

        print(
            "=" * 72
        )

        print(
            "The benchmark CVE is NOT used to "
            "force the online attribution."
        )

        print(
            "[*] Building online candidate pool..."
        )

        pool = build_candidate_pool(
            test_source[
                "repository"
            ],
            test_source[
                "version"
            ],
            findings,
        )

        print(
            f"    Online candidate CVEs: "
            f"{len(pool)}"
        )

        for finding in findings:

            scored = []

            for candidate in pool:

                scored_candidate = (
                    score_candidate(
                        finding,
                        candidate,
                        test_source[
                            "repository"
                        ],
                        test_source[
                            "version"
                        ],
                    )
                )

                # Ignore extremely weak candidates.
                if (
                    scored_candidate.score
                    >= 35
                ):

                    scored.append(
                        scored_candidate
                    )

            if not scored:
                continue

            scored.sort(
                key=lambda candidate:
                candidate.score,
                reverse=True,
            )

            best = scored[0]

            alternative = None

            if len(
                scored
            ) >= 2:

                second = scored[1]

                if (
                    second.score
                    >=
                    best.score
                    *
                    ALTERNATIVE_SCORE_RATIO
                ):

                    alternative = second

            # A score tie at the top.
            tied = (
                alternative is not None
                and
                abs(
                    best.score
                    -
                    alternative.score
                )
                < 0.0001
            )

            online_results.append(
                {
                    "finding":
                        finding,

                    "primary_candidate":
                        best,

                    "alternative_candidate":
                        alternative,

                    "score_tie":
                        tied,

                    "all_ranked_candidates":
                        scored[:5],
                }
            )

        # Strongest findings first.
        online_results.sort(
            key=lambda item:
            item[
                "primary_candidate"
            ].score,
            reverse=True,
        )

        # ----------------------------------------------------
        # Display only relevant findings.
        # ----------------------------------------------------

        for index, item in enumerate(
            online_results[
                :args.max_displayed_findings
            ],
            1,
        ):

            finding = item[
                "finding"
            ]

            primary = item[
                "primary_candidate"
            ]

            alternative = item[
                "alternative_candidate"
            ]

            tied = item[
                "score_tie"
            ]

            print()
            print(
                f"FINDING #{index}"
            )

            print(
                "-" * 72
            )

            print(
                f"taint-output.json line: "
                f"{finding.line_number}"
            )

            print(
                f"Callable: "
                f"{finding.callable}"
            )

            print(
                f"Code: "
                f"{finding.code} / "
                f"{CODE_TO_TYPE.get(finding.code, 'unknown')}"
            )

            print(
                f"File: "
                f"{finding.filename}"
            )

            print_candidate(
                primary,
                finding,
                rank=1,
                is_alternative=False,
                is_tied=tied,
            )

            if alternative:

                print_candidate(
                    alternative,
                    finding,
                    rank=2,
                    is_alternative=True,
                    is_tied=tied,
                )

            if tied:

                print()
                print(
                    "⚠️ TOP CANDIDATES HAVE "
                    "THE SAME SCORE."
                )

                print(
                    "NO AUTOMATIC WINNER."
                )

            elif alternative:

                print()
                print(
                    "ℹ️ An alternative candidate "
                    "is also reasonably close."
                )

                print(
                    "The primary candidate is only "
                    "ranked higher by the evidence score."
                )

            else:

                print()
                print(
                    "No close alternative candidate "
                    "was found."
                )

    # ========================================================
    # STAGE 2
    # ========================================================

    comparison_results = []

    if online_results:

        print()
        print(
            "=" * 72
        )

        print(
            "STAGE 2 — BENCHMARK COMPARISON"
        )

        print(
            "=" * 72
        )

        for item in online_results[
            :args.max_displayed_findings
        ]:

            finding = item[
                "finding"
            ]

            candidates_to_compare = [
                item[
                    "primary_candidate"
                ]
            ]

            if item[
                "alternative_candidate"
            ] is not None:

                candidates_to_compare.append(
                    item[
                        "alternative_candidate"
                    ]
                )

            for candidate in (
                candidates_to_compare
            ):

                comparisons = (
                    compare_benchmark(
                        benchmark,
                        candidate,
                    )
                )

                summary = (
                    comparison_summary(
                        comparisons
                    )
                )

                comparison_results.append(
                    {
                        "finding":
                            finding,

                        "candidate":
                            candidate,

                        "comparisons":
                            comparisons,

                        "summary":
                            summary,
                    }
                )

                print()
                print(
                    "-" * 72
                )

                print(
                    f"TaintP2X line: "
                    f"{finding.line_number}"
                )

                print(
                    f"Online candidate: "
                    f"{candidate.cve}"
                )

                print(
                    f"Online score: "
                    f"{candidate.score:.1f} / 100"
                )

                print_benchmark_comparison(
                    comparisons
                )

                print()
                print(
                    f"BENCHMARK AGREEMENT: "
                    f"{summary}"
                )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print()
    print(
        "=" * 72
    )

    print(
        "FINAL SUMMARY"
    )

    print(
        "=" * 72
    )

    print(
        f"Benchmark CVE: "
        f"{args.cve}"
    )

    print(
        f"Repository:    "
        f"{test_source['repository']}"
    )

    print(
        f"Version:       "
        f"{test_source['version']}"
    )

    print(
        f"kind=issue findings analysed: "
        f"{len(findings)}"
    )

    print()

    if online_results:

        print(
            "ONLINE ATTRIBUTION RESULTS"
        )

        print(
            "-" * 72
        )

        for item in online_results[
            :args.max_displayed_findings
        ]:

            primary = item[
                "primary_candidate"
            ]

            alternative = item[
                "alternative_candidate"
            ]

            finding = item[
                "finding"
            ]

            print(
                f"\nLine {finding.line_number}: "
                f"{finding.callable}"
            )

            print(
                f"  Candidate #1: "
                f"{primary.cve} "
                f"({primary.score:.1f}/100, "
                f"{primary.confidence})"
            )

            if alternative:

                print(
                    f"  Alternative:  "
                    f"{alternative.cve} "
                    f"({alternative.score:.1f}/100, "
                    f"{alternative.confidence})"
                )

            if item[
                "score_tie"
            ]:

                print(
                    "  Status:       "
                    "⚠️ TIED — NO WINNER"
                )

            else:

                print(
                    "  Status:       "
                    "Ranked by evidence score only"
                )

    else:

        print(
            "No sufficiently strong online "
            "attribution was found."
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

        "target_benchmark_cve":
            args.cve,

        "test_source":
            test_source,

        "benchmark":
            benchmark,

        "issue_count":
            len(findings),

        "online_scoring":
            {
                "total":
                    100,

                "weights":
                    WEIGHTS,

                "note":
                    (
                        "Evidence score only; "
                        "not probability and not proof."
                    ),
            },

        "online_attributions":
            [
                {
                    "taint_output_line":
                        item[
                            "finding"
                        ].line_number,

                    "callable":
                        item[
                            "finding"
                        ].callable,

                    "code":
                        item[
                            "finding"
                        ].code,

                    "filename":
                        item[
                            "finding"
                        ].filename,

                    "score_tie":
                        item[
                            "score_tie"
                        ],

                    "primary_candidate":
                        asdict(
                            item[
                                "primary_candidate"
                            ]
                        ),

                    "alternative_candidate":
                        (
                            asdict(
                                item[
                                    "alternative_candidate"
                                ]
                            )
                            if
                            item[
                                "alternative_candidate"
                            ]
                            else
                            None
                        ),

                    "top_ranked_candidates":
                        [
                            asdict(
                                candidate
                            )
                            for candidate
                            in item[
                                "all_ranked_candidates"
                            ]
                        ],
                }

                for item
                in online_results
            ],

        "benchmark_comparisons":
            [
                {
                    "taint_output_line":
                        item[
                            "finding"
                        ].line_number,

                    "online_cve":
                        item[
                            "candidate"
                        ].cve,

                    "online_score":
                        item[
                            "candidate"
                        ].score,

                    "agreement":
                        item[
                            "summary"
                        ],

                    "comparisons":
                        [
                            asdict(
                                comparison
                            )
                            for comparison
                            in item[
                                "comparisons"
                            ]
                        ],
                }

                for item
                in comparison_results
            ],
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

        print()
        print(
            "[*] JSON report written to:"
        )

        print(
            output
        )

    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )