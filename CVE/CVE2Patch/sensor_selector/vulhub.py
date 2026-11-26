"""Lettura dei README Vulhub senza eseguire comandi.

Distingue la sezione di exploit dalle istruzioni di preparazione. Un semplice
percorso sensibile non prova una syscall filesystem sul server.
"""
from __future__ import annotations
import json
import re

from .utils import csv_items, safe_vulhub_readme_url, is_explicit_multi_cve_chain


VULHUB_OBSERVABLE_CATALOG = {
    "process_execution": {
        "events": ["execve", "execveat"],
        "sensors": ["falco_modern_ebpf", "elastic_defend"],
        "fields": ["process.name", "process.parent", "process.command_line"],
        "caveat": "L'evento riguarda il PoC documentato; non tutti gli exploit RCE creano nuovi processi.",
    },
    "file_access": {
        "events": ["open", "openat", "openat2"],
        "sensors": ["falco_modern_ebpf"],
        "fields": ["file.path", "process.name"],
        "caveat": "README: path nel PoC, da verificare se letto dal processo bersaglio. Il solo path non prova la syscall né l’intento.",
    },
}


EXPLOIT_PROCESS_PATTERNS = [
    re.compile(r"(?:getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder\s*\(|subprocess\s*\.\s*(?:Popen|run|call|check_output|check_call)\s*\()", re.I),
    re.compile(r"\b(?:os\s*\.\s*(?:system|popen)|shell_exec|passthru)\s*\(", re.I),
    re.compile(r"\b(?:exec|system)\s*\(\s*['\"](?:/bin/|sh\b|bash\b|touch\b|id\b|whoami\b)", re.I),
    # CGI traversal: il comando HTTP dell'attaccante invoca una shell CGI sul server.
    re.compile(r"(?:curl|wget)\b[^\n]{0,400}(?:--data|--data-binary|-d\s)[^\n]{0,300}\b(?:/bin/sh|/bin/bash)\b", re.I),
    re.compile(r"(?:/bin/sh|/bin/bash)[^\n]{0,220}(?:--data|--data-binary|-d\s)[^\n]{0,220}", re.I),
    # Python import dinamico del modulo subprocess, presente in alcuni PoC.
    re.compile(r"__import__\s*\(\s*['\"]subprocess['\"]\s*\)\s*\.\s*(?:check_output|Popen|run|call)\s*\(", re.I),
]


README_ATTACK_HEADING = re.compile(r"(?:exploit|reproduc(?:e|tion)|proof.of.concept|\bpoc\b|\battack\b|verification|demonstration|验证|复现|漏洞利用)", re.I)


README_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*$")


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def attack_sections(text):
    """Ritorna soltanto le sezioni README che descrivono la riproduzione.

    Ignora esplicitamente le sezioni di setup e 'vulnerable environment'.
    """
    headings = [(idx, match.group(2).strip()) for idx, line in enumerate(text.splitlines())
                if (match := README_HEADING.match(line))]
    lines = text.splitlines()
    result = []
    for i, (start, name) in enumerate(headings):
        if not README_ATTACK_HEADING.search(name):
            continue
        if "environment" in name.casefold() or "setup" in name.casefold():
            continue
        end = headings[i + 1][0] if i + 1 < len(headings) else len(lines)
        result.append((name, "\n".join(lines[start + 1:end])))
    return result


def short_excerpt_around_match(line, start, end, max_len=340):
    """Conserva la parte della riga contenente il match, anche nei payload lunghi."""
    if len(line) <= max_len:
        return line.strip()
    left = max(0, start - 95)
    right = min(len(line), max(left + max_len, end + 100))
    return line[left:right].strip()


def evidence_excerpt(section, match):
    """Conserva testo effettivamente presente nel README, incluso il match."""
    pos = match.start()
    line_start = section.rfind("\n", 0, pos) + 1
    line_end = section.find("\n", match.end())
    if line_end == -1:
        line_end = len(section)
    line = section[line_start:line_end]
    return short_excerpt_around_match(line, match.start()-line_start, match.end()-line_start)


SENSITIVE_PATH = re.compile(
    r"(?<![\w])/(?:etc/(?:passwd|shadow)|proc/self/environ|var/jenkins_home/[^\s\"'<>]+)\b", re.I
)


FILE_ACCESS_CONTEXT = re.compile(
    r"\b(?:read|reading|retrieve|retrieving|disclos|exfiltrat|leak|contents?|file|files|"
    r"path traversal|inclusion|fetch|profile=|read_blob|\bAccept:)\b", re.I
)


def file_access_evidence(section, heading, *, max_evidence=2):
    """Record real README lines (not generated claims about HTTP or syscalls).

    This is a *candidate* file-access observable. A path inside an attacker
    command does not prove that the vulnerable process opened it; the operator
    should verify that the context refers to the victim's file access.
    """
    lines = section.splitlines()
    hits = []
    for idx, line in enumerate(lines):
        m = SENSITIVE_PATH.search(line)
        if not m:
            continue
        # Require some explanatory attack context nearby: a standalone path in
        # a generic listing is not enough.
        window = " ".join(lines[max(0, idx - 5):min(len(lines), idx + 3)])
        if not FILE_ACCESS_CONTEXT.search(window):
            continue
        exact = line.strip()
        if not exact:
            continue
        hits.append({
            "behavior": "file_access",
            "heading": heading,
            "line_in_section": idx + 1,
            "matched_path": m.group(0),
            "excerpt": short_excerpt_around_match(line, m.start(), m.end()),
            "evidence_kind": "file_path_in_attack_section",
        })
        if len(hits) >= max_evidence:
            break
    return hits


def parse_vulhub_readme(cve_id, path, text):
    """Extract specific attack-section evidence without running the PoC."""
    mentioned = set(x.upper() for x in CVE_PATTERN.findall(text))
    if mentioned and cve_id not in mentioned:
        return "identity_mismatch", [], [], []
    if cve_id not in mentioned and path.rsplit("/", 1)[-1].upper() != cve_id:
        return "identity_unverified", [], [], []
    sections = attack_sections(text)
    # Un README che dichiara una catena di CVE non e' prova isolata
    # per l'assegnazione del sensore alla singola vulnerabilita'.
    if is_explicit_multi_cve_chain(text) or any(
        is_explicit_multi_cve_chain(part) for _, part in sections
    ):
        return "excluded_multi_cve_chain", [], [], []
    if not sections:
        return "no_attack_section", [], [], []
    found, evidence = [], []
    for heading, section in sections:
        for pattern in EXPLOIT_PROCESS_PATTERNS:
            match = pattern.search(section)
            if match:
                if "process_execution" not in found:
                    found.append("process_execution")
                evidence.append({
                    "behavior": "process_execution", "heading": heading,
                    "excerpt": evidence_excerpt(section, match),
                    "matched_text": match.group(0),
                    "evidence_kind": "execution_api_in_attack_section",
                })
                break
        file_hits = file_access_evidence(section, heading)
        if file_hits:
            if "file_access" not in found:
                found.append("file_access")
            evidence.extend(file_hits)
    if found:
        return "observable_documented", sorted(found), evidence[:8], sections
    return "no_concrete_host_observable", [], [], sections


def inspect_vulhub(cve_id, path, cache):
    url = safe_vulhub_readme_url(path) if path and re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", path) else ""
    base = {"cve_id": cve_id, "vulhub_path": path, "readme_url": url,
            "extraction_status": "", "observable_families": "",
            "event_types": "", "sensor_candidates": "", "required_fields": "",
            "evidence": "[]", "limitations": "", "readme_sha256": "", "review_required": "no"}
    content, err, digest = cache.get(path)
    base["readme_sha256"] = digest
    if err:
        base["extraction_status"] = "unavailable"
        base["limitations"] = err
        return base
    state, families, evidences, _ = parse_vulhub_readme(cve_id, path, content)
    base["extraction_status"] = state
    base["observable_families"] = ";".join(families)
    base["event_types"] = ";".join(sorted(set(e for f in families for e in VULHUB_OBSERVABLE_CATALOG[f]["events"])))
    base["sensor_candidates"] = ";".join(sorted(set(s for f in families for s in VULHUB_OBSERVABLE_CATALOG[f]["sensors"])))
    base["required_fields"] = ";".join(sorted(set(fld for f in families for fld in VULHUB_OBSERVABLE_CATALOG[f]["fields"])))
    base["evidence"] = json.dumps(evidences, ensure_ascii=False)
    base["limitations"] = " | ".join(VULHUB_OBSERVABLE_CATALOG[f]["caveat"] for f in families)
    # Explicitly mark path-based inferences for source-level checking.
    if any(e.get("behavior") == "file_access" for e in evidences):
        base["review_required"] = "yes"
        base["limitations"] += " | Verificare che il file sia letto dal processo vulnerabile, non dall'attaccante."
    return base
