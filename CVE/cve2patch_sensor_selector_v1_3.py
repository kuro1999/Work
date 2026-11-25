#!/usr/bin/env python3
"""CVE2Patch — Sensor Selector v1.3 (documentale, Linux host-level; matrice minimal).

Input: il dataset consolidato output/initial_pool.csv NON viene modificato.
Fonti: dati NVD dal CSV; regole Falco/Elastic; README Vulhub; file PoC GitHub/Vulhub.
Sigma e' conservato nel CSV ma non partecipa alla selezione predefinita.

Output in output/:
  sensor_matrix_v1_3.csv        (9 colonne, una riga per CVE)
  sensor_summary_v1_3.json      (riepilogo)
  sensor_dettagli_v1_3/         (file tecnici separati)
  sensor_rule_cache/ e sensor_vulhub_cache/

Nessun PoC eseguito. Nessuna detection validata. Richiede Python >=3.11,
PyYAML (python -m pip install pyyaml) e Internet soltanto per i download iniziali.
"""
from __future__ import annotations

import argparse
import ast
import os
import csv
from concurrent.futures import ThreadPoolExecutor
import threading
import hashlib
import json
import re
import sys
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, quote

try:
    import yaml
except ImportError:
    sys.exit("Manca PyYAML. Installa con: python -m pip install pyyaml")

VERSION = "1.2.3"
USER_AGENT = "CVE2Patch-Sensor-Selector/1.2.3 (academic observability analysis)"
MAX_BYTES = 4 * 1024 * 1024

# Questi sono indizi TESTUALI sul comportamento. Non implicano eventi concreti.
BEHAVIOR_PATTERNS = {
    "command_execution": [
        r"\bcommand injection\b", r"\bremote command execution\b",
        r"\bos commands?\b", r"\bshell commands?\b",
        r"\bexecut(?:e|ion of) (?:arbitrary )?(?:system |os |shell )?commands?\b",
        r"\bcommand execution\b", r"\brun (?:arbitrary |system |shell )?commands?\b",
    ],
    "file_write": [
        r"\barbitrary file upload\b", r"\barbitrary file write\b",
        r"\bfile upload vulnerabilit", r"\bupload (?:an? |a malicious |arbitrary )?file\b",
        r"\bwrite arbitrary files?\b", r"\bfile creation\b",
        r"\boverwrite (?:the |an? )?(?:host |target |system )?(?:binary|file|executable)\b",
    ],
    "file_access": [
        r"\bpath traversal\b", r"\bdirectory traversal\b",
        r"\bread arbitrary files?\b", r"\barbitrary file read\b",
        r"\blocal file inclusion\b", r"\bfile disclosure\b",
    ],
    "privilege_escalation": [
        r"\bprivilege escalation\b", r"\bescalat(?:e|ion|ing) (?:\w+ )?privileges\b",
        r"\bgain root (?:privileges|access)\b", r"\bobtain root access\b",
    ],
    "authentication_bypass": [
        r"\bauthentication bypass\b", r"\bbypass (?:the )?authentication\b",
        r"\bunauthorized access\b",
    ],
    "code_execution_generic": [
        r"\barbitrary code execution\b", r"\bremote code execution\b",
        r"\bexecute arbitrary code\b", r"\bexecution of arbitrary code\b",
    ],
}
COMPILED = {k: [re.compile(p, re.I) for p in values] for k, values in BEHAVIOR_PATTERNS.items()}
DESC_MAP = {"command_execution": "process_execution_hypothesis",
            "file_write": "file_write_hypothesis", "file_access": "file_access_hypothesis"}

# Mappatura prudente tra logsource/eventi e possibili sorgenti di telemetria.
# E' un CATALOGO di candidati da verificare, non un elenco di sensori installati.
SIGMA_FAMILY = {
    "process_creation": ("process_execution", "linux_process_telemetry"),
    "process_access": ("process_access", "linux_process_telemetry"),
    "file_event": ("file_activity", "filesystem_event_collector"),
    "file_change": ("file_activity", "filesystem_event_collector"),
    "file_access": ("file_access", "filesystem_event_collector"),
    "webserver": ("http_request_log", "webserver_log_collector"),
    "network_connection": ("network_connection", "network_telemetry_collector"),
    "dns_query": ("dns_query", "dns_log_collector"),
    "proxy": ("http_proxy_log", "proxy_log_collector"),
}
# Perimetro tesi: sensori LATO SISTEMA, anche se il vettore della CVE e' NETWORK.
# Non confondere i log HTTP con eventi di kernel/endpoint.
HOST_SCOPES = {"host_kernel", "host_endpoint", "host_log"}
NON_HOST_SCOPES = {"application_log", "network_log"}
CONCRETE_HOST_SENSOR_CANDIDATES = {"falco_modern_ebpf", "elastic_defend", "auditd_log_collector"}

ELASTIC_FAMILY = {
    "process": "process_activity", "file": "file_activity",
    "network": "network_activity", "authentication": "authentication_event",
    "registry": "registry_event", "dns": "dns_event",
}
FALCO_FIELD = re.compile(r"\b(?:evt|proc|fd|user|group|container|fs|thread|k8s|ka|jevt)\.[a-zA-Z_][\w.]*(?:\[\d+\])?")
ECS_FIELD = re.compile(r"\b(?:process|file|event|host|user|group|container|network|source|destination|dns|auditd|data_stream)\.[A-Za-z_][\w.]*")


def uniq(xs):
    return list(dict.fromkeys(x for x in xs if x))


def csv_items(raw):
    try:
        parsed = json.loads(raw or "[]")
        return [str(s) for s in parsed] if isinstance(parsed, list) else []
    except (ValueError, TypeError):
        return []


def norm_name(name):
    return " ".join(str(name).casefold().split())


def evidence_from_description(description):
    matched = {}
    for label, patterns in COMPILED.items():
        found = sorted(set(m.group(0) for p in patterns for m in p.finditer(description)), key=str.casefold)
        if found:
            matched[label] = found
    return matched


def default_input():
    base = Path(__file__).resolve().parent
    cwd = Path.cwd().resolve()
    for root in uniq([base, base / "CVE2Patch", cwd, cwd / "CVE2Patch", base.parent / "CVE2Patch"]):
        candidate = root / "output" / "initial_pool.csv"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "Non trovo output/initial_pool.csv. Metti questo script in CVE2Patch o nella "
        "cartella CVE, oppure usa --input CVE2Patch/output/initial_pool.csv"
    )


def github_raw_url(public_url, repo_expected):
    """Accetta SOLO riferimenti GitHub nei tre repository noti (no SSRF)."""
    p = urlsplit(public_url)
    if p.scheme != "https" or p.netloc.lower() != "github.com":
        raise ValueError("Sorgente non autorizzata (richiesto github.com via HTTPS)")
    pieces = p.path.strip("/").split("/")
    owner, repo = repo_expected.split("/")
    if (len(pieces) < 5 or pieces[0].lower() != owner.lower()
            or pieces[1].lower() != repo.lower() or pieces[2] != "blob"):
        raise ValueError("URL non corrispondente al repository previsto")
    branch = pieces[3]
    tail = pieces[4:]
    if branch not in ("main", "master") or not tail or any(x in (".", "..", "") for x in tail):
        raise ValueError("Branch o percorso non supportato")
    if not tail[-1].endswith((".yaml", ".yml", ".toml")):
        raise ValueError("Il link non punta a una regola YAML/TOML")
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/" + "/".join(tail)


class RuleCache:
    def __init__(self, folder, *, offline=False, refresh=False, timeout=15):
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self.refresh = refresh
        self.timeout = timeout
        self.memo = {}
        self.stats = Counter()
        self.lock = threading.Lock()

    def get(self, url, repo):
        try:
            raw_url = github_raw_url(url, repo)
        except ValueError as exc:
            return None, "invalid_url: " + str(exc), ""
        with self.lock:
            if raw_url in self.memo:
                return self.memo[raw_url]
        key = hashlib.sha256(raw_url.encode("utf-8")).hexdigest()
        suffix = ".toml" if raw_url.endswith(".toml") else ".yaml"
        path = self.folder / (key + suffix)
        if path.is_file() and not self.refresh:
            try:
                content = path.read_bytes()
                if len(content) > MAX_BYTES:
                    raise ValueError("cache troppo grande")
                with self.lock: self.stats["from_cache"] += 1
                out = (content.decode("utf-8-sig"), "", hashlib.sha256(content).hexdigest())
            except (UnicodeError, OSError, ValueError) as exc:
                out = (None, "cache_error: " + str(exc), "")
        elif self.offline:
            with self.lock: self.stats["cache_miss"] += 1
            out = (None, "offline_cache_missing", "")
        else:
            try:
                req = urllib.request.Request(raw_url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    # Non seguire redirect verso host sconosciuti: ricontrolliamo il finale.
                    final = urlsplit(response.url)
                    if final.scheme != "https" or final.netloc.lower() != "raw.githubusercontent.com":
                        raise ValueError("Redirect verso host non autorizzato")
                    content = response.read(MAX_BYTES + 1)
                if len(content) > MAX_BYTES:
                    raise ValueError("File remoto troppo grande")
                text = content.decode("utf-8-sig")
                path.write_bytes(content)
                with self.lock: self.stats["downloaded"] += 1
                out = (text, "", hashlib.sha256(content).hexdigest())
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeError) as exc:
                with self.lock: self.stats["fetch_error"] += 1
                out = (None, "fetch_error: " + str(exc)[:220], "")
        with self.lock:
            self.memo[raw_url] = out
        return out

    def prefetch(self, rule_sources):
        """Scarica una volta per URL e in parallelo (rapido anche se GitHub non risponde)."""
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda pair: self.get(*pair), rule_sources))


def sigma_fields(tree):
    """Estrae campi da selettori e filtri, non dalle parole chiave libere."""
    result = []
    if isinstance(tree, dict):
        for k, v in tree.items():
            if k in ("condition", "timeframe"):
                continue
            if isinstance(v, dict):
                for field, val in v.items():
                    result.append(str(field).split("|")[0] if field is not None else "")
                    if isinstance(val, (dict, list)):
                        result.extend(sigma_fields(val))
            elif isinstance(v, list):
                for obj in v:
                    if isinstance(obj, dict):
                        result.extend(sigma_fields({"selector": obj}))
    return sorted(set(x for x in result if x))


def sigma_scope(category, product, service):
    if product == "windows":
        return "non_linux"
    if category == "webserver":
        return "application_log"
    if category in ("proxy", "dns_query"):
        return "network_log"
    if category == "network_connection":
        return "host_endpoint" if product == "linux" else "unknown"
    if category in ("process_creation", "process_access", "file_event", "file_change", "file_access"):
        return "host_endpoint"  # logsource logico: non prova un sensore installato
    if product == "linux" and (service in ("auth", "sshd", "auditd") or category == "authentication"):
        return "host_log"
    return "unknown"


def extract_esql_categories(query):
    """Supporto minimo per filtri espliciti ES|QL e indici endpoint; non un parser completo."""
    cats = []
    # WHERE event.category == "process", oppure event.category IN ("process", ...)
    pattern = r'\bevent\.category\s*(?:==|=|:)\s*[\'"](process|file|network|authentication|dns)[\'"]'
    cats += [m.group(1).lower() for m in re.finditer(pattern, query, re.I)]
    for m in re.finditer(r'\bevent\.category\s+IN\s*\(([^)]*)\)', query, re.I):
        cats += [x.lower() for x in re.findall(r'[\'"](process|file|network|authentication|dns)[\'"]', m.group(1), re.I)]
    # FROM logs-endpoint.events.process-* documenta il tipo di sorgente
    for m in re.finditer(r'\blogs-endpoint\.events\.(process|file|network)[\w*.-]*', query, re.I):
        cats.append(m.group(1).lower())
    return uniq(cats)


def parse_sigma(text, rule_id, expected_name):
    docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    matches = [d for d in docs if str(d.get("id", "")) == rule_id] if rule_id else []
    if not matches:
        matches = [d for d in docs if norm_name(d.get("title", "")) == norm_name(expected_name)]
    if len(matches) != 1:
        raise ValueError("sigma_rule_not_found_or_ambiguous")
    d = matches[0]
    ls = d.get("logsource") or {}
    ls = ls if isinstance(ls, dict) else {}
    category = str(ls.get("category") or "").lower()
    service = str(ls.get("service") or "").lower()
    product = str(ls.get("product") or "").lower()
    family, sensor = SIGMA_FAMILY.get(category, ("unknown", "undetermined"))
    scope = sigma_scope(category, product, service)
    if product == "linux" and service in ("auth", "sshd"):
        family, sensor = "linux_auth_log", "linux_auth_log_collector"
    if "auditd" in service:
        sensor = "auditd_log_collector"
    if product == "windows" and sensor == "linux_process_telemetry":
        sensor = "windows_process_telemetry"
    fields = sigma_fields(d.get("detection") or {})
    notes = ["Sigma descrive il logsource, non un sensore installato; richiede field mapping."]
    if family == "unknown":
        notes.append("Logsource non mappato: necessaria revisione manuale.")
    return {
        "rule_name": str(d.get("title", expected_name)), "rule_enabled": "not_applicable",
        "event_families": [family] if family != "unknown" else [],
        "event_types": ["logsource:" + "/".join(x for x in [product, category, service] if x)],
        "required_fields": fields, "sensor_candidates": [sensor] if sensor != "undetermined" else [],
        "source_context": json.dumps(ls, sort_keys=True, ensure_ascii=False),
        "telemetry_scope": scope,
        "notes": " ".join(notes), "extraction_status": "parsed" if family != "unknown" else "partial",
    }


def falco_event_types(expression):
    vals = []
    for m in re.finditer(r"\bevt\.type\s*(?:=|==|in)\s*(\([^)]*\)|[a-zA-Z0-9_]+)", expression):
        rhs = m.group(1).strip("() ")
        vals += re.findall(r"\b[a-zA-Z][a-zA-Z0-9_]*\b", rhs)
    return sorted(set(vals))


def expand_falco_macros(cond, macros, depth=0, visited=frozenset()):
    """Espande solo le macro dichiarate nello stesso file; non importa macro esterne."""
    if depth >= 8:
        return cond
    out = cond
    for name, expression in macros.items():
        if name in visited or not expression:
            continue
        if re.search(r"\b" + re.escape(name) + r"\b", out):
            child = expand_falco_macros(expression, macros, depth + 1, visited | {name})
            out = re.sub(r"\b" + re.escape(name) + r"\b", lambda _: "(" + child + ")", out)
    return out


def parse_falco(text, rule_id, expected_name):
    docs = [d for d in yaml.safe_load_all(text) if isinstance(d, (dict, list))]
    items = []
    for doc in docs:
        items.extend(doc if isinstance(doc, list) else [doc])
    macros = {str(x["macro"]): str(x.get("condition", "")) for x in items
              if isinstance(x, dict) and x.get("macro")}
    rules = [x for x in items if isinstance(x, dict) and x.get("rule")]
    matches = [r for r in rules if norm_name(r.get("rule", "")) == norm_name(expected_name)]
    # Non cercare una CVE nell'intero file: il file sandbox contiene molte regole.
    if len(matches) != 1:
        raise ValueError("falco_rule_not_found_or_ambiguous")
    rule = matches[0]
    original = str(rule.get("condition") or "")
    expanded = expand_falco_macros(original, macros)
    fields = sorted(set(FALCO_FIELD.findall(expanded)))
    events = falco_event_types(expanded)
    families = []
    if set(events) & {"execve", "execveat"} or re.search(r"\bspawned_process\b", expanded):
        families.append("process_execution")
    if set(events) & {"open", "openat", "openat2", "write", "writev", "unlink", "rename"}:
        families.append("file_activity")
    if "evt.buffer" in fields:
        families.append("buffer_content")
    if set(events) & {"setuid", "setreuid", "setresuid", "capset"}:
        families.append("privilege_change")
    notes = []
    if not events:
        notes.append("Syscall specifiche non esplicite: controllare macro dipendenti da altri file.")
    if rule.get("enabled") is False:
        notes.append("Regola dichiarata disabilitata.")
    source = str(rule.get("source") or "syscall")
    if source != "syscall":
        notes.append("Sorgente plugin/non-syscall: verificare meccanismo di raccolta.")
    return {
        "rule_name": str(rule.get("rule")),
        "rule_enabled": "false" if rule.get("enabled") is False else "true_or_unspecified",
        "event_families": uniq(families), "event_types": events,
        "required_fields": fields,
        "sensor_candidates": ["falco_modern_ebpf"] if source == "syscall" else ["falco_plugin:" + source],
        "source_context": source,
        "telemetry_scope": "host_kernel" if source == "syscall" else "unknown",
        "notes": " ".join(notes) if notes else "Presenza dei campi non verifica efficacia o specificita' CVE.",
        "extraction_status": "parsed" if events or families else "partial",
    }


def parse_elastic(text, rule_id, expected_name):
    doc = tomllib.loads(text)
    d = doc.get("rule") or {}
    if not isinstance(d, dict):
        raise ValueError("elastic_rule_invalid")
    if rule_id and str(d.get("rule_id", "")) != rule_id:
        # Non attribuire alla CVE una regola non verificata: gli ID possono cambiare
        # su main/master oppure essere stati associati male nel dataset.
        raise ValueError("elastic_rule_id_mismatch")
    if not rule_id and norm_name(d.get("name", "")) != norm_name(expected_name):
        raise ValueError("elastic_rule_name_mismatch")
    query = str(d.get("query") or "")
    language = str(d.get("language") or "").lower()
    indices = [str(x) for x in d.get("index", []) if isinstance(x, str)]
    intgs = d.get("related_integrations") or []
    integrations = [x.get("package") for x in intgs if isinstance(x, dict) and x.get("package")]
    event_categories = re.findall(r"\b(process|file|network|authentication|registry|dns)\s+where\b", query, re.I)
    # In EQL un blocco 'sequence ... [process where ...]' e' incluso nel pattern.
    # ES|QL usa una sintassi diversa e spesso parte da FROM logs-endpoint.events...
    if language in ("esql", "es|ql"):
        event_categories += extract_esql_categories(query)
    event_categories = uniq([c.lower() for c in event_categories])
    families = sorted(set(ELASTIC_FAMILY[c] for c in event_categories if c in ELASTIC_FAMILY))
    fields = sorted(set(ECS_FIELD.findall(query)))
    for el in d.get("required_fields", []):
        if isinstance(el, dict) and isinstance(el.get("name"), str):
            fields.append(el["name"])
    fields = sorted(set(fields))
    sensors = []
    all_context = " ".join(indices + [str(x) for x in integrations] + [query]).lower()
    if re.search(r"\bendpoint\b|logs-endpoint|endpoint\.events", all_context):
        sensors.append("elastic_defend")
    if re.search(r"\bauditd\b|auditbeat|logs-auditd", all_context):
        sensors.append("auditd_log_collector")
    # Senza integrazione/indice non forziamo Elastic Defend.
    if any(c in ("process", "file") for c in event_categories):
        scope = "host_endpoint"
    elif "network" in event_categories and "elastic_defend" in sensors:
        scope = "host_endpoint"
    elif "authentication" in event_categories:
        scope = "host_log"
    else:
        # Evento network senza integrazione endpoint: non sappiamo se sia host o rete.
        scope = "unknown"
    notes = ["Regola Elastic: sensor compatibile dipende da integrazioni e indici configurati."]
    if not families:
        notes.append("Evento non identificabile dal pattern EQL semplificato; verifica manuale.")
    if not sensors:
        notes.append("Sorgente concreta non determinata da index/related_integrations.")
    return {
        "rule_name": str(d.get("name") or expected_name),
        "rule_enabled": "not_applicable", "event_families": families,
        "event_types": ["eql:" + c.lower() for c in uniq(event_categories)],
        "required_fields": fields, "sensor_candidates": sensors,
        "source_context": json.dumps({"language": language, "index": indices,
                                       "related_integrations": integrations}, ensure_ascii=False, sort_keys=True),
        "telemetry_scope": scope,
        "notes": " ".join(notes),
        "extraction_status": "parsed" if families else "partial",
    }


SOURCES = {
    "falco": ("falcosecurity/rules", "falco_rule_urls", "falco_rules", None, parse_falco),
    "sigma": ("SigmaHQ/sigma", "sigma_rule_urls", "sigma_rules", "sigma_rule_ids", parse_sigma),
    "elastic": ("elastic/detection-rules", "elastic_rule_urls", "elastic_rules", "elastic_rule_ids", parse_elastic),
}


def inspect_rule(cve_id, source, rule_url, rule_name, rule_id, cache):
    repo, _, _, _, parser = SOURCES[source]
    base = {
        "cve_id": cve_id, "repository": source, "referenced_rule_name": rule_name,
        "rule_id": rule_id, "rule_url": rule_url, "rule_name": "",
        "rule_enabled": "", "event_families": "", "event_types": "",
        "required_fields": "", "sensor_candidates": "", "source_context": "",
        "telemetry_scope": "unknown",
        "extraction_status": "", "notes": "", "file_sha256": "",
    }
    content, error, digest = cache.get(rule_url, repo)
    base["file_sha256"] = digest
    if error:
        base["extraction_status"] = "unavailable"
        base["notes"] = error
        return base
    try:
        parsed = parser(content, rule_id, rule_name)
        for k in ("event_families", "event_types", "required_fields", "sensor_candidates"):
            base[k] = ";".join(parsed[k])
        for k in ("rule_name", "rule_enabled", "source_context", "telemetry_scope", "notes", "extraction_status"):
            base[k] = parsed[k]
    except (ValueError, TypeError, KeyError, yaml.YAMLError) as exc:
        # Mismatch identita' != errore di parsing: non selezioniamo la regola.
        base["extraction_status"] = "identity_mismatch" if "_id_mismatch" in str(exc) else "parse_error"
        base["notes"] = f"{type(exc).__name__}: {str(exc)[:250]}"
    return base


def aggregate_cve(row, rule_rows):
    matches = evidence_from_description(row.get("description", ""))
    desc = sorted(set(DESC_MAP[k] for k in matches if k in DESC_MAP))
    good = [r for r in rule_rows if r["extraction_status"] in ("parsed", "partial")]
    host_rules = [r for r in good if r["telemetry_scope"] in HOST_SCOPES]
    nonhost_rules = [r for r in good if r["telemetry_scope"] in NON_HOST_SCOPES]
    fam = sorted(set(x for r in good for x in r["event_families"].split(";") if x))
    evts = sorted(set(x for r in good for x in r["event_types"].split(";") if x))
    fields = sorted(set(x for r in good for x in r["required_fields"].split(";") if x))
    sensors = sorted(set(x for r in good for x in r["sensor_candidates"].split(";") if x))
    host_sensors = sorted(set(x for r in host_rules for x in r["sensor_candidates"].split(";") if x))
    concrete_sensors = sorted(set(host_sensors) & CONCRETE_HOST_SENSOR_CANDIDATES)
    scopes = sorted(set(r["telemetry_scope"] for r in good))
    rule_formats = sorted(set(r["repository"] for r in good))
    engines = sorted(set({"falco": "falco", "elastic": "elastic_security"}[r["repository"]]
                         for r in good if r["repository"] in ("falco", "elastic")))

    # Priorita' alla presenza documentata di telemetria host, NON alla marca del motore.
    if host_rules and concrete_sensors:
        status = "host_sensor_candidate"
        explanation = "Regola host: sorgente e sensore candidato identificati; raccolta non verificata."
    elif host_rules:
        status = "host_telemetry_source_only"
        explanation = "Regola host: sorgente/logsource identificato, sensore concreto da definire."
    elif nonhost_rules:
        status = "non_host_rule_only"
        explanation = "Regole disponibili solo per log applicativi/proxy: nessuna selezione host giustificata."
    elif desc:
        status = "description_hypothesis_only"
        explanation = "Descrizione indica un possibile comportamento; nessuna telemetria host confermata."
    else:
        status = "insufficient_evidence"
        explanation = "Nessun osservabile host identificabile dalle fonti analizzate."
    if str(row.get("kernel", "")).lower() == "true":
        status = "out_of_initial_scope"
        explanation = "CVE kernel esclusa dal perimetro userland iniziale."

    if host_rules:
        next_action = "Verificare campi/eventi e disponibilita' del sensore nell'ambiente Linux."
    elif nonhost_rules:
        next_action = "Valutare separatamente se advisory/PoC mostrano effetti host; non convertire log HTTP in syscall."
    elif desc:
        next_action = "Consultare PoC o advisory: la descrizione non determina una syscall."
    else:
        next_action = "Evidenze insufficienti: revisione mirata di advisory/PoC, senza selezione forzata."

    return {
        "cve_id": row["cve_id"], "attack_vector": row.get("attack_vector", ""),
        "platform_basis": row.get("platform_basis", ""),
        "description_behaviors": ";".join(sorted(matches)),
        "description_evidence": json.dumps(matches, ensure_ascii=False, sort_keys=True),
        "description_observable_hypotheses": ";".join(desc),
        "rule_count_referenced": len(rule_rows),
        "rule_count_parsed": sum(r["extraction_status"] == "parsed" for r in rule_rows),
        "rule_count_partial": sum(r["extraction_status"] == "partial" for r in rule_rows),
        "rule_count_unavailable": sum(r["extraction_status"] in ("unavailable", "parse_error", "identity_mismatch") for r in rule_rows),
        "rule_event_families": ";".join(fam),
        "rule_event_types": ";".join(evts),
        "rule_required_fields": ";".join(fields),
        "rule_sensor_candidates": ";".join(sensors),
        "rule_formats": ";".join(rule_formats),
        "rule_detection_engines": ";".join(engines),
        "evidence_rule_urls": json.dumps(uniq(r["rule_url"] for r in good), ensure_ascii=False),
        "telemetry_scopes": ";".join(scopes),
        "host_event_families": ";".join(sorted(set(x for r in host_rules for x in r["event_families"].split(";") if x))),
        "host_required_fields": ";".join(sorted(set(x for r in host_rules for x in r["required_fields"].split(";") if x))),
        "host_sensor_candidates": ";".join(host_sensors),
        "concrete_host_sensor_candidates": ";".join(concrete_sensors),
        "non_host_telemetry": ";".join(sorted(set(r["telemetry_scope"] for r in nonhost_rules))),
        "selection_status": status, "selection_reason": explanation,
        "next_action": next_action,
        "verification_status": "not_tested",
    }


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError("Nessun risultato da scrivere")
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# V1.2: evidenze documentali NVD + README Vulhub.
# Nessun PoC viene eseguito; le descrizioni RCE generiche NON implicano execve.
# Sigma resta nel dataset, ma per default e' ESCLUSO dalla selezione attiva.
# ---------------------------------------------------------------------------

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

# Pattern intenzionalmente ristretti: richieste exploit con un meccanismo
# esplicito di esecuzione di un comando nel processo vulnerabile.
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


def safe_vulhub_readme_url(path: str) -> str:
    """Evita path traversal/SSRF; la sorgente e' sempre il repository Vulhub."""
    parts = str(path).split("/")
    if len(parts) != 2 or any(not re.fullmatch(r"[A-Za-z0-9._-]+", p) or p in (".", "..") for p in parts):
        raise ValueError("Percorso Vulhub non supportato")
    return f"https://raw.githubusercontent.com/vulhub/vulhub/master/{parts[0]}/{parts[1]}/README.md"


class VulhubCache:
    def __init__(self, folder: Path, *, offline=False, refresh=False, timeout=12):
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)
        self.offline, self.refresh, self.timeout = offline, refresh, timeout
        self.memo = {}
        self.stats = Counter()
        self.lock = threading.Lock()

    def get(self, path):
        try:
            url = safe_vulhub_readme_url(path)
        except ValueError as exc:
            return None, f"invalid_path: {exc}", ""
        with self.lock:
            if url in self.memo:
                return self.memo[url]
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        cache_file = self.folder / (key + ".md")
        if cache_file.is_file() and not self.refresh:
            try:
                body = cache_file.read_bytes()
                if len(body) > MAX_BYTES:
                    raise ValueError("README in cache troppo grande")
                value = (body.decode("utf-8-sig"), "", hashlib.sha256(body).hexdigest())
                with self.lock:
                    self.stats["from_cache"] += 1
            except (OSError, ValueError, UnicodeError) as exc:
                value = (None, "cache_error: " + str(exc), "")
        elif self.offline:
            with self.lock:
                self.stats["cache_miss"] += 1
            value = (None, "offline_cache_missing", "")
        else:
            try:
                request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    final_url = urlsplit(response.url)
                    if final_url.scheme != "https" or final_url.netloc.lower() != "raw.githubusercontent.com":
                        raise ValueError("Redirect verso host non autorizzato")
                    body = response.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise ValueError("README remoto troppo grande")
                decoded = body.decode("utf-8-sig")
                cache_file.write_bytes(body)
                with self.lock:
                    self.stats["downloaded"] += 1
                value = (decoded, "", hashlib.sha256(body).hexdigest())
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                    OSError, ValueError, UnicodeError) as exc:
                with self.lock:
                    self.stats["fetch_error"] += 1
                value = (None, "fetch_error: " + str(exc)[:200], "")
        with self.lock:
            self.memo[url] = value
        return value

    def prefetch(self, paths):
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(self.get, paths))


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


# A positive result requires explicit attack-section evidence; a generic NVD RCE,
# a path occurring anywhere in the README, or a setup command is never enough.
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


def nvd_snapshot_context(row):
    """NVD e' gia' nella selezione CVE: non lo riscarichiamo, non inferiamo syscall da CWE/CVSS."""
    try:
        raw_details = json.loads(row.get("reference_details") or "[]")
        details = raw_details if isinstance(raw_details, list) else []
    except (TypeError, ValueError):
        details = []
    tagged_exploits = [str(x.get("url")) for x in details
                       if isinstance(x, dict) and "Exploit" in (x.get("tags") or []) and x.get("url")]
    return {"nvd_description": row.get("description", ""),
            "nvd_cwe": row.get("cwe", "[]"),
            "nvd_reference_count": len(csv_items(row.get("references", ""))),
            "nvd_exploit_reference_count": len(tagged_exploits),
            "nvd_tagged_exploit_urls": json.dumps(tagged_exploits[:4], ensure_ascii=False)}


def integrate_vulhub(row, rule_rows, vulhub_rows):
    """Seleziona il sensore in base all'evento documentato, NON al repository della regola."""
    baseline = aggregate_cve(row, rule_rows)
    parsed = [r for r in vulhub_rows if r["extraction_status"] == "observable_documented"]
    doc_families = sorted(set(x for r in parsed for x in r["observable_families"].split(";") if x))
    doc_events = sorted(set(x for r in parsed for x in r["event_types"].split(";") if x))
    doc_sensors = sorted(set(x for r in parsed for x in r["sensor_candidates"].split(";") if x))
    doc_fields = sorted(set(x for r in parsed for x in r["required_fields"].split(";") if x))
    rule_candidates = [x for x in baseline["concrete_host_sensor_candidates"].split(";") if x]
    total_sensors = sorted(set(doc_sensors + rule_candidates))
    had_concrete_before = bool(rule_candidates)
    if total_sensors and doc_sensors and had_concrete_before:
        current_status = "host_sensor_candidate_rules_and_vulhub"
    elif doc_sensors and not had_concrete_before:
        current_status = "host_sensor_candidate_from_vulhub"
    else:
        current_status = baseline["selection_status"]
    # Un percorso sensibile nel payload HTTP non prova che il processo server
    # abbia eseguito open/openat. Se questa e' l'unica evidenza host, la
    # selezione resta DA VERIFICARE, non un candidato documentato.
    file_only_needs_review = (
        any(r.get("review_required") == "yes" for r in parsed)
        and "process_execution" not in doc_families
        and not had_concrete_before
    )
    if file_only_needs_review and current_status == "host_sensor_candidate_from_vulhub":
        current_status = "file_access_review_required"
    if str(row.get("kernel", "")).lower() == "true":
        current_status = "out_of_initial_scope"
        total_sensors = []
    changed = (bool(doc_sensors) and not had_concrete_before
               and current_status not in ("out_of_initial_scope", "file_access_review_required"))
    base = dict(baseline)
    nvd_context = nvd_snapshot_context(row)
    base.update({
        "nvd_cwe": row.get("cwe", "[]"),
        "nvd_reference_count": nvd_context["nvd_reference_count"],
        "nvd_exploit_reference_count": nvd_context["nvd_exploit_reference_count"],
        "vulhub_reference_count": len(vulhub_rows),
        "vulhub_readme_observed_count": len(parsed),
        "vulhub_readme_statuses": ";".join(sorted(set(r["extraction_status"] for r in vulhub_rows))),
        "vulhub_observable_families": ";".join(doc_families),
        "vulhub_event_hypotheses": ";".join(doc_events),
        "vulhub_required_fields_examples": ";".join(doc_fields),
        "vulhub_sensor_candidates": ";".join(doc_sensors),
        "vulhub_evidence": json.dumps([{"url": r["readme_url"], "evidence": json.loads(r["evidence"])} for r in parsed], ensure_ascii=False),
        "vulhub_review_required": "yes" if any(r["review_required"] == "yes" for r in parsed) else "no",
        "sensor_candidates_active": ";".join(total_sensors),
        "selection_status_before_vulhub": baseline["selection_status"],
        "selection_status": current_status,
        "new_host_candidate_from_vulhub": "yes" if changed else "no",
        "verification_status": "not_tested",
    })
    if doc_sensors:
        base["selection_reason"] = ("README Vulhub: pattern concreto nella sezione di exploit; "
                                    "sensori candidati per capacita' dell'evento, senza verifica sperimentale.")
        base["next_action"] = "Controllare estratto, contesto e processo bersaglio, senza eseguire il PoC."
    # A non-match is not a claim that the CVE is undetectable. Explain exactly
    # which input was missing or was too generic for this conservative parser.
    if base["selection_status"] in ("insufficient_evidence", "description_hypothesis_only"):
        if not vulhub_rows:
            missing_reason = "no_vulhub_reference"
            source_next = "advisory_from_nvd_references"
        elif any(r["extraction_status"] == "no_attack_section" for r in vulhub_rows):
            missing_reason = "vulhub_attack_section_unrecognized"
            source_next = "readme_manual_review"
        elif any(r["extraction_status"] in ("unavailable", "identity_mismatch", "identity_unverified") for r in vulhub_rows):
            missing_reason = "vulhub_unavailable_or_identity_unverified"
            source_next = "vulhub_source_or_advisory"
        else:
            missing_reason = "no_explicit_host_pattern_recognized"
            source_next = "review_vulhub_poc_then_advisory"
        if base["selection_status"] == "description_hypothesis_only":
            missing_reason += ";description_only_generic"
    else:
        missing_reason = ""
        source_next = ""
    base["missing_evidence_reason"] = missing_reason
    base["suggested_next_source"] = source_next
    return base



# ---------------------------------------------------------------------------
# V1.3: proiezione MINIMA per l'utente. Le informazioni ricche rimangono
# disponibili SOLO nei dettagli tecnici, non nella matrice principale.
# ---------------------------------------------------------------------------
MATRIX_COLUMNS = [
    "cve_id", "comportamento", "osservabile_evento", "campi_necessari",
    "sensore_candidato", "fonte", "link_fonte", "stato", "nota",
]

BEHAVIOR_LABELS = {
    "command_execution": "esecuzione comandi",
    "code_execution_generic": "esecuzione codice generica",
    "file_write": "scrittura file",
    "file_access": "accesso file",
    "privilege_escalation": "escalation privilegi",
    "authentication_bypass": "bypass autenticazione",
    "process_execution": "esecuzione processo",
    "process_activity": "attivita processo",
    "file_activity": "attivita file",
    "network_activity": "attivita rete",
    "authentication_event": "evento autenticazione",
    "linux_auth_log": "log autenticazione Linux",
    "privilege_change": "modifica privilegi",
    "buffer_content": "contenuto buffer",
}

MISSING_NOTES = {
    "no_vulhub_reference": "Nessun README Vulhub associato; consultare advisory.",
    "vulhub_attack_section_unrecognized": "README presente ma sezione exploit non riconosciuta.",
    "vulhub_unavailable_or_identity_unverified": "README non disponibile o associazione CVE non verificata.",
    "no_explicit_host_pattern_recognized": "Nessun evento host esplicito riconosciuto nel README.",
}



# Vocabolario SEMANTICO comune: l'output breve non deve mescolare
# i nomi delle API Falco (proc.*) con quelli ECS Elastic (process.*).
# I nomi tecnici originali rimangono in sensor_dettagli_v1_3/.
NEUTRAL_FIELD_NAMES = {
    "evt.type": "tipo evento", "event.type": "tipo evento",
    "event.action": "azione evento", "event.category": "categoria evento",
    "evt.is_open_write": "apertura in scrittura", "evt.arg.flags": "flag operazione",
    "proc.name": "nome processo", "process.name": "nome processo",
    "proc.exe": "percorso eseguibile", "proc.exepath": "percorso eseguibile",
    "process.executable": "percorso eseguibile",
    "proc.cmdline": "riga di comando", "process.command_line": "riga di comando",
    "proc.args": "argomenti processo", "process.args": "argomenti processo",
    "proc.pname": "nome processo padre", "process.parent.name": "nome processo padre",
    "process.parent": "processo padre",
    "process.parent.executable": "percorso processo padre",
    "process.parent.command_line": "riga di comando del padre",
    "process.parent.entity_id": "ID processo padre",
    "process.entity_id": "ID processo",
    "proc.pid": "PID processo", "proc.ppid": "PID processo padre",
    "fd.name": "percorso file", "file.path": "percorso file",
    "file.name": "nome file", "file.extension": "estensione file",
    "fd.num": "descrittore file", "fd.type": "tipo descrittore file",
    "fd.typechar": "tipo descrittore file",
    "evt.buffer": "contenuto buffer",
    "process.env_vars": "variabili d'ambiente",
    "user.loginuid": "utente di login", "user.uid": "ID utente",
    "user.id": "ID utente", "user.name": "nome utente",
    "user.domain": "dominio utente", "host.os.type": "sistema operativo",
    "host.id": "ID host", "host.name": "nome host",
    "container.id": "ID container",
    "data_stream.dataset": "origine dati", "data_stream.namespace": "namespace dati",
    "process.working_directory": "directory di lavoro",
}


def neutral_required_fields(fields):
    """Normalizza solo i campi noti. Quelli non mappati non sono inventati.

    Il testo grezzo resta nei dettagli: segnaliamo i campi sconosciuti
    invece di mostrarli con una sintassi propria di un prodotto.
    """
    distinct = set()
    unknown = set()
    for value in fields:
        value = str(value).strip()
        if not value:
            continue
        label = NEUTRAL_FIELD_NAMES.get(value)
        if label:
            distinct.add(label)
        else:
            unknown.add(value)
    if unknown:
        distinct.add("altri campi specifici (vedi dettagli)")
    return "; ".join(sorted(distinct, key=str.casefold))


def pretty_sensor(sensor):
    return {
        "falco_modern_ebpf": "Falco (Modern eBPF)",
        "elastic_defend": "Elastic Defend",
        "auditd_log_collector": "auditd (log)",
        "linux_process_telemetry": "telemetria processi Linux (generica)",
    }.get(sensor, sensor)


def pretty_event(event):
    if event.startswith("eql:"):
        return "Elastic " + event.removeprefix("eql:")
    if event.startswith("logsource:"):
        return event.replace("logsource:", "log ")
    return event


def simple_row(full, original, rules, vulhub):
    """Crea solo le 9 colonne indispensabili. Nessuna inference aggiuntiva."""
    cve = full["cve_id"]
    status = full["selection_status"]
    candidate_sensors = [x for x in full.get("sensor_candidates_active", "").split(";") if x]
    is_concrete = bool(candidate_sensors) and status != "out_of_initial_scope"
    host_families = [x for x in (full.get("host_event_families", "") + ";" +
                                  full.get("vulhub_observable_families", "")).split(";") if x]
    doc_behaviors = sorted(set(host_families))
    desc_behaviors = [x for x in full.get("description_behaviors", "").split(";") if x]
    behavior_values = doc_behaviors if doc_behaviors else desc_behaviors
    behavior = "; ".join(BEHAVIOR_LABELS.get(x, x) for x in sorted(set(behavior_values)))

    if is_concrete or status == "host_telemetry_source_only":
        # Rule event types may contain non-host artifacts; keep only host evidence.
        host_rule_events = [x for r in rules if r.get("telemetry_scope") in HOST_SCOPES
                            and r.get("extraction_status") in ("parsed", "partial")
                            for x in r.get("event_types", "").split(";") if x]
        doc_events = [x for r in vulhub if r.get("extraction_status") == "observable_documented"
                      for x in r.get("event_types", "").split(";") if x]
        event_values = sorted(set(host_rule_events + doc_events))
        families = sorted(set(doc_behaviors))
        event_display = "; ".join(pretty_event(x) for x in event_values)
        # Ambito osservabile + evento specifico, senza fingere che EQL sia una syscall.
        if status == "file_access_review_required":
            # I nomi open/openat non sono stati osservati: non mostrarli
            # come syscall ricavate dal solo percorso nel payload del README.
            observable = "accesso file da verificare (evento kernel non dimostrato)"
        else:
            observable = "; ".join(families)
            if event_display:
                observable += " [" + event_display + "]" if observable else event_display
        field_values = [x for x in (full.get("host_required_fields", "") + ";" +
                                    full.get("vulhub_required_fields_examples", "")).split(";") if x]
        fields = neutral_required_fields(field_values)
    else:
        observable = ""
        fields = ""

    host_rules = [r for r in rules if r.get("telemetry_scope") in HOST_SCOPES
                  and r.get("extraction_status") in ("parsed", "partial")]
    good_vulhub = [r for r in vulhub if r.get("extraction_status") == "observable_documented"]
    # Primary evidence: a specific Vulhub README, then a verified host rule, then NVD.
    if good_vulhub:
        source_parts = ["Vulhub"]
        if host_rules:
            source_parts += sorted(set(r["repository"].capitalize() for r in host_rules))
        selected_path = good_vulhub[0].get("vulhub_path", "")
        link = (f"https://github.com/vulhub/vulhub/blob/master/{selected_path}/README.md"
                if selected_path else good_vulhub[0].get("readme_url", ""))
    elif host_rules:
        source_parts = sorted(set(r["repository"].capitalize() for r in host_rules))
        link = host_rules[0].get("rule_url", "")
    else:
        source_parts = ["NVD"]
        link = f"https://nvd.nist.gov/vuln/detail/{cve}"
    source = "; ".join(source_parts)

    if status == "out_of_initial_scope":
        simple_status = "fuori_perimetro"
        note = "CVE kernel: fuori dal perimetro iniziale."
    elif status == "file_access_review_required":
        simple_status = "da_verificare"
        note = "Il README mostra un percorso file, ma non prova l'accesso dal processo bersaglio."
    elif is_concrete:
        simple_status = "candidato"
        note = "Sensore candidato sulla base delle fonti disponibili."
        if full.get("vulhub_review_required") == "yes":
            note = "Da controllare se il file e' letto dal processo vulnerabile."
    elif status == "host_telemetry_source_only":
        simple_status = "sorgente_generica"
        note = "Dati host identificati; manca un sensore concreto."
    elif status == "non_host_rule_only":
        simple_status = "solo_log_applicativi"
        note = "Nessuna evidenza host dai riferimenti disponibili."
    elif status == "description_hypothesis_only":
        simple_status = "solo_ipotesi"
        note = "Descrizione NVD troppo generica per scegliere un sensore."
    else:
        simple_status = "evidenza_insufficiente"
        raw_reason = full.get("missing_evidence_reason", "").split(";")[0]
        note = MISSING_NOTES.get(raw_reason, "Evento host non determinabile dalle fonti lette.")

    return {
        "cve_id": cve,
        "comportamento": behavior,
        "osservabile_evento": observable,
        "campi_necessari": fields,
        "sensore_candidato": "; ".join(pretty_sensor(s) for s in candidate_sensors) if is_concrete else "",
        "fonte": source,
        "link_fonte": link,
        "stato": simple_status,
        "nota": note,
    }



# ---------------------------------------------------------------------------
# V1.3: analisi STATICA prudente di file PoC, solo per CVE senza selezione host.
# Non esegue codice, non importa moduli PoC, non verifica la detection.
# Limiti deliberati: max 1 repo GitHub esterno per CVE, max 2 file per sorgente,
# budget delle API per evitare rate-limit anonimi. Cache locale riutilizzabile.
# ---------------------------------------------------------------------------
POC_EXTENSIONS = {'.py', '.sh', '.js', '.php', '.rb', '.go', '.java', '.c', '.pl'}
POC_FILENAME = re.compile(r'(?:^|[^a-z])(?:poc|exploit|attack|exp|cve)[^/]*', re.I)
POC_SKIP = {'setup.py', 'manage.py', 'requirements.py', 'conftest.py', 'docker-compose.py'}
POC_MAX_BYTES = 200_000
POC_API_BUDGET_DEFAULT = 45   # GitHub anonimo: 60 richieste API/h (condivise per IP)

# Pattern volutamente limitati a istruzioni di esecuzione ESPLICITE nel payload.
# Non includere os.system/subprocess.run del codice principale: potrebbero essere
# eseguiti localmente sul sistema dell'attaccante.
POC_VICTIM_EXEC = re.compile(
    r'(?:\b(?:T\s*\(\s*java\.lang\.Runtime\s*\)|(?:java\.lang\.)?Runtime)\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\('
    r'|ProcessBuilder\s*\('
    r'|__import__\s*\(\s*[\\\'\"]os[\\\'\"]\s*\)\s*\.\s*(?:system|popen)\s*\('
    r'|\b(?:shell_exec|passthru)\s*\()', re.I
)
# La presenza di questa stringa da sola NON basta: dev'essere una stringa di
# payload/HTTP (non codice locale). Conserviamo l'estratto originale nel dettaglio.
POC_TRANSPORT = re.compile(r'\b(?:requests\.(?:get|post|put|request)|urllib|httpx\.|'
                           r'http\.client|fetch\s*\(|axios\.|curl\b|wget\b|'
                           r'socket\.|http\.NewRequest|HTTP::|Net::HTTP|'
                           r'request\s*\(|post\s*\()', re.I)


def parse_public_github_poc_url(url, cve_id):
    """Solo URL github.com riferiti UNIVOCAMENTE alla CVE nel repo/percorso."""
    try:
        p = urlsplit(url)
        if p.scheme != 'https' or p.netloc.lower() != 'github.com':
            return None
        parts = p.path.strip('/').split('/')
        if len(parts) < 2 or not all(re.fullmatch(r'[A-Za-z0-9_.-]+', x) for x in parts[:2]):
            return None
        owner, repo = parts[:2]
        if owner in ('.', '..') or repo in ('.', '..'):
            return None
        repo_identity = cve_id.lower() in (owner + '/' + repo).lower()
        if len(parts) >= 5 and parts[2] == 'blob':
            branch, rel = parts[3], '/'.join(parts[4:])
            if any(x in ('.','..','') for x in parts[4:]) or not re.fullmatch(r'[A-Za-z0-9_.-]+', branch):
                return None
            if not repo_identity and cve_id.lower() not in rel.lower():
                return None
            if Path(rel).suffix.lower() not in POC_EXTENSIONS:
                return None
            return ('direct', owner, repo, branch, rel)
        if len(parts) != 2 or not repo_identity:
            return None
        return ('repo', owner, repo, '', '')
    except (ValueError, AttributeError):
        return None


class PocCache:
    def __init__(self, folder, *, offline=False, refresh=False, api_budget=POC_API_BUDGET_DEFAULT, timeout=12):
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)
        self.offline, self.refresh, self.timeout = offline, refresh, timeout
        self.api_budget = max(0, api_budget)
        self.api_used = 0
        self.rate_limited = False
        self.stats = Counter()

    def get(self, url, api=False):
        p = urlsplit(url)
        if p.scheme != 'https' or p.netloc.lower() not in ('api.github.com', 'raw.githubusercontent.com'):
            return None, 'invalid_host'
        if api != (p.netloc.lower() == 'api.github.com'):
            return None, 'invalid_api_kind'
        key = hashlib.sha256(url.encode('utf-8')).hexdigest()
        path = self.folder / (key + ('.json' if api else '.txt'))
        if path.is_file() and not self.refresh:
            try:
                b = path.read_bytes()
                if len(b) > (800_000 if api else POC_MAX_BYTES):
                    raise ValueError('cached_file_too_large')
                self.stats['from_cache'] += 1
                return b.decode('utf-8-sig'), ''
            except (OSError, UnicodeError, ValueError):
                return None, 'cache_error'
        if self.offline:
            self.stats['cache_miss'] += 1
            return None, 'offline_cache_missing'
        if api:
            if self.rate_limited:
                self.stats['api_limit_skipped'] += 1
                return None, 'github_rate_limited'
            if self.api_used >= self.api_budget:
                self.stats['api_budget_skipped'] += 1
                return None, 'api_budget_exhausted'
            self.api_used += 1
        try:
            h = {'User-Agent': USER_AGENT, 'Accept': 'application/vnd.github+json' if api else 'text/plain'}
            # Token facoltativo, mai scritto in cache o output.
            if api and os.environ.get('GITHUB_TOKEN'):
                h['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
            request = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(request, timeout=self.timeout) as r:
                f = urlsplit(r.url)
                if f.scheme != 'https' or f.netloc.lower() != p.netloc.lower():
                    return None, 'unsafe_redirect'
                b = r.read((800_000 if api else POC_MAX_BYTES)+1)
            if len(b) > (800_000 if api else POC_MAX_BYTES):
                return None, 'file_too_large'
            text = b.decode('utf-8-sig')
            path.write_bytes(b)
            self.stats['api_downloaded' if api else 'files_downloaded'] += 1
            return text, ''
        except urllib.error.HTTPError as e:
            if api and (e.code == 429 or (e.code == 403 and e.headers.get('x-ratelimit-remaining') == '0')):
                self.rate_limited = True
                self.stats['rate_limit_reached'] += 1
                return None, 'github_rate_limited'
            self.stats['http_error'] += 1
            return None, f'http_{e.code}'
        except (urllib.error.URLError, TimeoutError, OSError, UnicodeError, ValueError):
            self.stats['fetch_error'] += 1
            return None, 'download_error'


def poc_files_from_directory(body, *, branch, owner, repo):
    """Massimo 2 file: nomi PoC specifici, o main.* solo in repo CVE dedicato."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    ranked = []
    for entry in data:
        if not isinstance(entry, dict) or entry.get('type') != 'file':
            continue
        name = str(entry.get('name') or '')
        if Path(name).suffix.lower() not in POC_EXTENSIONS or name.lower() in POC_SKIP:
            continue
        if int(entry.get('size') or 0) > POC_MAX_BYTES:
            continue
        score = 2 if POC_FILENAME.search(name) else 1 if name.lower().startswith(('main.', 'run.')) else 0
        if not score:
            continue
        url = str(entry.get('download_url') or '')
        u = urlsplit(url)
        if u.scheme != 'https' or u.netloc.lower() != 'raw.githubusercontent.com':
            continue
        # Repo identity controllata anche sul download, senza fidarsi del JSON.
        if not u.path.lower().startswith(f'/{owner}/{repo}/'.lower()):
            continue
        ranked.append((score, name, url))
    ranked.sort(key=lambda x: (-x[0], x[1].casefold()))
    return [(name, url) for _, name, url in ranked[:2]]


def poc_attack_payload_evidence(source, filename):
    """Riconosce solo un sink di processo IN una stringa di payload inviato.

    Evita il falso positivo frequente: `os.system` nel codice Python del PoC
    significa spesso che gira sul computer dell'attaccante, non sul bersaglio.
    """
    if not POC_TRANSPORT.search(source):
        return None
    suffix = Path(filename).suffix.lower()
    if suffix == '.py':
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            return None
        strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        candidates = [s for s in strings if POC_VICTIM_EXEC.search(s)]
        # Per evitare docstring/tutorial non pertinenti, richiedere variabile
        # payload o header esplicita nella sorgente del PoC.
        if not re.search(r'\b(?:payload|header|headers|data|body|params|url|command|cmd)\b', source, re.I):
            return None
        if candidates:
            fragment = candidates[0]
            match = POC_VICTIM_EXEC.search(fragment)
            return fragment[max(0,match.start()-90):match.end()+110].replace('\n',' ')[:260]
    else:
        # Per altri linguaggi richiediamo l'API all'interno di una stringa
        # payload associata a una richiesta HTTP; mai promuovere codice locale
        # non quotato (es. shell `os.system` / builder del PoC).
        for line in source.splitlines():
            match = POC_VICTIM_EXEC.search(line)
            if not match:
                continue
            if re.search(r'\b(?:payload|header|body|data|curl|fetch|request|post|url)\b', line, re.I):
                return line.strip()[:260]
    return None


def poc_file_access_hint(text):
    """Solo indizio, MAI promuovere automaticamente file access a candidato."""
    if re.search(r'(?:/etc/passwd|/etc/shadow|/proc/self/environ)', text, re.I):
        return 'Percorso sensibile nel PoC; accesso dal processo bersaglio non dimostrato.'
    return ''


def analyze_poc_file(cve_id, source_name, file_name, raw_url, cache):
    data, err = cache.get(raw_url)
    base = {'cve_id': cve_id, 'fonte_poc': source_name, 'file': file_name,
            'url': raw_url, 'stato_estrazione': 'non_disponibile' if err else 'letto',
            'comportamento': '', 'estratto': '', 'nota': err,
            'sha256': hashlib.sha256(data.encode('utf-8')).hexdigest() if data is not None else ''}
    if data is None:
        return base
    evidence = poc_attack_payload_evidence(data, file_name)
    if evidence:
        base.update(stato_estrazione='evidenza_payload', comportamento='process_execution',
                    estratto=evidence,
                    nota='Esecuzione esplicita in stringa payload; da confermare il flusso verso il bersaglio.')
    else:
        hint = poc_file_access_hint(data)
        if hint:
            base.update(stato_estrazione='indizio_non_sufficiente', nota=hint)
        else:
            base.update(stato_estrazione='nessun_pattern_esplicito',
                        nota='Il parser statico non ha riconosciuto un evento host concreto.')
    return base


def gather_pocs(cve_id, row, cache):
    """Per CVE: massimo 1 cartella Vulhub e 1 repository GitHub, max 2 file ciascuno."""
    findings = []
    paths = csv_items(row.get('vulhub_paths', ''))
    if paths:
        path = paths[0]
        try:
            # Fonte allowlist Vulhub, senza seguire link arbitrari nel README.
            safe_vulhub_readme_url(path)
            api_url = 'https://api.github.com/repos/vulhub/vulhub/contents/' + quote(path, safe='/') + '?ref=master'
            body, err = cache.get(api_url, api=True)
            if body:
                for filename, u in poc_files_from_directory(body, branch='master', owner='vulhub', repo='vulhub'):
                    findings.append(analyze_poc_file(cve_id, 'Vulhub', filename, u, cache))
            elif err:
                findings.append({'cve_id': cve_id, 'fonte_poc': 'Vulhub', 'file': '', 'url': api_url,
                                 'stato_estrazione': 'non_disponibile', 'comportamento': '',
                                 'estratto': '', 'nota': err, 'sha256': ''})
        except ValueError:
            pass
    # Evita un'altra richiesta API se una prova esplicita e' gia' nel PoC Vulhub.
    if any(x.get('stato_estrazione') == 'evidenza_payload' for x in findings):
        return findings
    # Selezione repo dedicato alla CVE (non scanner generici/multi-CVE).
    seen = set()
    for url in csv_items(row.get('poc_urls', '')):
        ref = parse_public_github_poc_url(url, cve_id)
        if not ref:
            continue
        kind, owner, repo, branch, rel = ref
        key = (owner.lower(), repo.lower())
        if key in seen:
            continue
        seen.add(key)
        if kind == 'direct':
            raw_url = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{quote(rel, safe="/")}'
            findings.append(analyze_poc_file(cve_id, 'GitHub', rel, raw_url, cache))
        else:
            api_url = f'https://api.github.com/repos/{owner}/{repo}/contents'
            body, err = cache.get(api_url, api=True)
            if body:
                for filename, u in poc_files_from_directory(body, branch='', owner=owner, repo=repo):
                    findings.append(analyze_poc_file(cve_id, 'GitHub', filename, u, cache))
            elif err:
                findings.append({'cve_id': cve_id, 'fonte_poc': 'GitHub', 'file': '', 'url': api_url,
                                 'stato_estrazione': 'non_disponibile', 'comportamento': '',
                                 'estratto': '', 'nota': err, 'sha256': ''})
        break
    return findings


def apply_poc_to_minimal(minimal, full, pocs):
    """Non cambiare le 9 colonne, ne' cancellare candidati documentati."""
    if minimal['stato'] in ('candidato', 'fuori_perimetro'):
        return minimal
    confirmed = next((p for p in pocs if p['stato_estrazione'] == 'evidenza_payload'
                      and p['comportamento'] == 'process_execution'), None)
    if not confirmed:
        return minimal
    r = dict(minimal)
    r.update(comportamento='esecuzione di comando nel payload PoC',
             osservabile_evento='esecuzione processo [execve; execveat]',
             campi_necessari='nome processo; nome processo padre; riga di comando',
             sensore_candidato='Falco (Modern eBPF); Elastic Defend',
             fonte='PoC ' + confirmed['fonte_poc'],
             link_fonte=confirmed['url'],
             stato='da_verificare',
             nota='Il PoC contiene un payload di esecuzione; verificare che raggiunga il bersaglio.')
    # Non promuoviamo automaticamente a candidato: il codice statico puo'
    # contenere un payload non utilizzato o un falso positivo.
    return r


def main():
    p = argparse.ArgumentParser(description="CVE2Patch Sensor Selector v1.3 (matrice minimal, NVD/Vulhub/Falco/Elastic)")
    p.add_argument("--input", type=Path, default=None, help="Dataset CSV; auto-cerca CVE2Patch/output/initial_pool.csv")
    p.add_argument("--output", type=Path, default=None, help="Matrice minimal (9 colonne): sensor_matrix_v1_3.csv")
    p.add_argument("--rules-output", type=Path, default=None, help="Dettaglio regole: sensor_rules_v1_3.csv")
    p.add_argument("--vulhub-output", type=Path, default=None, help="Dettaglio README: sensor_vulhub_v1_3.csv")
    p.add_argument("--summary", type=Path, default=None, help="Riepilogo JSON")
    p.add_argument("--cache-dir", type=Path, default=None, help="Cache dei file regola esistente")
    p.add_argument("--vulhub-cache-dir", type=Path, default=None, help="Cache README Vulhub")
    p.add_argument("--offline", action="store_true", help="Usa solo regole/README gia' salvati in cache")
    p.add_argument("--refresh", action="store_true", help="Riscarica regole e README (se online)")
    p.add_argument("--include-sigma", action="store_true", help="Include Sigma nella selezione (sospeso di default)")
    p.add_argument("--skip-vulhub", action="store_true", help="Disabilita Vulhub per confronto")
    p.add_argument("--skip-poc", action="store_true", help="Salta analisi statica PoC")
    p.add_argument("--poc-api-budget", type=int, default=POC_API_BUDGET_DEFAULT,
                   help="Numero massimo di richieste GitHub API per esecuzione (default 45)")
    args = p.parse_args()
    if args.offline and args.refresh:
        p.error("--offline e --refresh non sono compatibili")
    try:
        input_file = args.input.expanduser().resolve() if args.input else default_input()
        with input_file.open("r", newline="", encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
        if not rows:
            raise ValueError("Dataset vuoto")
        ids = [x.get("cve_id", "") for x in rows]
        if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", v) for v in ids) or len(ids) != len(set(ids)):
            raise ValueError("CVE IDs invalidi o duplicati")
        required = {"cve_id", "description", "vulhub_paths", "falco_rule_urls", "elastic_rule_urls"}
        if not required.issubset(rows[0]):
            raise ValueError("Colonne mancanti: " + ", ".join(sorted(required - set(rows[0]))))
    except (OSError, ValueError) as exc:
        p.error(str(exc))

    output_dir = input_file.parent
    output = args.output or output_dir / "sensor_matrix_v1_3.csv"
    rules_output = args.rules_output or output_dir / "sensor_dettagli_v1_3" / "sensor_rules_v1_3.csv"
    vulhub_output = args.vulhub_output or output_dir / "sensor_dettagli_v1_3" / "sensor_vulhub_v1_3.csv"
    summary_file = args.summary or output_dir / "sensor_summary_v1_3.json"
    rule_cache = RuleCache(args.cache_dir or output_dir / "sensor_rule_cache", offline=args.offline, refresh=args.refresh)
    vulhub_cache = VulhubCache(args.vulhub_cache_dir or output_dir / "sensor_vulhub_cache", offline=args.offline, refresh=args.refresh)

    active_sources = {k: v for k, v in SOURCES.items() if k != "sigma" or args.include_sigma}
    pending_rules = {(url, repo) for row in rows for repo, urlkey, _, _, _ in active_sources.values()
                     for url in csv_items(row.get(urlkey, ""))}
    paths = sorted(set(pth for row in rows for pth in csv_items(row.get("vulhub_paths", ""))))
    print(f"CVE: {len(rows)} | regole attive: {len(pending_rules)} file | Vulhub: {len(paths)} README candidati")
    print("Sigma:", "attivo" if args.include_sigma else "sospeso (riferimenti conservati nel dataset)")
    rule_cache.prefetch(sorted(pending_rules))
    if not args.skip_vulhub:
        vulhub_cache.prefetch(paths)

    matrix, details, vulhub_details = [], [], []
    for row in rows:
        rules = []
        for source, (_, urlkey, namekey, idkey, _) in active_sources.items():
            urls = csv_items(row.get(urlkey, ""))
            names = csv_items(row.get(namekey, ""))
            rule_ids = csv_items(row.get(idkey, "")) if idkey else []
            for idx, url in enumerate(urls):
                result = inspect_rule(row["cve_id"], source, url,
                                      names[idx] if idx < len(names) else "",
                                      rule_ids[idx] if idx < len(rule_ids) else "", rule_cache)
                rules.append(result)
                details.append(result)
        vulhub_rows = []
        if not args.skip_vulhub:
            for pth in csv_items(row.get("vulhub_paths", "")):
                detail = inspect_vulhub(row["cve_id"], pth, vulhub_cache)
                vulhub_details.append(detail)
                vulhub_rows.append(detail)
        matrix.append(integrate_vulhub(row, rules, vulhub_rows))
    minimal_matrix = [simple_row(full, original,
                                     [r for r in details if r["cve_id"] == full["cve_id"]],
                                     [r for r in vulhub_details if r["cve_id"] == full["cve_id"]])
                      for full, original in zip(matrix, rows)]
    # Analisi PoC solo per i casi senza sensore host documentato; file mai eseguiti.
    poc_details = []
    poc_cache = PocCache(output_dir / "sensor_poc_cache", offline=args.offline,
                         refresh=args.refresh, api_budget=args.poc_api_budget)
    if not args.skip_poc:
        unresolved = [(idx, row) for idx, row in enumerate(rows)
                      if minimal_matrix[idx]['stato'] not in ('candidato', 'fuori_perimetro')]
        print(f"CVE da esaminare nei PoC: {len(unresolved)} | budget API GitHub: {args.poc_api_budget}")
        for idx, row in unresolved:
            found = gather_pocs(row['cve_id'], row, poc_cache)
            poc_details.extend(found)
            minimal_matrix[idx] = apply_poc_to_minimal(minimal_matrix[idx], matrix[idx], found)
    assert all(list(r.keys()) == MATRIX_COLUMNS for r in minimal_matrix)
    write_csv(output, minimal_matrix)
    if details:
        write_csv(rules_output, details)
    else:
        rules_output.parent.mkdir(parents=True, exist_ok=True)
        with rules_output.open("w", encoding="utf-8-sig", newline="") as f:
            csv.writer(f).writerow(["cve_id", "repository", "rule_url", "extraction_status"])
    if vulhub_details:
        write_csv(vulhub_output, vulhub_details)
    else:
        vulhub_output.parent.mkdir(parents=True, exist_ok=True)
        with vulhub_output.open("w", encoding="utf-8-sig", newline="") as f:
            csv.writer(f).writerow(["cve_id", "vulhub_path", "extraction_status"])

    poc_output = output_dir / "sensor_dettagli_v1_3" / "sensor_poc_v1_3.csv"
    if poc_details:
        write_csv(poc_output, poc_details)
    else:
        poc_output.parent.mkdir(parents=True, exist_ok=True)
        with poc_output.open("w", encoding="utf-8-sig", newline="") as f:
            csv.writer(f).writerow(['cve_id','fonte_poc','file','url','stato_estrazione',
                                     'comportamento','estratto','nota','sha256'])

    summary = {
        "version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "input_sha256": hashlib.sha256(input_file.read_bytes()).hexdigest(),
        "cve_count": len(matrix),
        "nvd_existing_data_used": ["description", "cwe", "references", "reference_details"],
        "sigma_in_selection": args.include_sigma,
        "rule_reference_count_active": len(details),
        "rule_extraction_status_counts": dict(Counter(x["extraction_status"] for x in details)),
        "vulhub_reference_count": len(vulhub_details),
        "vulhub_extraction_status_counts": dict(Counter(x["extraction_status"] for x in vulhub_details)),
        "selection_status_counts": dict(Counter(x["selection_status"] for x in matrix)),
        "before_vulhub_status_counts_same_sigma_mode": dict(Counter(x["selection_status_before_vulhub"] for x in matrix)),
        "new_host_sensor_candidates_from_vulhub": sum(x["new_host_candidate_from_vulhub"] == "yes" for x in matrix),
        "host_candidate_before_vulhub_same_sigma_mode": sum(bool(x["concrete_host_sensor_candidates"]) for x in matrix),
        "active_host_sensor_candidate_count": sum(
            bool(x["sensor_candidates_active"])
            and x["selection_status"] not in ("file_access_review_required", "out_of_initial_scope")
            for x in matrix
        ),
        "pending_file_access_review_count": sum(
            x["selection_status"] == "file_access_review_required" for x in matrix
        ),
        "vulhub_readme_file_access_review_required_count": sum(x.get("vulhub_review_required") == "yes" for x in matrix),
        "rule_cache_stats": dict(rule_cache.stats),
        "vulhub_cache_stats": dict(vulhub_cache.stats),
        "poc_analysis_enabled": not args.skip_poc,
        "poc_api_requests": poc_cache.api_used,
        "poc_cache_stats": dict(poc_cache.stats),
        "poc_extraction_status_counts": dict(Counter(x['stato_estrazione'] for x in poc_details)),
        "poc_review_cases": sum(x['stato'] == 'da_verificare' and
                                x['fonte'].startswith('PoC ') for x in minimal_matrix),
        "final_minimal_status_counts": dict(Counter(x['stato'] for x in minimal_matrix)),
        "notes": [
            "NVD usato dai dati salvati nel dataset: CWE e CVSS non rivelano automaticamente le syscall.",
            "Il comportamento del PoC e' letto dal README Vulhub, non eseguito.",
            "Solo segnali host espliciti nelle sezioni exploit/reproduce producono candidati da Vulhub.",
            "Un sensore e' candidato per capacita' dell'evento, non per presenza di una regola del medesimo nome.",
            "Sigma resta nel dataset ed e' sospeso per default: --include-sigma lo riattiva.",
            "I README possono cambiare su master; la cache e lo SHA256 consentono di fissare l'input.",
            "Il risultato si riferisce ai PoC documentati, non a tutte le possibili tecniche d'exploit.",
            "Nessun exploit eseguito e nessuna detection sperimentalmente validata.",
            "Estratti file_access riportano righe reali del README, non frasi sintetiche; controllare la localizzazione del file.",
            "Insufficient_evidence indica assenza di pattern identificato dalle fonti elaborate, non impossibilita' di detection.",
            "Non vengono scaricati gli advisory dai riferimenti NVD: i link sono solo metadati al momento.",
            "I casi file_access basati solo su un path nel README sono da_verificare e non contano come candidati host documentati.",
            "I campi della matrice sono etichette semantiche comuni a Falco ed Elastic; sintassi originale nei CSV di dettaglio.",
            "PoC esaminati staticamente: nessun file eseguito; solo payload espliciti danno luogo a una revisione, non a selezione validata.",
            "Repository GitHub limitati a URL con CVE nel nome/percorso; max 1 repo e 2 file per fonte/CVE.",
            "GitHub API anonima: 60 richieste/ora; il budget predefinito e' 45 per run, con cache per riusi.",
        ],
    }
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    summary_file.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Righe matrice:", len(matrix))
    for key, value in summary["selection_status_counts"].items():
        print(" ", key + ":", value)
    print("Nuovi candidati host da README Vulhub:", summary["new_host_sensor_candidates_from_vulhub"])
    print("README Vulhub:", summary["vulhub_extraction_status_counts"])
    print("Matrice MINIMAL (9 colonne):", output)
    print("Dettagli tecnici (facoltativi):", rules_output.parent)
    print("PoC analizzati:", dict(Counter(x['stato_estrazione'] for x in poc_details)))
    print("Casi PoC da verificare:", summary['poc_review_cases'])
    print("Matrice finale:", summary['final_minimal_status_counts'])
    print("Dettagli PoC:", poc_output)
    print("Report:", summary_file)
    if rule_cache.stats["fetch_error"] or vulhub_cache.stats["fetch_error"]:
        print("ATTENZIONE: errori nel download; controlla dettaglio Vulhub/regole e riesegui per i mancanti.")


if __name__ == "__main__":
    main()
