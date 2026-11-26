"""Estrazione di eventi e campi dalle regole pubbliche Falco, Elastic e Sigma.

ATTENZIONE: la presenza di una regola non prova l'efficacia di una detection.
Sigma viene analizzato solo se abilitato esplicitamente dalla CLI.
"""
from __future__ import annotations
import json
import re
import tomllib
import yaml

from .utils import norm_name, uniq


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
