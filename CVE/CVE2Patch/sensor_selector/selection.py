"""Associazione conservativa: comportamenti -> eventi -> sensori host.

Questo modulo produce anche i dettagli interni usati per ricostruire le
motivazioni. La vista a nove colonne viene creata in presentation.py.
"""
from __future__ import annotations
import json
import re

from .utils import csv_items, uniq
from .rules import HOST_SCOPES, NON_HOST_SCOPES, CONCRETE_HOST_SENSOR_CANDIDATES


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


def evidence_from_description(description):
    matched = {}
    for label, patterns in COMPILED.items():
        found = sorted(set(m.group(0) for p in patterns for m in p.finditer(description)), key=str.casefold)
        if found:
            matched[label] = found
    return matched


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
        elif any(r["extraction_status"] == "excluded_multi_cve_chain" for r in vulhub_rows):
            missing_reason = "poc_multi_cve_excluded"
            source_next = "single_cve_poc_only"
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
