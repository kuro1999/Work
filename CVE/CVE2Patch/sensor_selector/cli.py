"""Orchestrazione: carica il CSV, interroga parser/cache, salva gli output.

Esempio: python cve2patch_sensor_selector.py --offline
Tutte le decisioni tecniche si trovano nei moduli sottostanti.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .utils import (VERSION, POC_API_BUDGET_DEFAULT, csv_items,
                    default_input, write_csv)
from .cache import RuleCache, VulhubCache, PocCache
from .rules import SOURCES, inspect_rule
from .vulhub import inspect_vulhub
from .selection import integrate_vulhub
from .presentation import MATRIX_COLUMNS, simple_row
from .poc import gather_pocs, apply_poc_to_minimal


def main():
    p = argparse.ArgumentParser(description="CVE2Patch Sensor Selector v1.4 (refactoring modulare, matrice 9 colonne)")
    p.add_argument("--input", type=Path, default=None, help="Dataset CSV; auto-cerca CVE2Patch/output/initial_pool.csv")
    p.add_argument("--output", type=Path, default=None, help="Matrice minimal (9 colonne): sensor_matrix_v1_4.csv")
    p.add_argument("--rules-output", type=Path, default=None, help="Dettaglio regole: sensor_rules_v1_4.csv")
    p.add_argument("--vulhub-output", type=Path, default=None, help="Dettaglio README: sensor_vulhub_v1_4.csv")
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
    output = args.output or output_dir / "sensor_matrix_v1_4.csv"
    output = output.expanduser().resolve()
    report_dir = output.parent
    rules_output = args.rules_output or report_dir / "sensor_dettagli_v1_4" / "sensor_rules_v1_4.csv"
    vulhub_output = args.vulhub_output or report_dir / "sensor_dettagli_v1_4" / "sensor_vulhub_v1_4.csv"
    summary_file = args.summary or report_dir / "sensor_summary_v1_4.json"
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
    # Raggruppiamo i dettagli una volta sola: ogni CVE resta una riga minimal.
    rules_by_cve = {}
    for detail in details:
        rules_by_cve.setdefault(detail["cve_id"], []).append(detail)
    vulhub_by_cve = {}
    for detail in vulhub_details:
        vulhub_by_cve.setdefault(detail["cve_id"], []).append(detail)
    minimal_matrix = [
        simple_row(full, rules_by_cve.get(full["cve_id"], []),
                   vulhub_by_cve.get(full["cve_id"], []))
        for full in matrix
    ]
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
            minimal_matrix[idx] = apply_poc_to_minimal(minimal_matrix[idx], found)
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

    poc_output = report_dir / "sensor_dettagli_v1_4" / "sensor_poc_v1_4.csv"
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
        "excluded_multi_cve_poc_files": sum(
            x['stato_estrazione'] == 'escluso_catena_multi_cve' for x in poc_details
        ),
        "excluded_multi_cve_vulhub_readmes": sum(
            x['extraction_status'] == 'excluded_multi_cve_chain' for x in vulhub_details
        ),
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
    print("PoC multi-CVE esclusi:", summary['excluded_multi_cve_poc_files'])
    print("Matrice finale:", summary['final_minimal_status_counts'])
    print("Dettagli PoC:", poc_output)
    print("Report:", summary_file)
    if rule_cache.stats["fetch_error"] or vulhub_cache.stats["fetch_error"]:
        print("ATTENZIONE: errori nel download; controlla dettaglio Vulhub/regole e riesegui per i mancanti.")
