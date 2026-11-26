"""Orchestrazione: carica il CSV, interroga parser/cache, salva gli output.

Esempio: python cve2patch_sensor_selector.py --offline
Tutte le decisioni tecniche si trovano nei moduli sottostanti.
"""
from __future__ import annotations
import argparse
import csv
import re
from pathlib import Path

from .utils import (POC_API_BUDGET_DEFAULT, csv_items,
                    default_input, write_csv)
from .cache import RuleCache, VulhubCache, PocCache
from .rules import SOURCES, inspect_rule
from .vulhub import inspect_vulhub
from .selection import integrate_vulhub
from .presentation import MATRIX_COLUMNS, simple_row
from .poc import gather_pocs, apply_poc_to_minimal
from .tetragon import add_tetragon_to_row


def main():
    p = argparse.ArgumentParser(description="CVE2Patch Sensor Selector (tre sensori, matrice 9 colonne)")
    p.add_argument("--input", type=Path, default=None, help="Dataset CSV; auto-cerca CVE2Patch/output/initial_pool.csv")
    p.add_argument("--output", type=Path, default=None, help="Matrice minimal (9 colonne): sensor_matrix.csv")
    p.add_argument("--rules-output", type=Path, default=None, help="Dettaglio regole: sensor_rules.csv")
    p.add_argument("--vulhub-output", type=Path, default=None, help="Dettaglio README: sensor_vulhub.csv")
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
    output = args.output or output_dir / "sensor_matrix.csv"
    output = output.expanduser().resolve()
    report_dir = output.parent
    rules_output = args.rules_output or report_dir / "sensor_dettagli" / "sensor_rules.csv"
    vulhub_output = args.vulhub_output or report_dir / "sensor_dettagli" / "sensor_vulhub.csv"
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
    # Tetragon aggiunto soltanto ai comportamenti host gia' documentati.
    # Questa fase non cambia lo stato delle CVE e non genera TracingPolicy.
    minimal_matrix = [add_tetragon_to_row(simple, full)
                      for simple, full in zip(minimal_matrix, matrix)]
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

    poc_output = report_dir / "sensor_dettagli" / "sensor_poc.csv"
    if poc_details:
        write_csv(poc_output, poc_details)
    else:
        poc_output.parent.mkdir(parents=True, exist_ok=True)
        with poc_output.open("w", encoding="utf-8-sig", newline="") as f:
            csv.writer(f).writerow(['cve_id','fonte_poc','file','url','stato_estrazione',
                                     'comportamento','estratto','nota','sha256'])

    # Mostriamo un esito breve a terminale senza creare un file di riepilogo.
    print(f"CVE elaborate: {len(minimal_matrix)}")
    print(f"Matrice (9 colonne): {output}")
    print(f"Dettagli tecnici facoltativi: {poc_output.parent}")
    if rule_cache.stats["fetch_error"] or vulhub_cache.stats["fetch_error"]:
        print("ATTENZIONE: errori nel download; controlla dettaglio Vulhub/regole e riesegui per i mancanti.")
