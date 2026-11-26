"""Analisi statica (mai esecuzione) di PoC GitHub/Vulhub.

Cerca solo segnali molto espliciti di comando nel payload destinato al server.
Esclude PoC che richiedono catene di due o piu' CVE distinte.
"""
from __future__ import annotations
import ast
import hashlib
import json
import re
import warnings
from pathlib import Path
from urllib.parse import quote, urlsplit

from .utils import (csv_items, POC_MAX_BYTES, safe_vulhub_readme_url,
                    is_explicit_multi_cve_chain)


POC_EXTENSIONS = {'.py', '.sh', '.js', '.php', '.rb', '.go', '.java', '.c', '.pl'}


POC_FILENAME = re.compile(r'(?:^|[^a-z])(?:poc|exploit|attack|exp|cve)[^/]*', re.I)


POC_SKIP = {'setup.py', 'manage.py', 'requirements.py', 'conftest.py', 'docker-compose.py'}


POC_VICTIM_EXEC = re.compile(
    r'(?:\b(?:T\s*\(\s*java\.lang\.Runtime\s*\)|(?:java\.lang\.)?Runtime)\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\('
    r'|ProcessBuilder\s*\('
    r'|__import__\s*\(\s*[\\\'\"]os[\\\'\"]\s*\)\s*\.\s*(?:system|popen)\s*\('
    r'|\b(?:shell_exec|passthru)\s*\()', re.I
)


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
            # Alcuni PoC contengono stringhe Python con backslash non escapati.
            # Sono avvisi del codice ESTERNO analizzato, non del nostro parser.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
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
    if is_explicit_multi_cve_chain(data):
        base.update(
            stato_estrazione="escluso_catena_multi_cve",
            nota="PoC con piu' CVE concatenate: non usato come evidenza isolata.",
        )
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


def apply_poc_to_minimal(minimal, pocs):
    """Non cambiare le 9 colonne, ne' cancellare candidati documentati."""
    if minimal['stato'] in ('candidato', 'fuori_perimetro'):
        return minimal
    confirmed = next((p for p in pocs if p['stato_estrazione'] == 'evidenza_payload'
                      and p['comportamento'] == 'process_execution'), None)
    if not confirmed:
        if (minimal['stato'] in ('evidenza_insufficiente', 'solo_ipotesi')
                and any(p['stato_estrazione'] == 'escluso_catena_multi_cve' for p in pocs)):
            return {**minimal, 'nota': 'PoC multi-CVE escluso: nessun sensore derivato dalla catena.'}
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
