"""Utility comuni e configurazione essenziale.

Questo modulo non interpreta vulnerabilita': gestisce i dati di input, gli URL
ammessi e la scrittura dei CSV. Nessuna esecuzione di PoC.
"""
from __future__ import annotations
import csv
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "1.4.0"
USER_AGENT = "CVE2Patch-Sensor-Selector/1.4.0 (academic observability analysis)"
MAX_BYTES = 4 * 1024 * 1024
POC_MAX_BYTES = 200_000
POC_API_BUDGET_DEFAULT = 45


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


def default_input():
    """Trova il dataset con lo script nella cartella CVE oppure in CVE2Patch.

    Non dipende dalla directory da cui si lancia Python: usa anche la
    posizione del pacchetto. --input resta disponibile per percorsi diversi.
    """
    script_dir = Path(__file__).resolve().parent.parent
    cwd = Path.cwd().resolve()
    roots = [script_dir, script_dir / "CVE2Patch", script_dir.parent,
             script_dir.parent / "CVE2Patch", cwd, cwd / "CVE2Patch"]
    for root in uniq(roots):
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


def safe_vulhub_readme_url(path: str) -> str:
    """Evita path traversal/SSRF; la sorgente e' sempre il repository Vulhub."""
    parts = str(path).split("/")
    if len(parts) != 2 or any(not re.fullmatch(r"[A-Za-z0-9._-]+", p) or p in (".", "..") for p in parts):
        raise ValueError("Percorso Vulhub non supportato")
    return f"https://raw.githubusercontent.com/vulhub/vulhub/master/{parts[0]}/{parts[1]}/README.md"


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError("Nessun risultato da scrivere")
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


# Non bastano due richieste HTTP: una *chain multi-CVE* richiede due
# vulnerabilita' distinte. Per evitare falsi positivi, richiediamo sia
# almeno due CVE che un'espressione esplicita di dipendenza/catena.
_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_CHAIN_WORDS = re.compile(
    r"\b(?:exploit[ -]?chain|vulnerability[ -]?chain|cve[ -]?chain|"
    r"chain|chaining|chained|combined exploits?|multi[ -]?cve|"
    r"requires? (?:another |a second )?cve|chain of (?:two|multiple) vulnerabilit)\b",
    re.I,
)


def is_explicit_multi_cve_chain(text: str) -> bool:
    """Rileva solo PoC che dichiarano esplicitamente una catena multi-CVE.

    Non esclude PoC con due richieste (es. CraftCMS), ne' un README che
    cita incidentalmente una vecchia CVE nelle note bibliografiche.
    In caso di dubbio restituisce False: il criterio e' volutamente ristretto.
    """
    # Guardiamo l'intestazione e le frasi vicine, non tutti i riferimenti
    # sparsi nel codice/documento.
    header = text[:3500]
    ids = {x.upper() for x in _CVE_ID.findall(header)}
    if len(ids) < 2:
        return False
    for hit in _CHAIN_WORDS.finditer(header):
        neighborhood = header[max(0, hit.start()-350):min(len(header), hit.end()+500)]
        if len({x.upper() for x in _CVE_ID.findall(neighborhood)}) >= 2:
            return True
    return False
