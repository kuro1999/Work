"""Aggiunge Tetragon come terzo sensore, senza interpretare nuovi exploit.

Mappatura **documentale** delle capacita':
- process_execution: evento ``process_exec`` disponibile nella configurazione base;
- file_activity/file_access e network_activity: osservabilita' condizionata a una
  TracingPolicy appropriata, da configurare e verificare nell'ambiente reale.

Non vengono generate policy, non si eseguono PoC e non si promuovono CVE
senza evidenze. Il risultato resta la stessa riga a nove colonne.
"""
from __future__ import annotations


TETRAGON_DOCS = {
    "process_exec": "https://tetragon.io/docs/use-cases/process-lifecycle/",
    "tracing_policy": "https://tetragon.io/docs/concepts/tracing-policy/",
}


def capability_labels(families: set[str]) -> list[str]:
    """Capacita' coerenti con famiglie di eventi gia' documentate.

    Non includiamo ``process_activity`` generico, ``buffer_content`` o
    descrizioni NVD: non bastano a indicare un evento Tetragon preciso.
    """
    result = []
    if "process_execution" in families:
        result.append("process_exec default")
    if "file_access" in families or "file_activity" in families:
        result.append("file: TracingPolicy richiesta")
    if "network_activity" in families:
        result.append("rete: TracingPolicy richiesta")
    return result


def add_tetragon_to_row(row: dict, selection_detail: dict) -> dict:
    """Integra la cella sensori, senza cambiare stato, fonte o altre colonne.

    La riga PoC viene costruita dopo la selezione principale; la riconosciamo
    esplicitamente per il payload di *process execution* gia' identificato,
    senza riesaminare ne' interpretare il codice dell'exploit.
    """
    if row.get("stato") not in ("candidato", "da_verificare"):
        return row
    if not row.get("sensore_candidato"):
        return row

    families = {
        value
        for key in ("host_event_families", "vulhub_observable_families")
        for value in selection_detail.get(key, "").split(";")
        if value
    }
    if (row.get("fonte", "").startswith("PoC ")
            and row.get("osservabile_evento", "").startswith("esecuzione processo")):
        families.add("process_execution")

    capabilities = capability_labels(families)
    if not capabilities:
        return row

    result = dict(row)
    result["sensore_candidato"] = row["sensore_candidato"] + "; Tetragon (" + "; ".join(capabilities) + ")"
    # Nota esplicita quando l'osservabilita' NON e' disponibile di default.
    if any("TracingPolicy richiesta" in label for label in capabilities):
        result["nota"] = (row["nota"].rstrip() + " Tetragon: configurare una TracingPolicy; non testata.").strip()
    return result
