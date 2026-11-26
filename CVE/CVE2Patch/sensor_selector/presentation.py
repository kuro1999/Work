"""La sola matrice finale (9 colonne), indipendente da sintassi Falco/ECS.

Non modifica le evidenze: traduce gli attributi in etichette leggibili.
Le strutture dettagliate sono salvate in CSV tecnici separati.
"""
from __future__ import annotations
from .rules import HOST_SCOPES


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
    "poc_multi_cve_excluded": "README con catena multi-CVE: evidenza scartata per questo caso.",
}


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


def simple_row(full, rules, vulhub):
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
