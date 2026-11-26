# CVE2Patch — Sensor Selector (Falco + Elastic + Tetragon)

Questo progetto **non crea regole di detection** e **non esegue exploit**. Analizza documenti e regole gia' associati alle CVE per formulare un'ipotesi di **osservabile host** e del **sensore che potrebbe raccoglierlo**.

**Domanda di ricerca:** dato il comportamento documentato di una CVE, quale evento di sistema serve e quale sensore puo' osservarlo?

## 1. Dove mettere i file

Consigliato: copia questi file **dentro il repository `CVE2Patch`**, accanto al notebook originale. Il dataset `output/initial_pool.csv` deve essere gia' presente oppure passato con `--input`. Non devi cancellare o modificare `cve.ipynb` o `initial_pool.csv`. Gli output sono rigenerati a ogni esecuzione.

```text
CVE2Patch/
├── cve.ipynb                          # Notebook originale: costruisce il dataset
├── cve2patch_sensor_selector.py       # File da eseguire
├── sensor_selector/
│   ├── __init__.py
│   ├── __main__.py
│   ├── utils.py
│   ├── cache.py
│   ├── rules.py
│   ├── vulhub.py
│   ├── poc.py
│   ├── selection.py
│   ├── tetragon.py                 # Mappatura delle capacita' Tetragon
│   ├── presentation.py
│   └── cli.py
├── README_SENSOR_SELECTOR.md         # Questa guida (non sovrascrive README.md)
├── requirements-sensor-selector.txt
└── output/
    ├── initial_pool.csv               # Input consolidato: NON modificato
    ├── sensor_matrix.csv               # Risultato principale: 9 colonne
    ├── sensor_dettagli/                # Dettagli tecnici e provenienza
    ├── sensor_rule_cache/              # Cache delle regole
    ├── sensor_vulhub_cache/            # Cache dei README
    └── sensor_poc_cache/               # Cache dei PoC
```

Se preferisci tenere lo script nella cartella **`CVE`**, come prima, copia nella stessa cartella sia `cve2patch_sensor_selector.py` sia `sensor_selector/`: il programma cerca anche `CVE2Patch/output/initial_pool.csv`.

## 2. Comandi Windows / PowerShell

Da dentro `CVE2Patch`:

```powershell
python -m pip install -r .\requirements-sensor-selector.txt
python .\cve2patch_sensor_selector.py --offline
```

`--offline` riutilizza le cache gia' scaricate e non fa richieste Internet. Se mancano file in cache, saranno marcati come non disponibili, non come assenza di sensori.

Se devi recuperare soltanto i file mancanti, in una seconda esecuzione:

```powershell
python .\cve2patch_sensor_selector.py
```

**Altri comandi facoltativi:**

```powershell
python .\cve2patch_sensor_selector.py --help
python .\cve2patch_sensor_selector.py --offline --skip-poc
python .\cve2patch_sensor_selector.py --offline --include-sigma
```

`--include-sigma` serve solo come esperimento facoltativo: **Sigma rimane sospeso per default**, come deciso. Tracee resta escluso. Tetragon partecipa solo come sensore candidato, senza generare TracingPolicy.

## 3. La pipeline in parole semplici

```text
initial_pool.csv (109 CVE, NVD e link esistenti)
            |
            v
[1] rules.py       → legge regole Falco/Elastic: evento e campi richiesti
            |
[2] vulhub.py      → legge README: comportamento del PoC descritto
            |
[3] poc.py         → se necessario, legge STATICAMENTE pochi file PoC
            |
[4] selection.py   → collega comportamento → evento → sensori compatibili
            |
[5] presentation.py→ riduce tutto a una matrice leggibile di 9 colonne
            |
[6] tetragon.py    → aggiunge Tetragon solo a osservabili gia' individuati
            |
            v
sensor_matrix.csv
```

Il programma **non seleziona Falco perche' trova una regola Falco**: prima individua l'evento, poi ragiona sulle capacita' dei sensori. Se non possiede evidenze adeguate, non forza una scelta.

## 4. Che cosa fa ogni modulo

| File | Responsabilita' | Funzioni principali |
|---|---|---|
| `cve2patch_sensor_selector.py` | Punto d'ingresso semplice | Lancia `cli.main()` |
| `sensor_selector/cli.py` | Coordina le fasi; gestisce input, output e opzioni | `main()` |
| `sensor_selector/utils.py` | Cerca il dataset, normalizza i dati, controlla gli URL e scrive CSV | `default_input`, `csv_items`, `write_csv`, `is_explicit_multi_cve_chain` |
| `sensor_selector/cache.py` | Legge/scarica regole, README e PoC, con cache e limiti di download | `RuleCache`, `VulhubCache`, `PocCache` |
| `sensor_selector/rules.py` | Legge le regole Falco/Elastic; Sigma facoltativo | `parse_falco`, `parse_elastic`, `parse_sigma` |
| `sensor_selector/vulhub.py` | Identifica le sezioni di exploit dei README ed estrae indizi espliciti | `attack_sections`, `parse_vulhub_readme` |
| `sensor_selector/poc.py` | Legge staticamente pochi file PoC, senza eseguirli | `poc_attack_payload_evidence`, `analyze_poc_file` |
| `sensor_selector/selection.py` | Combina le evidenze e decide quando proporre o NON proporre un sensore | `aggregate_cve`, `integrate_vulhub` |
| `sensor_selector/tetragon.py` | Mappa eventi gia' documentati su capacita' Tetragon default/TracingPolicy senza cambiare lo stato | `capability_labels`, `add_tetragon_to_row` |
| `sensor_selector/presentation.py` | Converte i dati tecnici nella matrice minimale | `simple_row`, `neutral_required_fields` |

### Cosa significa esattamente *parser*?

Il **parser** e' il codice che legge un testo e ne estrae informazioni strutturate. Non e' un agente AI e non comprende liberamente ogni exploit.

**Parser Falco:** identifica la regola corretta nel file YAML, legge `condition`, espande le macro disponibili nello stesso file, estrae eventi come `execve` e campi come `proc.name`. La presenza di un evento rende Falco *candidato*, non dimostra che l'attacco venga rilevato sempre.

**Parser Elastic:** legge il TOML e la query EQL/ES|QL; riconosce categorie quali `process` o `file`, i campi ECS e le sorgenti endpoint indicate da indici e integrazioni. Il parser **non verifica** come e' configurato Elastic Defend.

**Parser Sigma (facoltativo):** legge `logsource` e campi della `detection`. Non tratta Sigma come un sensore fisico. Senza `--include-sigma` non usa queste regole nella selezione.

**Parser Vulhub:** cerca sezioni del README come `Exploit` / `Reproduce`, evitando quelle dedicate al setup. Se trova un meccanismo esplicito come `Runtime.getRuntime().exec(...)`, ipotizza l'esecuzione di un processo sul bersaglio. Un semplice `/etc/passwd` nel README **non basta** a dimostrare una syscall: il caso resta `da_verificare`.

**Parser PoC:** scarica solo file di testo/codice in repository chiaramente associati alla CVE e legge il codice **senza eseguirlo**. Per PoC Python usa `ast.parse` per trovare stringhe che contengono meccanismi di esecuzione espliciti; cerca inoltre un contesto di invio HTTP. Un `os.system(...)` locale nello script dell'attaccante **non e' evidenza** di una syscall sul bersaglio. Se il collegamento tra payload e server non e' certo, restituisce `da_verificare`.

### Come vengono escluse le exploit chain?

Il programma ora scarta la **fonte PoC/README** quando essa descrive esplicitamente una catena che usa **almeno due CVE diverse**. Questa evidenza non viene usata per attribuire un sensore a una singola CVE. La riga della CVE **rimane nel dataset congelato**, perche' potrebbero esistere PoC autonomi validi. E' una scelta deliberata: non alteriamo il dataset originale durante la selezione dei sensori.

La presenza di *due richieste HTTP* in un PoC non basta per parlare di chain multi-CVE; due passaggi possono riguardare una sola vulnerabilita'. Il controllo e' prudente: riconosce le catene *esplicitamente dichiarate*, non tutte quelle possibili.

## 5. Regola di decisione per i sensori

1. **Comportamento chiaro dal documento?** Per esempio l'avvio di un processo esterno.
2. **Evento host plausibile?** Per esempio esecuzione di un processo (`execve` / `execveat`).
3. **Sensore compatibile?** Falco Modern eBPF, Elastic Defend e Tetragon, con i prerequisiti di raccolta specifici, possono osservare le famiglie di eventi pertinenti.
4. **Evidenza specifica insufficiente?** Non selezionare automaticamente un sensore.

Le informazioni NVD nel CSV (descrizione, CWE, riferimenti) sono contesto; ad esempio la dicitura *Remote Code Execution* **non implica sempre** che venga eseguita la syscall `execve`.

**Nota:** non abbiamo un confronto sperimentale di copertura tra Falco, Elastic e Tetragon. Il risultato e' una proposta **documentale**, non una prova di detection o di prevenzione.

## 5-bis. Tetragon: solo le tre modifiche richieste

**Non abbiamo modificato parser, dataset o criteri di evidenza.** `tetragon.py` viene richiamato dopo l'analisi PoC e aggiunge, ove giustificato, Tetragon nella stessa colonna `sensore_candidato`.

| Famiglia dell'evento gia' documentato | Tetragon | Requisito |
|---|---|---|
| `process_execution` | `process_exec` | Di default nella configurazione base |
| `file_access` / `file_activity` | Tracciamento file | Richiede una `TracingPolicy` specifica |
| `network_activity` | Tracciamento rete | Richiede una `TracingPolicy` specifica |
| `process_activity` generica / `buffer_content` / sola descrizione NVD | Nessuna aggiunta automatica | Evento non sufficientemente specifico per la nostra mappatura conservativa |

Esempi del contenuto della **stessa colonna**:
- `Falco (Modern eBPF); Elastic Defend; Tetragon (process_exec default)`
- `Falco (Modern eBPF); Tetragon (file: TracingPolicy richiesta)` — ancora `da_verificare` se il file compare solo nel payload

Se un caso combina processo e file, Tetragon riporta entrambe le modalita'. **Non viene creata, installata o testata alcuna TracingPolicy**. La compatibilita' e' una proposta documentale; una policy configurata male o un kernel non compatibile possono impedire la raccolta.

Il numero delle CVE `candidato`, `da_verificare`, `solo_ipotesi`, `evidenza_insufficiente` **non cambia a causa di Tetragon**. La logica scarta ancora i PoC multi-CVE; Sigma resta sospeso.

Fonti ufficiali:
- https://tetragon.io/docs/use-cases/process-lifecycle/
- https://tetragon.io/docs/concepts/tracing-policy/
- https://tetragon.io/docs/use-cases/

## 6. La matrice finale: SEMPRE nove colonne

| Colonna | Significato |
|---|---|
| `cve_id` | Identificatore CVE |
| `comportamento` | Comportamento dedotto dalle fonti |
| `osservabile_evento` | Evento host osservabile, quando identificato |
| `campi_necessari` | Nomi semantici, non sintassi di un prodotto |
| `sensore_candidato` | Falco / Elastic Defend / Tetragon, solo se giustificato; il requisito di TracingPolicy compare qui |
| `fonte` | Documento che motiva l'ipotesi |
| `link_fonte` | URL dell'evidenza |
| `stato` | Candidato, da verificare, solo ipotesi o insufficiente |
| `nota` | Una breve limitazione concreta |

Gli output intermedi (`sensor_rules.csv`, `sensor_vulhub.csv`, `sensor_poc.csv`) restano nella sottocartella `sensor_dettagli`, **non vanno consultati quotidianamente**: servono solo a ricostruire una selezione dubbia.

### Come interpretare `stato`

- **`candidato`**: c'e' una evidenza documentale sufficiente per proporre un sensore (non testato).
- **`da_verificare`**: c'e' un segnale possibile, ma il legame con il bersaglio o la syscall non e' ancora certo.
- **`solo_ipotesi`**: la descrizione fornisce una categoria generica, senza evento host concreto.
- **`evidenza_insufficiente`**: le fonti esaminate non permettono una selezione motivata; **non significa “CVE impossibile da rilevare”**.

## 7. Supporto Tetragon

Il modulo `tetragon.py` distingue gli eventi osservabili di default da quelli che richiedono una `TracingPolicy`. `cli.py` applica questa mappatura ai risultati senza promuovere lo stato di evidenza delle CVE.

La selezione mantiene nove colonne; Sigma resta facoltativo e i PoC multi-CVE espliciti non contribuiscono alle evidenze.

## 8. Riproducibilita' e limiti

Per ottenere risultati confrontabili tra macchine bisogna usare lo stesso dataset e le stesse fonti in cache. Con `--offline`, i riferimenti non presenti nella cache vengono trattati come non disponibili. I file di dettaglio contengono gli estratti delle fonti e i relativi hash, utili per la tracciabilita'.

I file sotto `output/sensor_*_cache/` possono essere esclusi dal repository, ma per riprodurre esattamente le fonti usate devi conservarne uno snapshot: i branch GitHub `main/master` possono cambiare.

**Il programma non genera un report di esecuzione JSON:** produce `sensor_matrix.csv` e, separatamente, i CSV di dettaglio per ispezionare le evidenze. Non esegue exploit e non valida sperimentalmente i sensori.

## 9. File da escludere dal repository

Se il repository ha gia' un `.gitignore`, **aggiungi** soltanto queste righe:

```gitignore
**/__pycache__/
**/.ipynb_checkpoints/
**/.pytest_cache/
**/sensor_rule_cache/
**/sensor_vulhub_cache/
**/sensor_poc_cache/
.env
.venv/
```

Non cancellare il `.gitignore` originale e non inserire il token GitHub nel codice.
