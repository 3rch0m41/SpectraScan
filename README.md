# Network Scanner

Uno scanner di rete scritto in Python che esegue in un unico flusso la ricognizione base di un host: scansione delle porte TCP, banner grabbing e analisi delle vulnerabilità tramite Nmap.

> ⚠️ **Disclaimer:** usa questo strumento **solo su sistemi di tua proprietà o per cui hai un'autorizzazione esplicita**. La scansione non autorizzata di reti e host può essere illegale. L'autore non è responsabile di usi impropri.

---

## Indice

- [Network Scanner](#network-scanner)
  - [Indice](#indice)
  - [Come funziona](#come-funziona)
  - [Requisiti](#requisiti)
  - [Installazione](#installazione)
  - [Utilizzo](#utilizzo)
  - [Esempio di output](#esempio-di-output)
  - [Struttura del codice](#struttura-del-codice)
  - [Limiti noti](#limiti-noti)
  - [Roadmap](#roadmap)
    - [✅ v1.1 — Completata](#-v11--completata)
    - [🚧 v1.2 — Prestazioni](#-v12--prestazioni)
    - [🔜 v1.3 — Qualità dei risultati](#-v13--qualità-dei-risultati)
    - [🔭 v2.0 — Estensione del perimetro](#-v20--estensione-del-perimetro)
  - [Autore](#autore)

---

## Come funziona

La scansione avviene in tre fasi consecutive.

**1. Port scan (TCP connect)**
Per ogni porta nel range indicato, lo script tenta un handshake TCP completo. Se la connessione riesce, la porta viene considerata aperta. Il range è inclusivo: con `-s 1 -e 1024` vengono controllate le porte da 1 a 1024 comprese.

**2. Banner grabbing**
Su ogni porta aperta, lo script si connette e legge i primi byte inviati dal servizio. Funziona con i servizi che si presentano per primi al client, come SSH, FTP e SMTP, e permette di identificare software e versione.

**3. Vulnerability scan (Nmap)**
Lancia Nmap con rilevamento del sistema operativo (`-O`), dei servizi e delle versioni (`-sV`) e con gli script NSE della categoria `vuln`. Per ogni porta vengono riportati il servizio individuato e l'output degli script, insieme alle ipotesi sul sistema operativo con la relativa accuratezza.

Al termine viene mostrato il tempo totale impiegato.

## Requisiti

- Python 3.6 o superiore
- [Nmap](https://nmap.org/download.html) installato e presente nel `PATH`
- Libreria [`python-nmap`](https://pypi.org/project/python-nmap/)
- Privilegi di root o di amministratore per il rilevamento del sistema operativo (`-O`)

## Installazione

```bash
git clone https://github.com/<tuo-utente>/<nome-repo>.git
cd <nome-repo>
pip install python-nmap
```

Verifica che Nmap sia installato:

```bash
nmap --version
```

## Utilizzo

**Da riga di comando**

```bash
sudo python network_scanner.py 192.168.1.10 -s 1 -e 1024
```

| Argomento | Descrizione |

|---|---|
| `target` | Indirizzo IP o hostname da scansionare |
| `-s`, `--start` | Prima porta del range (inclusa, 1–65535) |
| `-e`, `--end` | Ultima porta del range (inclusa, 1–65535) |
| `-h`, `--help` | Mostra l'help |

**In modalità interattiva**

Se avvii lo script senza argomenti, i parametri mancanti ti vengono chiesti a terminale:

```bash
sudo python network_scanner.py
```

**Come modulo**

```python
from network_scanner import network_scan

network_scan("192.168.1.10", 1, 1024)
```

La documentazione completa delle funzioni è consultabile con:

```bash
python -m pydoc network_scanner
```

## Esempio di output

```text
Starting network scan on 192.168.1.10:
Scanning target: 192.168.1.10 for open ports from 1 to 1024...
Open ports found: [22, 80]
Grabbing banner for 192.168.1.10:22...
Banner for 192.168.1.10:22 - SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
Grabbing banner for 192.168.1.10:80...
No banner found for port 80.
Performing vulnerability scan on 192.168.1.10...
Operating system guesses:
  - Linux 5.0 - 5.14 (98% accuracy)

[tcp/80] http Apache httpd 2.4.52
  http-csrf:
    Couldn't find any CSRF vulnerabilities.
  ...
Scan completed in 0:03:12.481920
```

*L'output è indicativo e varia in base al target.*

## Struttura del codice

| Funzione | Ruolo |

|---|---|

| `port_scan()` | TCP connect scan sul range di porte |
| `banner_grab()` | Lettura del banner di un servizio |
| `vulnerability_scan()` | Scansione Nmap con OS detection, `-sV` e script `vuln` |
| `print_vuln_results()` | Stampa di hostname, sistema operativo e output NSE |
| `network_scan()` | Orchestrazione delle tre fasi e misura del tempo |
| `parse_args()` | Gestione degli argomenti da riga di comando e dei prompt interattivi |

## Limiti noti

- **Port scan lento:** la scansione è sequenziale con un timeout di 1 secondo per porta, quindi range ampi su host filtrati possono richiedere molto tempo.
- **Porte analizzate da Nmap:** la fase Nmap usa le porte di default di Nmap, non il range indicato, e può durare diversi minuti.
- **Servizi senza banner:** i servizi che attendono una richiesta dal client, come HTTP, di solito non restituiscono un banner.
- **Protocolli supportati:** sono supportati solo IPv4 e TCP.

---

## Roadmap

### ✅ v1.1 — Completata

- [x] Range di porte inclusivo
- [x] Timeout applicato anche alla connessione del banner grabbing
- [x] Output corretto degli script NSE `vuln`, porta per porta
- [x] Supporto agli hostname nei risultati Nmap
- [x] Interfaccia da riga di comando con `argparse`, con fallback interattivo
- [x] Validazione delle porte e interruzione pulita con Ctrl+C
- [x] Documentazione completa del codice tramite docstring

### 🚧 v1.2 — Prestazioni

- [ ] Port scan concorrente con `ThreadPoolExecutor` o `asyncio`
- [ ] Timeout configurabile da riga di comando
- [ ] Scansione Nmap limitata alle sole porte trovate aperte
- [ ] Flag `--no-vuln` per una ricognizione rapida senza Nmap
- [ ] Controllo iniziale della presenza di Nmap e dei privilegi di root

### 🔜 v1.3 — Qualità dei risultati

- [ ] Probe attivi per i servizi "silenziosi", come la richiesta HTTP `HEAD` e il banner TLS sulla 443
- [ ] Esportazione dei risultati in JSON e CSV (`-o report.json`)
- [ ] Logging con livelli di verbosità (`-v`, `-vv`)

### 🔭 v2.0 — Estensione del perimetro

- [ ] Scansione di più target: range CIDR e file di host
- [ ] Fase di host discovery
- [ ] Supporto IPv6
- [ ] Scansione UDP opzionale (`-sU`)
- [ ] Test automatici con `pytest`

Suggerimenti e segnalazioni sono benvenuti tramite le [Issues](../../issues).

---

## Autore

**Giulio Malini** (*Erchomai*)