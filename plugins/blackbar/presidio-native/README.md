# Native analyzer (no Docker)

A first-class alternative to the Docker analyzer for running blackbar's PII/PHI/
financial detection **without containers**. It serves the exact same
`POST /analyze` API on `:5002`, so the plugin needs no configuration change —
`presidio_client.py` talks to `http://localhost:5002` in either mode.

`analyzer_service.py` here is the **single source of truth** for detection
coverage; the Docker image (`./Dockerfile`, same directory) bakes the very same
file, so Docker and native detect identically.

## When to use which

| | Docker | Native |
|---|---|---|
| Best for | hosts already running containers | no-Docker hosts, or when Docker is unavailable (e.g. AppArmor/VPN-MTU issues on newer kernels) |
| Setup | `docker compose up -d` | `./setup.sh` then `./run.sh` |
| Coverage | identical | identical |

## Quickstart

```bash
cd plugins/blackbar/presidio-native
./setup.sh                 # venv + presidio + flask + spaCy models (md, 6 langs)
./run.sh                   # serves 127.0.0.1:5002
curl -s localhost:5002/health
```

The service binds **`127.0.0.1` by default** — it processes PII, so it stays off
the LAN. Override only if you truly need remote access:

```bash
BLACKBAR_BIND_HOST=0.0.0.0 ./run.sh      # exposes :5002 on all interfaces
```

(The Docker image sets `BLACKBAR_BIND_HOST=0.0.0.0` internally so the container is
reachable through the port map, while compose still publishes it on `127.0.0.1`.)

Smaller / larger footprint:

```bash
BLACKBAR_LANGUAGES="en es" ./setup.sh        # just two languages
BLACKBAR_MODEL_SIZE=lg ./setup.sh            # large models, higher recall
```

## Coverage

- **Tier 1 (Presidio built-in, all languages):** PERSON, LOCATION, EMAIL_ADDRESS,
  PHONE_NUMBER, URL, IP_ADDRESS, MAC_ADDRESS, DATE_TIME, CREDIT_CARD, IBAN_CODE,
  CRYPTO, MEDICAL_LICENSE, and national IDs (ES_NIF/ES_NIE, IT_*, UK_NHS,
  US_SSN/passport/driver, …).
- **Tier 2 (custom, context-aware):** SWIFT_BIC, EU_VAT, PT_NIF, DE_STEUER_ID,
  FR_NIR_SSN (French SSN — also a health identifier), ES_SSN (Spanish social
  security), HEALTH_RECORD, ICD10_CODE, PASSPORT_GENERIC.
- **Special categories (GDPR Art. 9), two layers:**
  - *Layer 1 (on):* multilingual lexicons for explicit mentions —
    `HEALTH_CONDITION`, `RELIGIOUS_BELIEF`, `POLITICAL_OPINION`, `ETHNIC_ORIGIN`,
    `SEXUAL_ORIENTATION`, `TRADE_UNION`. Extend the `SPECIAL_CATEGORIES` list in
    `analyzer_service.py`.
  - *Layer 2 (optional):* local zero-shot classifier in `zeroshot.py` for
    paraphrase. Enable with `BLACKBAR_ENABLE_ZEROSHOT=1` after
    `pip install -r requirements-zeroshot.txt` (large: torch + a ~280 MB model).
    Sentence-level, slower, best-effort — runs entirely on your machine.

```bash
# enable Layer 2 (after installing requirements-zeroshot.txt into the venv)
BLACKBAR_ENABLE_ZEROSHOT=1 ./run.sh
```

## Run as a service (optional, systemd --user)

One shared instance for every Claude Code session, every parallel VS Code window,
and every repo — started once at login, not per project:

```ini
# ~/.config/systemd/user/blackbar-analyzer.service
[Unit]
Description=blackbar native Presidio analyzer (localhost:5002)
After=network-online.target
Wants=network-online.target
[Service]
Environment=PORT=5002
Environment=BLACKBAR_LANGUAGES=en,es,fr,de,it,pt
Environment=BLACKBAR_MODEL_SIZE=md
ExecStart=%h/.local/share/blackbar/presidio-venv/bin/python %h/dev/e2its/myrmion-blackbar-pii-guard/plugins/blackbar/presidio-native/analyzer_service.py
Restart=on-failure
RestartSec=3
TimeoutStartSec=120
[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now blackbar-analyzer
loginctl enable-linger "$USER"     # keep it up at boot, without a graphical login
```

Binds `127.0.0.1` (the `analyzer_service.py` default). Manage with
`systemctl --user {status,restart,stop} blackbar-analyzer` and
`journalctl --user -u blackbar-analyzer -f`.
