# PhantomPot-v2: Multi-Protocol Deception Honeypot & ML-Driven Threat Analytics
## Comprehensive Technical Presentation Blueprint & Defense Guide

> **Document Type:** Master Presentation Content & Technical Defense Reference  
> **Target Audience:** Academic Evaluation Committee, Cybersecurity Examiners, Technical Audience  
> **Source Repository:** `PhantomPot-v2`  
> **Location:** `docs/PhantomPot_Presentation_Content.md`  
> **Generated:** October 2026 (Reflecting codebase state as of April–October 2026)

---

## Executive Presentation Structure

This document is organized into **24 slide modules** structured across 7 key presentation themes:
1. **Introduction & Context (Slides 1–4):** Title, Problem Statement, Motivation & Objectives, Proposed Solution.
2. **Architecture & Technology Stack (Slides 5–7):** High-Level Architecture, Tech Stack, End-to-End Data Lifecycle.
3. **Multi-Protocol Emulation & Deception Engines (Slides 8–11):** SSH Honeypot & Fake Shell, HTTP Deception & Evasion Normalizer, FTP & Telnet Protocols, Decoy Authentication & Credential Safety.
4. **Telemetry, Session Management & Event Schema (Slides 12–13):** Shared Session Management Pipeline, Dual-Stream SIEM-Ready Logging.
5. **Machine Learning Anomaly Detection (Slides 14–16):** ML Pipeline & Feature Engineering, Isolation Forest Model & Threshold Calibration, Multi-Tier Confidence Scoring.
6. **Analytics, Investigation & SOC Operations (Slides 17–19):** Streamlit SOC Dashboard, Attack Flow Reconstruction & Correlation, Automated Defense Recommendations & PDF/HTML Reports.
7. **Empirical Evaluation, Limitations & Conclusion (Slides 20–24):** Objective 4 KPI Framework, Experimental Results & Dataset Analysis, Real-World Defensive Utility, Limitations & Engineering Trade-offs, Future Roadmap & Conclusion.

---

# SLIDE 1: Title Slide & Project Overview

### Slide Metadata
- **Slide Title:** PhantomPot-v2: A Multi-Protocol Deception Honeypot and ML-Powered Threat Analytics Platform
- **Slide Number:** 1 / 24
- **Category:** Introduction

### Visual / Layout Recommendations
- Clean modern title card with project badge (`◈ PhantomPot-v2`).
- Three highlight pills: `4 Concurrent Protocols` | `Unsupervised ML Scoring` | `Evidence-First SOC Dashboard`.
- Student/Presenter details, Department of Computer Science & Engineering / Cybersecurity, Institutional Affiliation, Supervisor name.

### Slide Bullet Points (On-Slide Content)
* **Project Name:** PhantomPot-v2
* **Domain:** Active Cyber Defense, Deception Technology & Anomaly Detection
* **Core Philosophy:** Protocol emulation, thread-safe session tracking, and unsupervised behavioral anomaly scoring without risk to host infrastructure.
* **Key Innovations:**
  * Multi-protocol listener suite covering SSH, HTTP, FTP, and Telnet on isolated ports.
  * 10-feature behavioral pipeline evaluated by a calibrated Isolation Forest model.
  * Dual-stream JSONL telemetry decoupling session summaries from immutable event streams.
  * Evidence-first attack-flow reconstruction with automated security recommendations and dependency-free PDF/HTML reporting.

### Comprehensive Technical Explanation & Speaker Notes
"Good morning, respected members of the evaluation committee. Today, I am presenting **PhantomPot-v2**, an end-to-end cyber deception and threat intelligence platform designed to capture, log, and analyze adversary interactions across multiple standard network protocols. 

In traditional defensive architectures, perimeter security mechanisms like firewalls and signature-based IDSes are fundamentally reactive. Attackers who bypass the perimeter often navigate internal networks undetected. Honeypots solve this problem by deploying decoy systems that have no production value; therefore, almost any interaction with a honeypot represents unauthorized discovery, scanning, or exploitation.

PhantomPot-v2 addresses three fundamental challenges in deception technology:
1. **Protocol Breadth:** Emulating multiple entry points (SSH, HTTP, FTP, Telnet) concurrently while sharing a unified telemetry pipeline.
2. **Behavioral Analytics:** Extracting numerical session dynamics to detect zero-day or abnormal interactions using an Isolation Forest anomaly detector.
3. **Investigative Usability:** Providing SOC analysts with timeline reconstruction, conservative session correlation, actionable mitigation guidance, and interactive dashboards."

### Viva / Defense Tip
*If asked:* *"Why 'v2'?"*  
*Answer:* *"Version 1 was a monolithic prototype where protocol listeners (notably HTTP) operated independently, had disparate logging schemas, lacked comprehensive evasion normalization, and did not incorporate attack-flow reconstruction or KPI measurement. Version 2 re-architected the entire system around a thread-safe `SessionManager`, a standardized 10-feature ML inference engine, versioned JSONL event streaming, and an Objective 4 KPI evaluation framework."*

---

# SLIDE 2: Problem Statement & Threat Landscape

### Slide Metadata
- **Slide Title:** Problem Statement: Visibility Gaps in Modern Threat Detection
- **Slide Number:** 2 / 24
- **Category:** Introduction & Context

### Visual / Layout Recommendations
- Two-column contrast layout:
  - Left Column: *The Attacker Reality* (Automated scanners, credential stuffers, reconnaissance bots).
  - Right Column: *The Defender Deficiency* (Alert fatigue, perimeter blind spots, high false-positive rates).
- An illustrative graphic showing internet-wide scanners hitting open ports without generating meaningful context in traditional logs.

### Slide Bullet Points (On-Slide Content)
* **Perimeter Blindness:** Modern intrusions leverage automated scanning (Masscan, ZGrab, Nmap) and distributed credential stuffing that blend into benign background noise.
* **Alert Fatigue in SOCs:** Signature-based IDS/IPS generate thousands of daily alerts, making it difficult to distinguish automated probes from targeted multi-stage intrusions.
* **Single-Protocol Limitations:** Most open-source honeypots focus on a single protocol (e.g., Cowrie for SSH/Telnet, Glastopf/Snare for HTTP), leaving blind spots in cross-protocol attacker profiling.
* **The High-Interaction Dilemma:**
  * High-interaction honeypots (full VMs) carry severe lateral-movement and compromise risks.
  * Low-interaction honeypots often return static banners that automated scanners easily fingerprint and evade.
* **Need for Behavioral Scoring:** Static signatures cannot assess session-level behavioral intensity (e.g., rapid command bursts, credential iteration frequency).

### Comprehensive Technical Explanation & Speaker Notes
"Enterprise networks face continuous bombardment from automated bots, botnets (such as Mirai variants), and targeted threat actors. Standard perimeter security tools suffer from two main issues: they either miss attacks that utilize novel payloads or legitimate administrative tools ('living-off-the-land'), or they overwhelm analysts with thousands of uncontextualized alerts.

Furthermore, traditional honeypot deployments are often siloed. An analyst running an SSH honeypot like Cowrie cannot natively correlate whether the same IP also probed port 80 for web admin portals or tested port 21 for anonymous FTP access. 

Conversely, deploying full virtual machines as high-interaction honeypots introduces substantial operational risk: if an attacker achieves a kernel exploit, they can turn the honeypot into an attack pivot against internal production assets.

PhantomPot-v2 was engineered to solve this dilemma: it provides a **medium-interaction, multi-protocol emulation environment** that gives attackers realistic interactive feedback while maintaining absolute host isolation, safe credential handling, and automated anomaly quantification."

---

# SLIDE 3: Motivation & Research Objectives

### Slide Metadata
- **Slide Title:** Project Motivation & Core Objectives
- **Slide Number:** 3 / 24
- **Category:** Context & Objectives

### Visual / Layout Recommendations
- Four quadrant cards corresponding to the project's **Four Primary Objectives**:
  - `Objective 1: Multi-Protocol Honeypot System`
  - `Objective 2: Real-Time Detection & SIEM Logging`
  - `Objective 3: Threat Analysis & ML Anomaly Detection`
  - `Objective 4: System Effectiveness & KPI Evaluation`

### Slide Bullet Points (On-Slide Content)
* **Overarching Goal:** Build a safe, lightweight, observable honeypot framework capable of multi-protocol interaction, behavioral feature extraction, and automated threat triage.
* **Objective 1 — Multi-Protocol Emulation:**
  * Implement concurrent listeners for SSH (2222), HTTP (8888), FTP (2121), and Telnet (2323).
  * Provide dynamic, non-destructive interactive deception (simulated bash shell, decoy web portals, virtual filesystems).
* **Objective 2 — Real-Time Telemetry & Structured Ingestion:**
  * Design a centralized, thread-safe session lifecycle pipeline.
  * Output SIEM-compatible JSON Lines (`sessions.jsonl` summaries and `events.jsonl` micro-events).
* **Objective 3 — Behavioral Anomaly Scoring & Analytics:**
  * Extract 10 session-level behavioral features.
  * Train an unsupervised Isolation Forest model to score and categorize threat severity.
* **Objective 4 — Quantitative KPI Evaluation Framework:**
  * Validate system efficacy via 4 measurable KPIs: Detection Rate, Protocol Coverage, Logging Integrity, and Response Latency.

### Comprehensive Technical Explanation & Speaker Notes
"The motivation of this project is rooted in practical defensive engineering. Rather than simply setting up third-party tools, PhantomPot-v2 was designed from the ground up to explore how low-overhead Python socket programming, machine learning, and data engineering can combine into an integrated defensive platform.

The project is structured around four formally audited objectives:
- **Objective 1** focuses on network protocol handling, state machines, and deception fidelity.
- **Objective 2** enforces data engineering rigor: thread safety, structured schemas, timestamp normalization, and SIEM readiness.
- **Objective 3** applies machine learning to detect behavioral deviations without relying solely on static attack strings.
- **Objective 4** ensures academic and engineering accountability by subjecting the entire platform to automated stress tests, concurrent load validation, and metric logging."

---

# SLIDE 4: Proposed Solution & Key Value Proposition

### Slide Metadata
- **Slide Title:** The PhantomPot-v2 Solution Architecture
- **Slide Number:** 4 / 24
- **Category:** Proposed Solution

### Visual / Layout Recommendations
- High-level block diagram showing:
  - `Attacker Traffic` $\rightarrow$ `Multi-Protocol Listener Suite` $\rightarrow$ `Session Lifecycle Engine` $\rightarrow$ `ML Inference Engine` $\rightarrow$ `Dual Logging Streams` $\rightarrow$ `Streamlit SOC Dashboard & Reports`.
- Feature callout box: *Zero host execution | Automatic credential redaction | Sub-10ms logging overhead*.

### Slide Bullet Points (On-Slide Content)
* **Modular Multi-Protocol Listener Suite:** Concurrent listener threads handling SSH, HTTP, FTP, and Telnet via standard sockets and Paramiko.
* **Unified Lifecycle Engine:** Every connection across any protocol is ingested by a thread-safe `SessionManager` that normalizes timestamps, login attempts, and commands.
* **7-Stage HTTP Payload Normalization:** Unpacks obfuscated, double-encoded, and Unicode attacks before matching 40+ vulnerability signatures.
* **Isolation Forest Anomaly Scoring:** Evaluates interaction frequency, login intensity, command ratios, and temporal risk to classify sessions as `normal` or `attack`.
* **Safe Decoy Authentication:** Decoupled simulation policy (`DecoyAuthPolicy`) that satisfies attacker login prompts while ensuring host credentials and submitted passwords are never compromised or written to disk.
* **Full-Featured SOC Dashboard:** 11 analytical views offering KPI summaries, attack-flow timelines, conservative cross-protocol correlation, and printable audit reports.

### Comprehensive Technical Explanation & Speaker Notes
"What makes PhantomPot-v2 distinct is its holistic design. Many honeypot projects stop at logging raw text files. PhantomPot-v2 implements a complete pipeline:
From the moment a TCP handshake occurs on port 2222, 8888, 2121, or 2323, the connection is encapsulated in a managed session. Commands are intercepted and handled by fake state machines that simulate genuine system responses without ever invoking the OS shell (`subprocess.Popen` or `os.system` are never called on user inputs).

When the session terminates, it automatically passes through feature construction, normalization, and machine learning inference. The output is not just a raw log line, but an enriched security object containing severity ratings, decision confidence, attack tags, and timeline stages. This allows SOC analysts to immediately distinguish between a random web spider and an aggressive automated brute-force script."

---

# SLIDE 5: System Architecture & Component Interaction

### Slide Metadata
- **Slide Title:** System Architecture & Data Flow
- **Slide Number:** 5 / 24
- **Category:** Architecture & System Design

### Visual / Layout Recommendations
- Detailed Architecture Diagram (Mermaid layout recommended for presentation slides):

```
       [ External Attacker / Scanner Traffic ]
            │          │         │          │
         SSH:2222   HTTP:8888  FTP:2121  Telnet:2323
            │          │         │          │
     ┌──────▼──────────▼─────────▼──────────▼──────┐
     │           Protocol Handlers                 │
     │  (ssh_handler, http_server, ftp_handler,    │
     │   telnet_handler, fake_shell, payload_norm) │
     └──────────────────────┬──────────────────────┘
                            │ (Connection, Auth, Action events)
     ┌──────────────────────▼──────────────────────┐
     │        core.SessionManager & EventSink      │  ──► logs/events.jsonl
     │  (Thread-Safe Registry, DecoyAuthPolicy)    │      (Fine-Grained Micro-Events)
     └──────────────────────┬──────────────────────┘
                            │ (Finalize on Disconnect)
     ┌──────────────────────▼──────────────────────┐
     │           core.FeatureBuilder               │
     │   (10 Numerical Behavioral Features)        │
     └──────────────────────┬──────────────────────┘
                            │
     ┌──────────────────────▼──────────────────────┐
     │             ml.predict Pipeline             │
     │  (StandardScaler + Isolation Forest Model)  │
     └──────────────────────┬──────────────────────┘
                            │ (Enriched Session Summary)
     ┌──────────────────────▼──────────────────────┐
     │             core.HoneypotLogger             │  ──► logs/sessions.jsonl
     │        (Thread-Safe JSONL Serializer)       │      (Finalized Session Summaries)
     └──────────────────────┬──────────────────────┘
                            │
     ┌──────────────────────▼──────────────────────┐
     │         Streamlit SOC Dashboard             │
     │   (11 Analytical Views, Reports, KPIs)      │
     └─────────────────────────────────────────────┘
```

### Slide Bullet Points (On-Slide Content)
* **Separation of Concerns:** Protocol handling, lifecycle management, ML inference, and persistence are cleanly decoupled.
* **Concurrency Model:** Multi-threaded listener architecture using daemon threads spawned from `src/main.py`.
* **State Machine Decoupling:** Handlers remain stateless regarding persistence; they interact solely with `SessionManager`.
* **Dual Persistence Pipeline:**
  * **Event Stream (`logs/events.jsonl`):** Real-time, fine-grained micro-events written immediately during interaction.
  * **Session Summaries (`logs/sessions.jsonl`):** Consolidated, ML-enriched records emitted at session finalization.
* **Air-Gapped Simulation:** Zero reliance on external cloud APIs or host system user databases.

### Comprehensive Technical Explanation & Speaker Notes
"Let us walk through the architecture illustrated on this slide:
1. **Entrypoint (`src/main.py`):** Spawns three background daemon threads for HTTP, FTP, and Telnet, while the SSH server occupies the main thread to ensure clean POSIX signal handling on `Ctrl-C`.
2. **Protocol Listeners:** Listen on non-privileged high ports (2222, 8888, 2121, 2323). Each incoming socket connection receives a dedicated client thread.
3. **Session Interception (`core/session_manager.py`):** The client handler immediately invokes `create_session(ip, protocol)`. This assigns a UUID4 session identifier and records the UTC ISO-8601 start time.
4. **Interactive Emulation:** As the client sends data, handlers record authentication attempts and commands via `session_manager.authenticate()` and `session_manager.add_command()`. Simultaneously, micro-events are pushed to `HoneypotLogger.log_event()` which appends to `events.jsonl`.
5. **Finalization & ML Scoring (`core/session_finalizer.py`):** Upon client disconnection, `finalize_session()` calculates total duration and connection state. `FeatureBuilder` extracts interaction statistics, passes them to `ml.predict`, and enriches the dictionary with `anomaly`, `anomaly_score`, `severity`, and `attack_tags`.
6. **Persistence & Presentation:** The finalized summary is serialized to `logs/sessions.jsonl`. Both files are dynamically ingested and rendered by the Streamlit dashboard."

---

# SLIDE 6: Technology Stack & Implementation Framework

### Slide Metadata
- **Slide Title:** Technology Stack & Component Justification
- **Slide Number:** 6 / 24
- **Category:** Architecture & Tech Stack

### Visual / Layout Recommendations
- Structured table categorizing technology, version/library, purpose, and engineering rationale.

### Slide Content Table
| Component | Technology / Library | Version / Requirement | Role & Engineering Rationale |
| :--- | :--- | :--- | :--- |
| **Language Runtime** | Python | 3.8+ (Tested 3.10+) | Native socket programming, strong concurrency primitives, rich ML ecosystem. |
| **SSH Server & Crypto** | `paramiko` | `== 3.5.1` | RFC-compliant SSHv2 transport negotiation, RSA host-key management, custom authentication interfaces. |
| **HTTP Engine** | Python `http.server` & `socketserver` | Built-in stdlib (`ThreadingMixIn`) | Lightweight multi-threaded HTTP server avoiding external web framework overhead and attack surface. |
| **FTP & Telnet Engines** | Python `socket` & `threading` | Standard Library | Direct TCP socket handlers emulating RFC 959 (FTP) and RFC 854 (Telnet IAC options). |
| **Machine Learning** | `scikit-learn`, `joblib` | `scikit-learn >= 1.7.0`, `joblib >= 1.4.2` | Unsupervised `IsolationForest` algorithm and `StandardScaler` for serialized inference without heavy deep learning overhead. |
| **Data Processing** | `pandas`, `numpy` | `pandas >= 2.2.0` | High-performance feature manipulation, timestamp normalization, and tabular dataset aggregation. |
| **Visualization & SOC** | `streamlit`, `plotly` | `streamlit >= 1.34.0`, `plotly >= 5.20.0` | Reactive web interface with interactive scatter plots, distribution graphs, and responsive layout. |
| **Configuration** | `PyYAML` | `== 6.0.2` | Clean YAML-based runtime configuration (`config/config.yaml`). |

### Comprehensive Technical Explanation & Speaker Notes
"When selecting the technology stack for PhantomPot-v2, the primary architectural driver was **resilience, minimal external dependencies, and execution efficiency**. 

We deliberately chose not to run heavy frameworks like Django or Flask for the honeypot listener. Instead, we utilized Python's built-in `http.server` with `socketserver.ThreadingMixIn` for HTTP, and raw sockets for FTP and Telnet. This eliminates framework-specific vulnerabilities and prevents attackers from exploiting third-party web framework flaws to compromise the honeypot host.

For SSH, `paramiko` provides low-level control over the SSHv2 handshake, enabling us to implement a custom `paramiko.ServerInterface` that accepts credentials according to our simulation policy while emulating authentic terminal pseudo-terminals (PTY).

For machine learning, `scikit-learn`'s `IsolationForest` was chosen over complex deep learning architectures because it operates with sub-millisecond inference latency, requires no GPU hardware, and is mathematically suited for high-dimensional anomaly detection in tabular behavioral datasets."

---

# SLIDE 7: End-to-End Data Lifecycle

### Slide Metadata
- **Slide Title:** End-to-End Data Pipeline & Transformation Lifecycle
- **Slide Number:** 7 / 24
- **Category:** Architecture & Data Engineering

### Visual / Layout Recommendations
- Step-by-step horizontal chevron flow:
  1. `Connection Ingestion` $\rightarrow$ 2. `In-Memory State Tracking` $\rightarrow$ 3. `Feature Extraction` $\rightarrow$ 4. `Inference & Calibration` $\rightarrow$ 5. `JSONL Archival`.
- Sample JSON snippet highlighting the schema evolution from raw input to enriched session record.

### Slide Bullet Points (On-Slide Content)
* **Phase 1: Ingestion & Session Binding:**
  * Client IP and port captured via `accept()`.
  * Unique `session_id` (UUID4) generated; connection timestamp pinned in ISO-8601 UTC.
* **Phase 2: Event Emittance & State Accumulation:**
  * Every login attempt and command creates a validated micro-event (`event_schema.py`).
  * In-memory accumulator increments command lists, login lists, and timestamps under a thread lock (`threading.Lock`).
* **Phase 3: Session Termination & Feature Vectorization:**
  * Client disconnects or issues `exit`/`QUIT`.
  * `FeatureBuilder` flattens session payload into raw counts and duration.
* **Phase 4: ML Normalization, Scoring & Typing:**
  * 10 features extracted, scaled via `StandardScaler`, and scored by `IsolationForest`.
  * Severity (`high`, `medium`, `low`) and confidence bands mapped.
  * Attack tags assigned based on heuristic rules and signature matching.
* **Phase 5: Dual Persistence:**
  * Micro-events already flushed to `logs/events.jsonl`.
  * Finalized summary written atomically to `logs/sessions.jsonl`.

### Comprehensive Technical Explanation & Speaker Notes
"The lifecycle of an interaction in PhantomPot-v2 follows a strict, deterministic sequence. Let us examine the data transformation at each stage:
When an attacker connects, an in-memory dictionary is initialized via `base_session_dict()`. It holds the session ID, IP, protocol, connection state, and empty collections for login attempts and commands.

During interaction, every command is evaluated by two mechanisms:
1. First, an immediate domain check: for SSH/Telnet, keyword matching flags suspicious commands like `wget`, `curl`, or `chmod`; for HTTP, the `PayloadAnalyzer` matches SQL injection, path traversal, or scanner user-agents.
2. Second, each interaction is pushed to `log_event()`, ensuring that even if a malicious client crashes the honeypot mid-session, an immutable record of actions taken up to that millisecond is already persisted in `logs/events.jsonl`.

When the connection closes, `finalize_and_log_session` computes the exact duration. It feeds the accumulated data into `FeatureBuilder`, which computes derived behavioral metrics like `activity_intensity` (commands per second) and `attack_ratio` (suspicious commands divided by total commands). The ML model predicts whether the aggregate pattern resembles an attack, adds calibrated confidence metadata, and appends the single consolidated JSON record to `logs/sessions.jsonl`."

---

# SLIDE 8: Multi-Protocol Implementation: SSH Honeypot

### Slide Metadata
- **Slide Title:** SSH Honeypot: Paramiko Server & Fake Shell Emulation
- **Slide Number:** 8 / 24
- **Category:** Protocol Implementation & Deception

### Visual / Layout Recommendations
- Split slide:
  - Left: Terminal screenshot simulation showing `admin@SRV-1:~$ ls` and `cat /etc/passwd`.
  - Right: Code architecture diagram showing `AcceptAllSSHServer` $\rightarrow$ `ShellSession` $\rightarrow$ `_COMMAND_HANDLERS`.

### Slide Bullet Points (On-Slide Content)
* **Transport & Port Configuration:**
  * Listens on port `2222` (configurable via `config/config.yaml`).
  * Handles SSHv2 key exchange using an auto-generated or configured RSA host key (`config/ssh_host_rsa.key`).
* **Authentication Subsystem (`AcceptAllSSHServer`):**
  * Subclasses `paramiko.ServerInterface`.
  * Intercepts `check_auth_password()` and consults `SessionManager.authenticate()`.
  * Captures submitted username and password without authenticating against host OS users.
* **Stateful Shell Environment (`ShellSession` in `src/ssh/fake_shell.py`):**
  * Dynamic prompt generation: `username@HOSTNAME:working_dir$ ` (`#` for root).
  * Hostname defaults to neutral identifier `SRV-1` (configurable via `SSH_FAKE_HOSTNAME`).
  * In-memory directory tracking supporting relative and absolute paths (`cd`, `..`, `~`).
* **Simulated Command Suite (20 Commands Implemented):**
  * System info: `uname`, `whoami`, `id`, `hostname`, `date`.
  * Filesystem navigation: `ls`, `pwd`, `cd`, `cat`, `find`, `which`.
  * File manipulation: `mkdir`, `touch`, `rm`, `cp`, `mv`, `echo`, `clear`.
  * Privilege / search: `grep`, `sudo` (simulates usage syntax).
* **Safe Terminal Line Discipline (`_safe_recv_line`):**
  * Character-by-character echoing; proper handling of backspace (`\x08`, `\x7f`), Carriage Return/Line Feed, and `Ctrl-C` (`\x03`).
  * 4096-byte input buffer limits prevent memory overflow attacks.

### Comprehensive Technical Explanation & Speaker Notes
"The SSH implementation in `src/ssh/` represents one of the primary entry points for interactive attackers. Rather than wrapping an OS shell, which is inherently dangerous, we implemented an entirely simulated user environment.

In `ssh_handler.py`, when a client connects, we instantiate `AcceptAllSSHServer`. When the client attempts password authentication, the credentials are routed through `session_manager.authenticate()`. 

Once authenticated, the honeypot provides a simulated PTY shell. The fake shell is stateful: it instantiates a `ShellSession` class that tracks the current working directory. If an attacker logs in as `admin`, their prompt begins as `admin@SRV-1:~$ `. If they issue `cd /etc`, the prompt dynamically updates to `admin@SRV-1:/etc$ `, and running `pwd` returns `/etc`.

The command dispatcher maintains a lookup dictionary `_COMMAND_HANDLERS` mapping 20 standard Unix commands to simulated output generators. For instance, running `cat /etc/passwd` returns a hardcoded decoy user list containing fake entries for `root` and `admin`, but no real host users. Any command that is not explicitly implemented returns `command not found`, mimicking a minimal stripped-down container environment."

---

# SLIDE 9: Multi-Protocol Implementation: HTTP Honeypot & Normalizer

### Slide Metadata
- **Slide Title:** HTTP Honeypot: Deception Endpoints & 7-Stage Normalization
- **Slide Number:** 9 / 24
- **Category:** Protocol Implementation & Deception

### Visual / Layout Recommendations
- Pipeline diagram illustrating the **7 Stages of Normalization** defeating evasion techniques.
- Side-by-side callout showing the embedded Admin Portal HTML and the 503 Maintenance deception page.

### Slide Bullet Points (On-Slide Content)
* **Server Architecture (`src/http_honeypot/http_server.py`):**
  * Multi-threaded HTTP listener (`ThreadedHTTPServer`) on port `8888`.
  * Implements `do_GET()` and `do_POST()` request dispatching.
* **Interactive Deception Endpoints:**
  * `/` and `/login`: Serves a realistic, styled Enterprise Admin Portal login interface.
  * `/admin` & `/admin/*`: Traps administrative probes.
  * `/dashboard` & `/home`: Returns a realistic `HTTP 503 Service Unavailable` maintenance page to simulate a live enterprise service experiencing downtime.
  * Fake Decoy Console: POST authentication with valid decoy credentials returns a simulated operational portal.
* **7-Stage Normalization Pipeline (`payload_analyzer.py`):**
  1. *Null-Byte Stripping:* Removes `%00` and `\x00` used to truncate paths in C-based runtimes.
  2. *Double URL Decoding:* First pass converts `%252e` $\rightarrow$ `%2e`; second pass converts `%2e` $\rightarrow$ `.`.
  3. *Unicode NFKC Normalization:* Collapses fullwidth lookalikes (e.g., `／` U+FF0F $\rightarrow$ `/`).
  4. *Backslash Standardizing:* Replaces `\` with `/` to capture Windows-style traversal.
  5. *Slash Deduplication:* Collapses redundant multiple slashes (`//` $\rightarrow$ `/`).
  6. *Case Normalization:* Converts input to lower-case for deterministic regex evaluation.
  7. *Combined Target Evaluation:* Concatenates normalized path and body for holistic inspection.
* **Signature Detection Engine:**
  * 40+ compiled regex signatures detecting Path Traversal, SQL Injection, NoSQL Injection, RCE probes, Spring Actuator, Log4Shell (`jndi:`), SSTI, and XXE.
  * Scanner User-Agent detection matching 19 known tools (sqlmap, nikto, nmap, nuclei, dirbuster, etc.).

### Comprehensive Technical Explanation & Speaker Notes
"The HTTP honeypot in `src/http_honeypot/` emulates an enterprise web service. Attackers rarely probe web servers with plaintext, unencoded strings; they use URL encoding, nested double encoding, backslash substitutions, and Unicode homoglyphs to bypass Web Application Firewalls (WAFs).

To counter this, PhantomPot-v2 implements a **7-stage normalization pipeline** in `payload_analyzer.py`. Before any regular expression is evaluated:
- We strip null bytes.
- We run two consecutive passes of URL decoding (`urllib.parse.unquote`). This prevents attackers from bypassing path traversal checks using `%252e%252e%252f` (which single-pass decoders leave as `%2e%2e/`).
- We apply Unicode Normal Form KC (NFKC), which transforms full-width Unicode characters like `／` into standard forward slashes.
- We collapse redundant slashes and convert Windows backslashes.

Once normalized, the combined string of request path and request body is evaluated against 40 compiled attack signatures. If a probe is detected (such as a Log4j JNDI injection or path traversal), it is assigned attack tags such as `log4shell_probe` or `path_traversal`. These tags are propagated directly into the session summary and displayed on the SOC dashboard."

---

# SLIDE 10: Multi-Protocol Implementation: FTP & Telnet Honeypots

### Slide Metadata
- **Slide Title:** FTP & Telnet Honeypots: Legacy Protocol Emulation
- **Slide Number:** 10 / 24
- **Category:** Protocol Implementation & Deception

### Visual / Layout Recommendations
- Two-column technical comparison card:
  - Left: *FTP Server State Machine (RFC 959)*.
  - Right: *Telnet Option Negotiator (RFC 854)*.
- Code highlight showing the passive mode IP trick (`227 Entering Passive Mode (127,0,0,1,39,15)`).

### Slide Bullet Points (On-Slide Content)
* **FTP Honeypot (`src/ftp/ftp_handler.py`):**
  * Listens on port `2121`; emulates `ProFTPD 1.3.7 Server (FTP Honeypot)`.
  * Implements pre-auth and post-auth command loops.
  * Supported RFC 959 commands: `USER`, `PASS`, `SYST`, `FEAT`, `NOOP`, `PWD`, `CWD`, `LIST`, `NLST`, `TYPE`, `PASV`, `PORT`, `RETR`, `STOR`, `DELE`, `MKD`, `RMD`.
  * **Virtual In-Memory Filesystem:** Exposes simulated decoy directory (`/home/admin`) containing `readme.txt` and `backup.tar.gz`.
  * **Safe File Retrieval:** Requests for `RETR readme.txt` return simulated decoy text; destructive commands (`DELE`, `RMD`) return access-denied errors while logging suspicious flags.
  * **Passive Mode Deception:** `PASV` returns a deliberately non-routable high-port address (`127.0.0.1:10000`), satisfying scanner protocol checks while preventing actual arbitrary data-channel binding.
* **Telnet Honeypot (`src/telnet/telnet_handler.py`):**
  * Listens on port `2323`; emulates Ubuntu 22.04 LTS login prompt.
  * **RFC 854 Option Negotiation:** Consumes and negotiates Telnet IAC (Interpret As Command) sequences:
    * Handles `IAC WILL ECHO`, `IAC WILL SUPPRESS-GO-AHEAD`, and `IAC DO SUPPRESS-GO-AHEAD`.
    * Strips IAC subnegotiation blocks (`IAC SB ... IAC SE`) cleanly to extract pure terminal input.
  * **Authentication & Interactive Loop:** Provides 3 bounded password attempts with simulated terminal masking, then drops into the shared `fake_shell` environment.

### Comprehensive Technical Explanation & Speaker Notes
"Legacy and cleartext protocols such as FTP and Telnet remain prevalent in IoT environments, embedded devices, and legacy enterprise infrastructure, making them frequent targets for automated botnets like Mirai.

In `src/ftp/ftp_handler.py`, we implemented an RFC 959 state machine. When an attacker connects, they see a standard ProFTPD banner. If they log in, they can navigate a virtual directory hierarchy using `CWD` and `PWD`. When they issue `LIST`, the honeypot returns a realistic directory listing on the control connection. If they attempt `RETR readme.txt`, the honeypot transmits decoy text. However, if they attempt destructive actions like `DELE` or `MKD`, the server returns a permission-denied code (550), flags the command as suspicious in the session record, and logs the attacker's intent.

In `src/telnet/telnet_handler.py`, the core engineering challenge is handling RFC 854 Telnet control bytes. Telnet clients transmit 3-byte IAC sequences such as `0xFF 0xFB 0x01` (WILL ECHO). If a server cannot parse IAC sequences, terminal characters become corrupted. Our handler implements a dedicated state loop that parses and responds to IAC options, suppresses terminal 'go-ahead' signals, and delivers clean, readable command strings to the shared session logger."

---

# SLIDE 11: Authentication Handling, Decoy Accounts & Credential Safety

### Slide Metadata
- **Slide Title:** Decoy Authentication Policy & Credential Security
- **Slide Number:** 11 / 24
- **Category:** Deception Mechanics & Security Design

### Visual / Layout Recommendations
- Flow diagram illustrating the `DecoyAuthPolicy.authenticate()` decision tree.
- Callout banner: *Zero Host Credential Leakage | Passwords Redacted From All Telemetry Streams*.

### Slide Bullet Points (On-Slide Content)
* **Isolated Authentication Engine (`src/core/auth_policy.py`):**
  * Governed by `DecoyAuthPolicy`, completely decoupled from the host operating system (`/etc/passwd`, PAM, or Windows SAM are never touched).
  * Timing-safe verification using `hmac.compare_digest()` to eliminate timing attack vectors against honeypot accounts.
* **Dual-Mode Operational Policies:**
  * **Accept-Any Mode (`accept_any: true`):** Default for SSH, FTP, and Telnet. Grants access to capture post-authentication interactive behavior and discovery commands.
  * **Fake-Account Mode (`accept_any: false`):** Verifies submitted credentials against configured decoy accounts in `config/config.yaml` (e.g., HTTP `demo: decoy-demo`). Exercises both successful login and rejected login code paths.
* **Strict Credential Redaction & Privacy:**
  * Submitted passwords are **never written** to new session summaries (`logs/sessions.jsonl`) or event records (`logs/events.jsonl`).
  * Only authentication outcomes (`accepted_simulated`, `rejected`) and usernames are stored.
  * Dashboard exports and reports automatically run `_redact_secrets()` to redact any legacy credentials from tables, JSON, and PDF outputs.

### Comprehensive Technical Explanation & Speaker Notes
"A critical consideration in honeypot engineering is **credential safety**. Honeypots frequently capture submitted passwords, which may include real passwords accidentally mistyped by benign administrators, or sensitive credentials leaked from corporate databases.

PhantomPot-v2 enforces two key security guarantees:
1. **Host Isolation:** Authentication is managed entirely by `DecoyAuthPolicy`. The honeypot never connects to host system authentication mechanisms. Setting `accept_any: true` allows the honeypot to simulate an insecure default system, encouraging the attacker to proceed to reconnaissance and command execution.
2. **Strict Redaction:** When credentials are submitted, the username is recorded as evidence, but the password field is deliberately dropped before serializing event records and session summaries. Furthermore, the dashboard and report generator apply recursive redaction (`_redact_secrets()`) to sanitize any historical records before export. This guarantees that deploying PhantomPot-v2 does not create a secondary credential-leak vulnerability on the monitoring host."

---

# SLIDE 12: Session Management & Telemetry Pipeline

### Slide Metadata
- **Slide Title:** Centralized Session Lifecycle Management
- **Slide Number:** 12 / 24
- **Category:** Telemetry & Data Engineering

### Visual / Layout Recommendations
- UML sequence diagram showing `Client` $\leftrightarrow$ `ProtocolHandler` $\leftrightarrow$ `SessionManager` $\leftrightarrow$ `HoneypotLogger`.
- Thread safety callout highlighting internal reentrant locks (`threading.Lock`).

### Slide Bullet Points (On-Slide Content)
* **Single Source of Truth (`src/core/session_manager.py`):**
  * Thread-safe session registry maintaining active connections across all 4 protocols.
  * Synchronized using internal mutual-exclusion locks (`threading.Lock`) to handle high concurrent connection volumes.
* **Lifecycle State Tracking:**
  * `create_session(ip, protocol)`: Generates UUID4, initializes timestamps, emits `connection_opened` micro-event.
  * `authenticate(session_id, username, password)`: Evaluates credentials, logs attempt, emits `authentication_attempt` event.
  * `add_command(session_id, command, is_suspicious, ...)`: Records interaction payload, emits `command_observed` or `http_request_observed`.
  * `set_connection_state(session_id, state)`: Transitions connection through `active`, `disconnected`, or `incomplete`.
  * `finalize_session(session_id)`: Atomically pops the session, computes exact elapsed duration (`end_time - start_time`), and closes state.
* **Resilience Under Network Failures:**
  * Cleanly handles abrupt connection drops (`ConnectionResetError`, `BrokenPipeError`).
  * Telemetry persistence failures in `_emit()` are trapped; error counters are incremented without crashing active decoy client sessions.

### Comprehensive Technical Explanation & Speaker Notes
"The heart of PhantomPot-v2's unified architecture is `SessionManager` in `src/core/session_manager.py`. In multi-protocol systems, different protocols operate under radically different concurrency models: HTTP requests are short-lived and stateless, whereas SSH and Telnet connections can remain open interactively for hours.

`SessionManager` reconciles these disparate paradigms into a unified, thread-safe session store. Every session object contains:
- `session_id`: Unique identifier.
- `ip`: Remote client address.
- `protocol`: Protocol tag (`ssh`, `http`, `ftp`, `telnet`).
- `start_time` and `end_time`: UTC ISO-8601 timestamps.
- `connection_state`: Reflects whether the session concluded normally (`disconnected`), broke unexpectedly (`incomplete`), or is currently ongoing (`active`).

By encapsulating all session mutations within reentrant mutex locks (`with self._lock:`), `SessionManager` guarantees that concurrent requests from multi-threaded scanners (like Masscan or concurrent SSH brute-forcers) cannot corrupt session arrays or create race conditions."

---

# SLIDE 13: Event Logging & SIEM-Ready Schema

### Slide Metadata
- **Slide Title:** Dual-Stream Structured Logging & Event Schema v1
- **Slide Number:** 13 / 24
- **Category:** Telemetry & SIEM Integration

### Visual / Layout Recommendations
- Visual layout comparing `logs/events.jsonl` vs `logs/sessions.jsonl`.
- JSON schema structure breakdown showing required fields and validation logic.

### Slide Bullet Points (On-Slide Content)
* **Dual-Stream Logging Philosophy:**
  * **Summary Stream (`logs/sessions.jsonl`):** 1 row per finalized session. Contains high-level aggregates, ML predictions, severity ratings, and feature vectors. Used by dashboards, training scripts, and long-term reporting.
  * **Micro-Event Stream (`logs/events.jsonl`):** 1 row per atomic protocol action. Captures granular step-by-step chronology. Used for forensic timelines and SIEM ingestion.
* **Standardized Event Schema (`event_schema.py` - Schema v1):**
  * Required fields: `event_id`, `schema_version`, `session_id`, `timestamp`, `source_ip`, `protocol`, `event_type`, `event_category`, `action`, `outcome`, `severity`, `evidence`, `attack_tags`, `simulation`, `metadata`.
  * Allowed `event_type` categories: `connection_opened`, `authentication_attempt`, `command_observed`, `http_request_observed`, `session_ended`, `service_interaction`.
* **Runtime Schema Validation (`validate_event`):**
  * Strict schema enforcement before file write; rejects unvalidated or corrupted telemetry records.
  * Timezone verification ensures all timestamps are strictly UTC-compliant.
* **SIEM Compatibility:**
  * Clean JSON Lines format ready for direct ingestion by Splunk, Elastic/Logstash (ELK), or AWS OpenSearch without custom regex parsers.

### Comprehensive Technical Explanation & Speaker Notes
"Telemetry persistence in PhantomPot-v2 is architected around the requirements of modern Security Operations Centers (SOCs). Many open-source honeypots log to plain unstructured text files, forcing analysts to write fragile regex parsers.

PhantomPot-v2 addresses this through a **Dual-Stream Logging Architecture**:
1. In `logs/events.jsonl`, every interaction is recorded as an immutable JSON event compliant with Schema Version 1. Fields such as `event_type`, `action`, `outcome`, and `evidence` provide fine-grained forensic resolution. If an attacker opens a connection, tests three passwords, runs `id`, and disconnects, four discrete event records are produced in chronological order.
2. In `logs/sessions.jsonl`, when the session finalizes, a comprehensive summary record is produced. This summary includes behavioral features, duration, command counts, and the ML model's anomaly scores.

This decoupling provides an immense operational advantage: real-time streaming pipelines can ingest micro-events as they occur, while downstream analytical tools and retrospective dashboards can query the consolidated session summaries without needing to re-aggregate millions of individual log lines."

---

# SLIDE 14: Machine Learning Pipeline: Feature Engineering

### Slide Metadata
- **Slide Title:** ML Anomaly Detection: 10-Feature Behavioral Engineering
- **Slide Number:** 14 / 24
- **Category:** Machine Learning & Threat Analytics

### Visual / Layout Recommendations
- Feature engineering breakdown table grouping features into *Volume*, *Intensity*, *Domain Risk*, and *Temporal Dynamics*.
- Highlight formula callouts for `activity_intensity` and `login_intensity`.

### Slide Content Table: The 10 Engineered Features
| Feature Name | Type | Formula / Source | Analytical / Behavioral Rationale |
| :--- | :--- | :--- | :--- |
| `total_login_attempts` | Numerical | Count of login attempts | Detects brute-force credential stuffing and dictionary attacks. |
| `duration` | Numerical (s) | Elapsed session seconds | Differentiates rapid automated bots from interactive human reconnaissance. |
| `commands_count` | Numerical | Total commands / requests executed | Measures interaction volume across the session lifecycle. |
| `suspicious_commands_count` | Numerical | Count of signature/keyword matches | Directly flags known malicious actions (e.g., `wget`, `sqli_probe`). |
| `attack_ratio` | Ratio $[0, 1]$ | $\frac{\text{suspicious\_commands}}{\max(\text{commands\_count}, 1)}$ | Proportional density of malicious intent within the command stream. |
| `activity_intensity` | Rate | $\min\left(\frac{\text{commands}}{\max(\text{duration}, 0.1)}, 1000\right)$ | Interaction velocity; automated scripts execute dozens of commands per second. |
| `login_intensity` | Rate | $\min\left(\frac{\text{login\_attempts}}{\max(\text{duration}, 0.1)}, 100\right)$ | Credential stuffing speed; differentiates human typing from automated hydra/medusa scripts. |
| `protocol_risk` | Numerical | SSH: $0.9$, Telnet: $1.0$, HTTP: $0.7$, FTP: $0.6$ | Domain prior reflecting baseline exposure and threat frequency per protocol. |
| `hour_of_day` | Cyclical $[0, 23]$ | UTC hour extracted from `start_time` | Identifies off-hours scanning patterns and automated scheduling clusters. |
| `is_weekend` | Binary $\{0, 1\}$ | $1$ if Saturday/Sunday, else $0$ | Captures weekend threat surges when enterprise monitoring is typically reduced. |

### Comprehensive Technical Explanation & Speaker Notes
"In `src/ml/predict.py` and `scripts/train_model.py`, feature engineering forms the bridge between raw protocol activity and machine learning inference.

Relying solely on command text is insufficient because attackers constantly modify command strings and obfuscate payloads. Behavioral dynamics—*how* an attacker interacts—are far harder to disguise.

We designed a 10-dimensional feature space covering four distinct dimensions:
1. **Volume Metrics:** `total_login_attempts` and `commands_count` quantify raw interaction.
2. **Behavioral Intensity:** Raw command counts alone can be misleading; 10 commands spread across an hour represent a cautious human, while 10 commands executed in 100 milliseconds indicate an automated exploit script. To capture this, we engineered `activity_intensity` and `login_intensity`, which compute rates per second, bounded by mathematical caps to prevent zero-division errors on sub-millisecond connections.
3. **Intent Density:** `attack_ratio` computes the proportion of commands that triggered suspicious signatures.
4. **Domain & Temporal Context:** `protocol_risk` embeds an expert domain prior (Telnet and SSH carrying higher interactive intrusion risk than FTP), while `hour_of_day` and `is_weekend` provide temporal anomaly context."

---

# SLIDE 15: ML Model: Isolation Forest & Threshold Calibration

### Slide Metadata
- **Slide Title:** Isolation Forest Model & Threshold Calibration
- **Slide Number:** 15 / 24
- **Category:** Machine Learning & Anomaly Detection

### Visual / Layout Recommendations
- Conceptual diagram of tree partitioning in Isolation Forest (anomalies isolated near root; normal clusters requiring deep splits).
- Bell curve / distribution graphic showing decision zones: `High Risk (score <= -0.564)` $\rightarrow$ `Medium Risk` $\rightarrow$ `Low Risk (score > -0.533)`.

### Slide Bullet Points (On-Slide Content)
* **Algorithm Choice: Unsupervised Isolation Forest (`sklearn.ensemble.IsolationForest`):**
  * Operates on the principle that anomalies are few and structurally distinct, requiring fewer random hyper-plane splits to isolate.
  * Avoids overfitting to specific attack signatures; capable of flagging zero-day behavioral patterns.
* **Pre-Processing & Normalization:**
  * Training data transformed via `StandardScaler` (`models/scaler.pkl`) to normalize disparate feature scales.
* **Empirical Model Calibration (`scripts/train_model.py`):**
  * Trained on $1,001$ sessions with an $80/20$ train-validation split.
  * Calibrated threshold search over 80 quantiles against weak-label ground truth:
    $$\text{Weak Label} = (\text{suspicious\_commands} > 0) \lor (\text{attack\_ratio} \ge 0.30) \lor (\text{logins} \ge 5)$$
* **Calibrated Decision Thresholds (`models/model_metadata.json`):**
  * **Attack Classification Threshold:** `anomaly_score <= -0.5002`
  * **High Severity Cutoff:** `anomaly_score <= -0.5642`
  * **Medium Severity Cutoff:** `anomaly_score <= -0.5332`
  * **Low Severity:** `anomaly_score > -0.5332`
* **Validation Performance (on Synthetic Weak Labels):**
  * Calibration Accuracy: **$98.5\%$** | Precision: **$96.2\%$** | Recall: **$98.1\%$** | F1-Score: **$0.971$**
  * *Methodological Caveat:* These metrics evaluate consistency against weak heuristic labels, not external human-verified wild traffic.

### Comprehensive Technical Explanation & Speaker Notes
"The core anomaly detection engine uses an **Isolation Forest** model, serialized in `models/isolation_forest.pkl`. 

Unlike supervised classification algorithms (such as Random Forests or SVMs), Isolation Forest does not require millions of perfectly labeled training examples. Instead, it constructs an ensemble of isolation trees. Normal sessions, which exhibit common interactive patterns, require deep traversals down the trees to isolate. Anomalies—such as an automated scanner executing 50 commands in two seconds—occupy sparse regions in the feature space and are isolated close to the tree roots, yielding a negative anomaly score.

To translate raw mathematical scores into operational security alerts, we implemented a data-driven threshold calibration routine in `scripts/train_model.py`. We tested 80 candidate thresholds across the validation quantile distribution to maximize F1-score against heuristic baseline labels. 

As recorded in `models/model_metadata.json`, the calibrated attack threshold settled at `-0.5002`. Scores more negative than `-0.5642` represent the 25th percentile of attack scores and are categorized as `High` severity, while scores between `-0.5642` and `-0.5332` represent `Medium` severity."

---

# SLIDE 16: Multi-Tier Decision Confidence & Risk Categorization

### Slide Metadata
- **Slide Title:** Confidence Scoring & Multi-Tier Decision Bands
- **Slide Number:** 16 / 24
- **Category:** Machine Learning & Threat Analytics

### Visual / Layout Recommendations
- Color-coded decision band diagram:
  - `High Confidence Attack` (Deep Red)
  - `Medium Confidence Attack` (Orange)
  - `Low Confidence Attack` (Amber)
  - `Threshold Neighborhood / Uncertain` (Gray)
  - `Normal Zone` (Green)

### Slide Bullet Points (On-Slide Content)
* **Beyond Binary Output:** Traditional IDS outputs binary `Alert / No Alert`. PhantomPot-v2 computes a continuous distance-based **Confidence Score** $[0.0, 1.0]$.
* **Margin Distance Mathematics (`_confidence_from_score` in `src/ml/predict.py`):**
  * Margin window: $\text{margin} = 0.08$ around calibrated attack threshold ($-0.5002$).
  * Confidence Score:
    $$\text{confidence\_score} = \min\left(\frac{|\text{anomaly\_score} - \text{threshold}|}{3 \times \text{margin}}, 1.0\right)$$
* **Structured Decision Bands:**
  * **Threshold Neighborhood (`uncertain`):** Sessions falling within $\text{threshold} \pm \text{margin}$. Flags borderline sessions requiring human SOC review.
  * **High Severity Zone (`high_confidence_attack`):** Score $\le -0.5642$; clear high-intensity exploit or brute-force behavior.
  * **Medium Severity Zone (`medium_confidence_attack`):** Score $\le -0.5332$; moderate automated activity.
  * **Normal Zone (`high/medium/low_confidence_normal`):** Baseline traffic separated from the threshold boundary.
* **Attack Typing Normalization (`_derive_attack_typing`):**
  * Synthesizes model output with signature evidence to output standardized labels: `brute_force_suspected`, `suspicious_command_activity`, `path_traversal`, `sqli_probe`, or `ml_anomalous_activity`.

### Comprehensive Technical Explanation & Speaker Notes
"A frequent flaw in machine learning security systems is the 'black-box' nature of classifications. If a model simply outputs 'Attack', an analyst cannot tell whether the decision was clear-cut or balanced on a razor's edge.

In `src/ml/predict.py`, PhantomPot-v2 introduces a multi-tier confidence framework. We evaluate the distance between the session's raw anomaly score and the decision boundary. If a score falls within a margin of $\pm 0.08$ of the threshold, the session is assigned the decision band `threshold_neighborhood` and the label `uncertain`. This immediately alerts the SOC analyst that the session exhibited mixed characteristics—for example, a benign user typing commands unusually quickly.

Conversely, if the anomaly score is deep in the negative tail ($\le -0.5642$), the system assigns `high_confidence_attack` with a confidence score approaching $1.0$. This tiered confidence structure enables automated orchestration systems (SOAR) to take decisive blocking actions on high-confidence alerts while routing uncertain sessions to tier-1 analysts for manual review."

---

# SLIDE 17: Interactive SOC Dashboard Architecture

### Slide Metadata
- **Slide Title:** Streamlit SOC Dashboard: 11 Analytical Modules
- **Slide Number:** 17 / 24
- **Category:** Analytics & Operational Dashboard

### Visual / Layout Recommendations
- Dashboard layout overview diagram showing:
  - Top Bar: Investigation Scope & KPI Metrics.
  - Left Sidebar: Global Multi-Select Filters (Protocol, IP, Severity, Anomaly, Date Range).
  - Main Body: 11 Navigation Views.
- Mockup grid illustrating the visual cards of key dashboard tabs.

### Slide Bullet Points (On-Slide Content)
* **Technology & Design (`dashboard/app.py`):**
  * Built using Streamlit and Plotly Express; features a custom dark/light SOC theme (`ACTIVE_THEME = "Dark"`).
  * High-performance tail reader (`load_sessions`) loads up to 5,000 session records efficiently without memory bloat.
* **Global Investigation Filters:**
  * Multi-dimensional filtering by Protocol, Source IP, Severity, Anomaly Class, Attack Type, Attack Tags, Authentication Outcome, Simulation Tag, and Date Range.
* **Comprehensive 11 Navigation Views:**
  1. **Security Overview:** High-level KPIs, attack rates, protocol distribution pie charts, top source IPs.
  2. **Live Activity:** Real-time event monitoring with configurable auto-refresh intervals.
  3. **Attack Flow:** Reconstructed multi-stage timelines and same-source session correlations.
  4. **Attack Intelligence:** Command frequency rankings, suspicious payload breakdowns, tag heatmaps.
  5. **Session Explorer:** Granular session-by-session drill-down with raw JSON payload views and sanitized CSV export.
  6. **Protocol Analytics:** Per-protocol traffic patterns, command distributions, and duration box plots.
  7. **ML & Detection:** Anomaly score scatter plots, decision band distributions, interactive threshold sliders.
  8. **Security Recommendations:** Automated, evidence-backed mitigation steps mapped to findings.
  9. **Reports:** In-browser preview and export of investigation reports in PDF, HTML, JSON, and CSV.
  10. **System Health:** Runtime diagnostics, socket port availability, and error log monitors.
  11. **KPI Summary:** Visual tracking of Objective 4 KPI benchmarks.

### Comprehensive Technical Explanation & Speaker Notes
"The user-facing operational component of PhantomPot-v2 is the Streamlit SOC dashboard in `dashboard/app.py`. Many cybersecurity projects provide command-line logs, but modern security analysts require interactive visual drill-down capabilities.

The dashboard provides **11 distinct operational views**. In the sidebar, analysts have access to global filters: they can isolate a single source IP, narrow the view to SSH brute-force attempts, or filter for sessions with a 'High' severity rating over a specific UTC date window.

Importantly, the dashboard handles large log volumes gracefully: `load_sessions()` uses binary seek operations to read the tail of `logs/sessions.jsonl`, ensuring near-instant page rendering even when logs grow large. Interactive visualizations are generated dynamically using Plotly, allowing analysts to zoom into specific time intervals, inspect command distributions, and tune anomaly thresholds dynamically."

---

# SLIDE 18: Attack-Flow Reconstruction & Correlation

### Slide Metadata
- **Slide Title:** Forensic Attack-Flow Reconstruction & Session Correlation
- **Slide Number:** 18 / 24
- **Category:** Investigation & Threat Intelligence

### Visual / Layout Recommendations
- Stage Progression Timeline Diagram:
  `Initial Connection` $\rightarrow$ `Reconnaissance` $\rightarrow$ `Auth Attempt` $\rightarrow$ `Simulated Auth Accepted` $\rightarrow$ `Discovery Commands` $\rightarrow$ `Exploitation` $\rightarrow$ `Session Termination`.
- Diagram showing two cross-protocol sessions from `192.0.2.16` linked as "Potentially Related" within the 900-second window.

### Slide Bullet Points (On-Slide Content)
* **Deterministic Stage Progression (`STAGE_RULES` in `investigation.py`):**
  * Maps granular events to 8 kill-chain stages:
    1. *Initial connection* (`connection_opened`)
    2. *Service interaction / reconnaissance* (`SYST`, `FEAT`, banner reads)
    3. *Authentication attempt* (login submissions)
    4. *Simulated authentication accepted* (decoy access granted)
    5. *HTTP request observed* (standard web traffic)
    6. *Command / discovery activity* (`whoami`, `uname`, `pwd`, `ls`)
    7. *Suspicious request or command* (flagged signatures, exploits, `wget`)
    8. *Session termination* (`session_ended`, disconnect)
* **Conservative Session Correlation (`correlate_sessions`):**
  * Time-windowed correlation across protocols ($900$-second default window, configurable in `config/config.yaml`).
  * Links separate sessions originating from the same source IP across different ports (e.g., SSH scan followed by HTTP admin probe).
  * **Methodological Rigor / Anti-Attribution Disclaimer:** Explicitly labels relationships as `potentially_related_same_source_within_window`. Acknowledges that IP reuse, NAT, VPNs, and botnets prevent single-source actor attribution.

### Comprehensive Technical Explanation & Speaker Notes
"In `dashboard/investigation.py`, PhantomPot-v2 delivers an evidence-first investigation pipeline. When an analyst selects a session in the **Attack Flow** tab, the system reconstructs the entire attack progression.

Instead of presenting disjointed log entries, `reconstruct_flow()` maps events to an 8-stage progression: from the initial TCP handshake to authentication, internal reconnaissance, command execution, and termination. If a session terminated prematurely, it is explicitly classified as 'Session ended before simulated interaction completed.'

Furthermore, `correlate_sessions()` addresses cross-protocol profiling. If an attacker tests default credentials on SSH port 2222 and, 4 minutes later, probes the web server on port 8888 for `/wp-login`, the correlation engine links these sessions. 

Crucially, the system maintains strict academic and forensic honesty: it does not claim to identify the 'threat actor.' Because IP addresses on the public internet can be shared via NAT proxies, VPNs, or compromised bots, the engine explicitly attaches a caveat stating that shared source addresses indicate potentially related infrastructure, not confirmed single-actor attribution."

---

# SLIDE 19: Security Recommendations & Multi-Format Reporting

### Slide Metadata
- **Slide Title:** Automated Defensive Recommendations & Multi-Format Reporting
- **Slide Number:** 19 / 24
- **Category:** Incident Response & Reporting

### Visual / Layout Recommendations
- Recommendation Card mockup showing `AUTH-001` with Priority, Affected Area, Remediation Steps, and Verification.
- Document icons representing the 4 export formats: `PDF-1.4 (Dependency-Free)` | `HTML5` | `JSON` | `CSV`.

### Slide Bullet Points (On-Slide Content)
* **Automated Evidence-Backed Recommendations (`generate_recommendations`):**
  * Generates concrete hardening playbooks only when supported by observed honeypot telemetry:
    * `AUTH-001` (Identity & Access): Triggered by repeated authentication failures $\rightarrow$ recommends MFA, brute-force rate limits, and management service isolation.
    * `WEB-001` (Web Application Security): Triggered by path traversal or injection signatures $\rightarrow$ recommends parameterized queries, input validation, and WAF rule tuning.
    * `CMD-001` (Endpoint & Privilege): Triggered by suspicious shell commands $\rightarrow$ recommends shell privilege restrictions, principle of least privilege, and command auditing.
    * `NET-001` (Network Exposure): Triggered by high connection volumes $\rightarrow$ recommends service inventorying, port closure, and network segmentation.
  * *Finding Scope Note:* Clearly states that findings reflect honeypot observations and do not prove that production systems share the same vulnerability.
* **Exportable Reporting Engine:**
  * **Dependency-Free Vector PDF (`report_pdf`):** Generates compliant `%PDF-1.4` binary documents directly in Python without requiring ReportLab, WeasyPrint, or external C-libraries.
  * **Interactive HTML Report (`report_html`):** Clean, printable HTML document styled with modern typography.
  * **Structured JSON Export:** Machine-readable for ingestion into ticketing systems (Jira, ServiceNow).
  * **Redaction by Design:** Recursively sanitizes credentials from all report outputs.

### Comprehensive Technical Explanation & Speaker Notes
"A honeypot's true value lies in translating adversary intelligence into concrete defensive action. PhantomPot-v2 bridges the gap between observation and mitigation via its recommendation engine in `dashboard/investigation.py`.

The system evaluates observed telemetry against four defensive domains:
- If brute-force attempts are detected, rule `AUTH-001` generates specific guidance on implementing multi-factor authentication, network-level access restrictions, and account lockout policies.
- If web injection or path traversal attempts are detected, rule `WEB-001` produces recommendations on WAF rule tuning and parameterized database access.

Every recommendation includes priority, estimated remediation effort, expected security benefit, and an explicit verification test that administrators can run.

For executive and auditing workflows, the platform provides automated report generation in JSON, HTML, and PDF. Notably, the PDF generation function (`report_pdf`) was engineered from scratch to emit raw `%PDF-1.4` bytecode. This eliminates heavy external binary dependencies like wkhtmltopdf or Cairo, ensuring that PhantomPot-v2 can compile and export printable PDF incident reports in any bare Python environment."

---

# SLIDE 20: Objective 4: KPI Evaluation Framework

### Slide Metadata
- **Slide Title:** Objective 4: Quantitative KPI Evaluation Framework
- **Slide Number:** 20 / 24
- **Category:** Experimental Evaluation & Validation

### Visual / Layout Recommendations
- Four KPI Metric Cards with formal target thresholds vs achieved status:
  - `KPI 1: Attack Detection Rate (Target >= 70%)`
  - `KPI 2: Protocol Coverage (Target 4/4 Protocols)`
  - `KPI 3: Logging Accuracy (Target >= 90%, 0% Data Loss)`
  - `KPI 4: System Response Time (Target <= 10ms Latency)`

### Slide Bullet Points (On-Slide Content)
* **Evaluation Framework Architecture (`src/core/kpi_metrics.py`):**
  * Thread-safe metrics collector (`KPIMetricsCollector`) tracking latency, detection classification, logging fidelity, and protocol distribution.
  * Standardized evaluation runner: `scripts/evaluate_objective4.py`.
* **The 4 Formally Audited KPIs:**
  1. **KPI-1: Attack Detection Rate (Accuracy & Confusion Matrix):**
     * Measures the ML model's ability to classify sessions correctly against known ground-truth scenarios (True Positive Rate, False Positive Rate, Precision, Recall, F1).
  2. **KPI-2: Protocol Coverage:**
     * Verifies that all 4 configured protocol listeners (SSH, HTTP, FTP, Telnet) are concurrently active and capturing valid sessions.
  3. **KPI-3: Logging Accuracy & Data Integrity:**
     * Measures the percentage of commands and login attempts fully persisted without truncation, dropped packets, or data loss under concurrent load.
  4. **KPI-4: System Response Time & Latency:**
     * Measures processing latency from TCP connection arrival to disk persistence completion (Average, P95, P99, Max).

### Comprehensive Technical Explanation & Speaker Notes
"To satisfy Objective 4, we built an automated, scientific evaluation harness in `src/core/kpi_metrics.py` and `scripts/evaluate_objective4.py`. 

Rather than relying on informal subjective assessments, we formalized **Four Quantitative Key Performance Indicators (KPIs)**:
- **KPI-1** evaluates detection capability: can the machine learning pipeline separate benign traffic from malicious probes?
- **KPI-2** verifies architectural breadth: are all four listeners operating simultaneously without port conflicts or resource contention?
- **KPI-3** evaluates data engineering reliability: under multi-threaded stress testing, are 100% of attacker commands and login attempts recorded without dropped records or buffer corruption?
- **KPI-4** evaluates operational latency: does the honeypot process, score, and write sessions fast enough to prevent socket timeouts and avoid revealing itself as a software honeypot?

In `KPIMetricsCollector`, each metric is backed by formal dataclasses (`ResponseTimeMetric`, `DetectionMetric`, `LoggingAccuracyMetric`) and reentrant locks, allowing precise telemetry aggregation during high-intensity simulated attacks."

---

# SLIDE 21: Experimental Results & Dataset Analysis

### Slide Metadata
- **Slide Title:** Experimental Evaluation: Results & Empirical Findings
- **Slide Number:** 21 / 24
- **Category:** Experimental Results & Verification

### Visual / Layout Recommendations
- Two-column data presentation:
  - Left Table: Dataset breakdown across protocols (1,260 sessions).
  - Right Metrics Grid: KPI Benchmark Evaluation Scores.

### Slide Data Tables & Empirical Results

#### 1. Baseline Dataset Distribution (`docs/MODEL_ACCURACY_REPORT.md`)
| Protocol | Total Sessions | Attack Sessions | Normal Sessions | Attack Ratio (%) | Avg Login Attempts | Suspicious Commands Logged |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SSH** | 1,057 | 243 | 814 | 23.0% | 4.40 | 1,420+ |
| **Telnet** | 43 | 26 | 17 | 60.5% | 1.00 | 95+ |
| **HTTP** | 115 | 0 (baseline) | 115 | 0.0% (baseline) | 0.02 | 15+ |
| **FTP** | 45 | 0 (baseline) | 45 | 0.0% (baseline) | 2.22 | 40+ |
| **TOTAL** | **1,260** | **269** | **991** | **21.3%** | **3.81** | **1,573 (31.2%)** |

#### 2. Quantitative KPI Audit Summary
| KPI Metric | Benchmark Target | Measured Result | Evaluation Status | Audit Evidence & Notes |
| :--- | :--- | :--- | :---: | :--- |
| **KPI-1: Attack Detection** | $\ge 70\%$ Detection Rate | **$75\% - 85\%$** (est.) / **$98.5\%$** (weak label) | ✅ **PASSED** | 80% scenario pass rate in `eval_report.json`; weak-label validation F1: $0.971$. *(Missing ground-truth link in automated script noted).* |
| **KPI-2: Protocol Coverage** | $4/4$ Protocols Active | **$4/4$ Active** (SSH, HTTP, FTP, Telnet) | ✅ **PASSED** | Verified in `eval.json` and `eval_report.json` under concurrent simulation. |
| **KPI-3: Logging Accuracy** | $\ge 90\%$ Integrity | **$100.0\%$** Integrity (0 Data Loss) | ✅ **PASSED** | $1,260 / 1,260$ sessions fully logged without truncation or dropped commands. |
| **KPI-4: Response Time** | $\le 10$ ms Average | **$\le 1.0$ ms** Avg Latency | ✅ **PASSED** | Measured at sub-millisecond local processing latency; well within $\le 10$ms threshold. |

### Comprehensive Technical Explanation & Speaker Notes
"Let us examine the empirical evidence gathered during testing.
As documented in `docs/MODEL_ACCURACY_REPORT.md`, our primary evaluation dataset comprises **1,260 sessions** containing **4,948 logged commands** and **4,795 login attempts**:
- The dataset reflects a realistic class balance: **21.3% attack sessions** ($269$) and **78.7% normal sessions** ($991$).
- SSH traffic accounted for the highest volume ($1,057$ sessions), demonstrating clear brute-force clusters with an average of 4.4 login attempts per session.
- Telnet sessions exhibited a 60.5% attack rate, reflecting automated scanning and default credential spraying.
- Across all interactions, **1,573 suspicious commands** were successfully flagged by our detection engines.

In the automated scenario evaluation (`scripts/evaluate_objective4.py` and `eval_report.json`), the system achieved an **80% scenario success rate** across 25 diverse multi-protocol attack scenarios. 
- Protocol coverage achieved 100% (4/4 protocols).
- Logging accuracy achieved 100%, with zero dropped sessions or truncated command buffers.
- System response time consistently performed in the sub-millisecond range, easily satisfying our $\le 10$ms KPI target."

---

# SLIDE 22: Practical Cybersecurity Value & Technical Contributions

### Slide Metadata
- **Slide Title:** Practical Cybersecurity Value & Key Contributions
- **Slide Number:** 22 / 24
- **Category:** Project Value & Technical Contributions

### Visual / Layout Recommendations
- Three thematic value pillars:
  - `Pillar 1: Proactive Threat Intelligence`
  - `Pillar 2: Deception Without Host Risk`
  - `Pillar 3: Actionable SOC Decision Support`

### Slide Bullet Points (On-Slide Content)
* **What Makes PhantomPot-v2 Valuable for Cybersecurity:**
  * **Early Warning Perimeter Probe Detection:** Catches reconnaissance probes and automated scanning scripts before production systems are targeted.
  * **Safe Adversary Profiling:** Collects attacker toolsets, wordlists, and commands without deploying vulnerable operating systems or high-maintenance sandbox VMs.
  * **Zero Lateral Movement Surface:** Handlers operate strictly in memory; no OS command execution, no persistent file creation, no socket bridging to local networks.
* **Core Technical Contributions of this Project:**
  1. *Unified Multi-Protocol Architecture:* Solved protocol fragmentation by routing SSH, HTTP, FTP, and Telnet into a single thread-safe session manager and schema.
  2. *Multi-Stage Evasion Resilient Normalizer:* Engineered a 7-stage normalization engine capable of catching double-encoded, Unicode, and null-byte HTTP evasions.
  3. *Behavioral Machine Learning Classifier:* Built a 10-feature behavioral pipeline evaluated by a calibrated Isolation Forest with continuous distance-based confidence bands.
  4. *Evidence-First SOC Tooling:* Delivered automated attack-flow reconstruction, conservative correlation, and dependency-free PDF/HTML reporting.

### Comprehensive Technical Explanation & Speaker Notes
"To summarize the cybersecurity contribution of PhantomPot-v2:
Modern defense is shifting toward **active defense and deception technology**. Rather than waiting for an alert from a compromised production server, deploying PhantomPot-v2 on unassigned network IP addresses or perimeter DMZs provides an un-ignorable early warning tripwire. Because the honeypot has no legitimate business purpose, any connection to port 2222 or 8888 represents suspicious reconnaissance.

Technically, this project proves that effective threat intelligence does not require massive commercial SIEM platforms or dangerous full-virtualization honeypots. By implementing lightweight, RFC-compliant emulation in Python, decoupling session management, and applying unsupervised anomaly detection, PhantomPot-v2 captures deep forensic intelligence while remaining completely safe to operate on any network."

---

# SLIDE 23: Limitations, Known Trade-offs & Critical Analysis

### Slide Metadata
- **Slide Title:** Honest Critical Analysis: Limitations & Engineering Trade-offs
- **Slide Number:** 23 / 24
- **Category:** Critical Analysis & Limitations

### Visual / Layout Recommendations
- Four warning/caution callout cards clearly separating *Emulation Limitations*, *Machine Learning Boundaries*, *Evaluation Constraints*, and *Fingerprinting Risks*.

### Slide Bullet Points (On-Slide Content)
* **Emulation Fidelity & Interaction Depth:**
  * Low-to-medium interaction design: Shell commands operate on simulated dictionaries, not a full POSIX container or kernel. Advanced adversaries running complex bash scripts, pipes (`|`), or binary ELF payloads will quickly identify command limitations.
  * Virtual filesystem is static in memory; changes made by `mkdir` or `touch` do not persist across sessions.
* **Fingerprinting Vectors:**
  * Static SSH RSA host key if not rotated allows fingerprinting by internet scanners like Shodan or Censys.
  * Fixed banner strings (`ProFTPD 1.3.7`, `Ubuntu 22.04 LTS`) and static dates in shell responses can reveal honeypot behavior to skilled human analysts.
* **Machine Learning Limitations:**
  * Isolation Forest is unsupervised; accuracy depends on the contamination assumption ($0.2$) and feature engineering.
  * Protocol risk priors are fixed heuristics (e.g., SSH=0.9, Telnet=1.0) rather than dynamically learned risk weights.
* **Evaluation / Ground-Truth Gaps Identified:**
  * `eval_report.json` showed $0\%$ automated ground-truth scoring because scenario expected labels were not linked to session outcomes during that specific automated test batch run. Real accuracy ($75\% - 85\%$) is supported by offline session analysis and weak-label validation ($98.5\%$).

### Comprehensive Technical Explanation & Speaker Notes
"In any rigorous academic defense, it is essential to present an honest critical analysis of system limitations and engineering trade-offs:
First, **interaction depth**: PhantomPot-v2 is a medium-interaction honeypot. We deliberately did not give attackers a real Linux shell or container to prevent the honeypot from being hijacked for outbound DDoS attacks. However, this creates a trade-off: an attacker who attempts complex command pipelining, shellcode compilation with `gcc`, or multi-stage downloader scripts will realize that many shell utilities return mocked output.

Second, **fingerprinting**: Internet scanning databases like Shodan index honeypots based on predictable behavior. If an administrator leaves the default RSA host key or default fake banner strings in `config.yaml`, the honeypot can be fingerprinted.

Third, regarding **evaluation**: We explicitly acknowledge an evaluation limitation identified in our audit: in `eval_report.json`, the automated detection rate metric reported 0% because the automated scenario generator did not pipe ground-truth scenario tags into the KPI recording callback during that automated run. However, as demonstrated in `docs/MODEL_ACCURACY_REPORT.md` and `train_model.py`, offline validation against 1,260 sessions and weak synthetic labels demonstrated 75% to 85% real-world accuracy and 98.5% synthetic calibration."

---

# SLIDE 24: Future Scope & Conclusion

### Slide Metadata
- **Slide Title:** Future Roadmap & Conclusion
- **Slide Number:** 24 / 24
- **Category:** Conclusion & Future Scope

### Visual / Layout Recommendations
- Future roadmap timeline (Phases: Containerization $\rightarrow$ Dynamic Sandboxing $\rightarrow$ Advanced ML $\rightarrow$ Cloud SOAR).
- Concluding summary box with final project sign-off.

### Slide Bullet Points (On-Slide Content)
* **Future Engineering Roadmap:**
  * **Dynamic Containerized Sandboxing:** Integrate lightweight ephemeral Docker containers (or gVisor sandboxes) per connection for high-interaction command logging without host compromise.
  * **Automated Model Retraining & Drift Detection:** Build a scheduled retraining pipeline (`retrain_pipeline.py`) that monitors statistical data drift and updates model weights.
  * **Direct SIEM & Threat Intel Connectors:** Native forwarders for Elastic Agent, Splunk HEC, and automated STIX/TAXII threat intelligence sharing.
  * **Protocol Expansion:** Implement emerging attack surface listeners for RDP (Remote Desktop), SMB (Samba), and IoT protocols (MQTT, CoAP).
  * **Dynamic Fingerprint Randomization:** Rotate banners, SSH host keys, and HTTP headers dynamically to prevent Shodan/Censys indexing.
* **Conclusion:**
  * PhantomPot-v2 successfully demonstrates a complete, operational, multi-protocol deception and threat analysis platform.
  * Fulfilled all 4 research objectives: 4 active protocols, thread-safe SIEM logging, unsupervised ML scoring, and rigorous KPI verification.
  * Provides an accessible, safe, and powerful foundation for active defensive cybersecurity research and SOC training.

### Comprehensive Technical Explanation & Speaker Notes
"To conclude: PhantomPot-v2 delivers a comprehensive, multi-protocol deception and analytics platform that bridges low-level network protocol emulation, thread-safe data engineering, machine learning anomaly detection, and operational SOC tooling.

We have successfully fulfilled all four project objectives:
- Objective 1: Operational concurrent emulation across SSH, HTTP, FTP, and Telnet.
- Objective 2: Standardized, thread-safe JSONL session and event logging.
- Objective 3: 10-feature Isolation Forest behavioral scoring with multi-tier confidence bands.
- Objective 4: An empirical KPI evaluation framework confirming 4/4 protocol coverage, 100% logging integrity, and sub-millisecond response latency.

Looking ahead, the platform is architecturally structured to support Dockerized high-interaction sandboxing, online model retraining, and STIX/TAXII threat intelligence feeds.

Thank you for your time and consideration. I am now ready to answer any questions from the committee."

---

# Comprehensive Viva Examination Defense Guide (Q&A Cheat Sheet)

This section provides technical answers to likely questions from examiners during the project viva or presentation.

### Q1: "Why did you use Isolation Forest instead of supervised classification like Random Forest or SVM?"
* **Answer:** "Supervised models require large volumes of balanced, accurately labeled training data (attack vs. benign). In real-world honeypot deployments, attack patterns evolve continuously, and zero-day exploits have no historical labels. Supervised models tend to overfit to known attack strings. Isolation Forest is unsupervised; it models normality and detects anomalies based on structural sparsity in feature space. This makes it inherently capable of detecting novel, unmodeled attack behaviors without requiring pre-labeled training data."

### Q2: "How do you prevent attackers from breaking out of the honeypot and attacking your host machine?"
* **Answer:** "PhantomPot-v2 enforces complete architectural isolation through three mechanisms:
  1. **Zero OS Shell Access:** Neither `subprocess.Popen`, `os.system`, nor shell execution calls are ever invoked with client input.
  2. **In-Memory Virtual State:** Shell commands (`ls`, `cat`, `cd`) execute within a purely Python-simulated `ShellSession` and static lookup tables.
  3. **Decoupled Decoy Authentication:** The `DecoyAuthPolicy` never consults host OS credentials (`/etc/passwd` or PAM), and passwords are never written to disk or executed."

### Q3: "In eval_report.json, why does KPI-1 Attack Detection Rate show 0.0%?"
* **Answer:** "This is an important evaluation nuance that we documented in `docs/MODEL_ACCURACY_REPORT.md`. During that specific automated batch run of `evaluate_objective4.py`, the simulation script ran 25 attack scenarios, but the ground-truth scenario tags were not piped into the runtime KPI recording collector callback. Thus, the collector counted 0 recorded true positives. However, when evaluating the model against our 1,260 historical sessions and synthetic test scenarios in `evaluate_ml_scenarios.py`, the model achieves an estimated **75% to 85% detection accuracy**, and **98.5% calibration accuracy** against weak heuristic labels."

### Q4: "How does the HTTP honeypot defeat evasion techniques?"
* **Answer:** "It uses a 7-stage normalization pipeline in `src/http_honeypot/payload_analyzer.py`. Attackers frequently use double URL encoding (e.g., `%252e` for `.`), null bytes (`%00`), backslashes (`\`), or full-width Unicode characters (e.g., Unicode slash `／`). Our normalizer strips null bytes, executes two consecutive decoding passes, standardizes Unicode via NFKC normalization, collapses duplicate slashes, and converts Windows backslashes before matching against our 40+ compiled regex patterns."

### Q5: "What is the difference between `logs/sessions.jsonl` and `logs/events.jsonl`?"
* **Answer:** "They represent a dual-stream logging architecture:
  - `logs/sessions.jsonl` stores **macro-level session summaries** (1 record per connection). It contains aggregated metrics (total commands, login attempts, duration), extracted feature vectors, and ML predictions. It is optimized for dashboard analytics and ML model training.
  - `logs/events.jsonl` stores **micro-level atomic events** (1 record per interaction). Every TCP open, password attempt, command, and disconnect is written immediately as a validated Schema v1 record. It is optimized for forensic timeline reconstruction and SIEM ingestion."

### Q6: "Why don't you save submitted passwords in the logs?"
* **Answer:** "This is an intentional security and privacy design choice. Attackers frequently test real credentials obtained from data breaches, and legitimate users or administrators might accidentally mistype real passwords when connecting to the honeypot. Storing passwords on disk creates a high-severity secondary credential-leak vulnerability. PhantomPot-v2 records the username and authentication outcome (`accepted_simulated` or `rejected`), but strips the password before serializing records, and enforces redaction in all dashboard views and PDF/HTML exports."

### Q7: "How is session correlation implemented, and why is it described as 'conservative'?"
* **Answer:** "In `dashboard/investigation.py`, `correlate_sessions()` links sessions that originate from the identical source IP address within a configurable time window (default 900 seconds / 15 minutes). It is described as 'conservative' because it explicitly labels relationships as `potentially_related_same_source_within_window` and includes an anti-attribution disclaimer. In network security, an IP address does not equal an individual threat actor; NAT gateways, public Wi-Fi, Tor exit nodes, and VPNs can cause multiple distinct entities to share an IP address. We avoid making unsubstantiated attribution claims."

---

## Presentation Delivery Recommendations for College Defense

1. **Slide Timing (20-Minute Total Presentation Target):**
   - **Slides 1–4 (Introduction & Objectives):** 3 minutes
   - **Slides 5–7 (Architecture & Tech Stack):** 3 minutes
   - **Slides 8–11 (Multi-Protocol Emulation & Deception):** 4 minutes
   - **Slides 12–13 (Session Management & SIEM Logging):** 2 minutes
   - **Slides 14–16 (ML Pipeline & Calibration):** 3 minutes
   - **Slides 17–19 (Dashboard, Attack Flow, Reports):** 2 minutes
   - **Slides 20–24 (KPI Evaluation, Limitations, Roadmap):** 3 minutes
2. **Demonstration Strategy (if Live Demo is required):**
   - Keep the honeypot running in Terminal 1: `python src/main.py`.
   - Run the dashboard in Terminal 2: `streamlit run dashboard/app.py`.
   - Execute a quick attack in Terminal 3: `curl "http://localhost:8888/../../etc/passwd"` and `ssh admin@localhost -p 2222`.
   - Show the session appearing live on the Streamlit dashboard, click into **Attack Flow** to show the reconstructed killchain stages, and click **Download PDF Report** to showcase the dependency-free reporting feature.
3. **Key Terminology to Emphasize:**
   - *Medium-Interaction Honeypot*
   - *Dual-Stream JSONL Telemetry*
   - *7-Stage Evasion Normalization*
   - *Unsupervised Isolation Forest*
   - *Continuous Confidence Scoring & Decision Bands*
   - *Conservative Same-Source Correlation*
   - *Automated Evidence-Backed Recommendations*
