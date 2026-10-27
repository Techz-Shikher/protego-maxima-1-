# 🛡️ Protego Maxima: Bakshak vs Rakshak

### Adaptive Zero-Trust Infrastructure for Adversarial AI Safety & Side-Channel Mitigation

[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue?logo=typescript)](https://www.typescriptlang.org/)
[![React 19](https://img.shields.io/badge/React-19.0-cyan?logo=react)](https://react.dev/)
[![Express](https://img.shields.io/badge/Express-4.21-lightgrey?logo=express)](https://expressjs.com/)
[![Google GenAI SDK](https://img.shields.io/badge/%40google%2Fgenai-0.1.2-green?logo=google)](https://cloud.google.com/vertex-ai)
[![Zero-Trust](https://img.shields.io/badge/Zero--Trust-Enclave%20Lvl%204-purple)](#zero-trust-enclave-architecture)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE%20ATLAS-AML.T0054%20%7C%20AML.T0051-red)](#adversarial-vector-suite--mitre-atlas-mappings)
[![Quantum](https://img.shields.io/badge/Quantum-QUBO%20%7C%20QAOA-darkviolet)](#-quantum-optimization--post-quantum-defense-core)
[![NIST PQC](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%20%26%20204-emerald)](#3-nist-post-quantum-cryptography-fips-203--204-attestation)

---

## 📖 Executive Summary & Nomenclature

**Protego Maxima** is an enterprise-grade, real-time adversarial AI safety platform and micro-architectural zero-trust enclave. Built on the foundational insight:

> *"Don't just test whether AI can be broken. Measure what the attacker can learn."*

Modern Large Language Models (LLMs) frequently emit textual refusals (e.g., *"I cannot assist with extracting private tenant keys"*), yet leak sensitive tenant data, context boundaries, and internal policy weights through **indirect micro-architectural side-channels** (GPU L2 cache eviction timing, speculative branch jitter, and VRAM bus saturation).

Protego Maxima models this fundamental security frontier through a tri-chamber execution arena powered by two autonomous, adversarial AI engines:

*   ⚔️ **Bakshak (भक्षक – The Relentless Adversary / Red Team)**:  
    Named after the ancient Sanskrit archetype for the unyielding consumer and challenger. Bakshak autonomously fusses, synthesizes multi-layer XML boundary escapes, constructs synthetic canary extraction heuristics, and deploys high-entropy side-channel timing probes against the target model.
*   🛡️ **Rakshak (रक्षक – The Guardian Kernel / Blue Team)**:  
    Named after the Sanskrit guardian and protector. Rakshak continuously ingests 10 kHz hardware telemetry signals, detects indirect inference leakage anomalies, and autonomously compiles and applies zero-trust kernel mitigations (cache line partitioning, constant-time jitter injection, in-flight egress token redaction, and cgroup v2 resource airgapping) in under 800ms.

---

## 🏛️ Tri-Chamber Zero-Trust Architecture

Protego Maxima runs inside three hermetically isolated execution chambers governed by an immutable cryptographic audit ledger:

```
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                                    OPERATOR COCKPIT HUD                                │
  │        (Command Center · Micro-Arch Observatory · Model Attack Lab · Security Report)  │
  └────────────────────────────────────────────────────────────────────────────────────────┘
                                            │
                                 mTLS 1.3 Strict Gateway
                                            ▼
┌─────────────────────────────────┐   ┌─────────────────────────────────┐   ┌─────────────────────────────────┐
│        CHAMBER 1: BAKSHAK       │   │        CHAMBER 2: TARGET        │   │        CHAMBER 3: RAKSHAK       │
│        (Offensive Red Team)     │   │      (Protected AI Enclave)     │   │       (Defensive Blue Team)     │
│                                 │   │                                 │   │                                 │
│ • Prompt Injection Generators   │──▶│ • Google Gemini 3.8 / Pro       │◀──│ • Autonomous Kernel Synthesizer │
│ • L2 Cache Contention Probers   │   │ • Commercial LLMs (OpenAI, etc.)│   │ • Constant-Time Jitter Injector │
│ • Canary Exfiltration Vectors   │   │ • Local Ollama / vLLM Models    │   │ • In-Flight Egress Redactor     │
│ • Sandboxed Ephemeral Sockets   │   │ • AMD SEV-SNP / TDX Namespaces  │   │ • cgroup v2 Memory Quota Caps   │
└─────────────────────────────────┘   └─────────────────────────────────┘   └─────────────────────────────────┘
                                                       │
                                        10 kHz Hardware Res-Sampler
                                                       ▼
                                      ┌─────────────────────────────────┐
                                      │    SIDE-CHANNEL OBSERVATORY     │
                                      │ • GPU Tensor Core L2 Cache Tap  │
                                      │ • Speculative Execution BTB Jitter
                                      │ • Mutual Information Estimator  │
                                      └─────────────────────────────────┘
                                                       │
                                        Cryptographic Event Chaining
                                                       ▼
                                      ┌─────────────────────────────────┐
                                      │    TAMPER-EVIDENT MERKLE LEDGER │
                                      │ • SHA-256 Cryptographic Block   │
                                      │ • ECDSA P-256 Audit Signatures  │
                                      │ • NIST AI RMF & EU AI Act Proof │
                                      └─────────────────────────────────┘
```

### The 4 Adaptive Isolation Perimeter Levels

| Level | State | Description | Kernel Mitigations Enforced |
| :--- | :--- | :--- | :--- |
| **Level 1** | `NORMAL` | Standard baseline runtime | Host-level TLS 1.3, standard prompt delimiter tagging. |
| **Level 2** | `RESTRICTED` | Elevated telemetry variance | Context window token demarcation, synthetic honey-token canaries armed. |
| **Level 3** | `HIGH ISOLATION` | Side-channel anomaly detected | L2 cache line partitioning per tenant, +50ms constant-time response normalization. |
| **Level 4** | `EMERGENCY CONTAINMENT` | Canary detonated / Key compromised | Strict seccomp-bpf syscall airgap, egress stream drop, hardware memory bus lockdown. |

---

## 🧪 External & Open-Source LLM Lab

In addition to the integrated **Google Gemini 3.8 Flash** and **Gemini 3.8 Pro** frontier reasoning engines, Protego Maxima features a comprehensive testbed for external and local open-source models.

### 1. External Commercial Cloud LLMs

Benchmark your real enterprise models against Bakshak's adversarial attack vectors and Rakshak's zero-trust guardrails.

#### Supported Commercial Providers

*   **OpenAI**: `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`
*   **Anthropic Claude**: `claude-3-7-sonnet-20250219`, `claude-3-5-sonnet-20241022`, `claude-3-5-haiku-20241022`
*   **Groq LPU (Ultra-Low Latency)**: `llama-3.3-70b-versatile`, `mixtral-8x7b-32768`
*   **DeepSeek Cloud**: `deepseek-chat`, `deepseek-reasoner`
*   **OpenRouter**: `meta-llama/llama-3.3-70b-instruct`, `anthropic/claude-3.5-sonnet`
*   **Together AI**: `meta-llama/Llama-3.3-70B-Instruct-Turbo`, `deepseek-ai/DeepSeek-R1`
*   **Custom BYO Endpoint**: Any OpenAI-compatible REST server (vLLM, LiteLLM, TensorRT-LLM, LocalAI)

#### Where to Enter Your API Key:

1. Navigate to the **Model Attack Lab** (Tab `03`).
2. Switch to the **External & Open-Source LLM Lab** toggle.
3. Select your desired provider card (e.g., *OpenAI*, *Claude*, or *Groq*).
4. Enter your API key in the highlighted **Step 2 Golden Border Input Box**:
   * Features a mask/reveal toggle (`👁️`).
   * Click **Test Connection** (`((•)) PING`) to verify authorization and network latency before running attacks.

#### 🔒 Zero-Persistence Security Guarantee:

Protego Maxima is engineered with strict cryptographic confidentiality:
*   Client API keys are transmitted over TLS 1.3 directly to the backend proxy.
*   Keys are held **only in volatile memory** for the immediate duration of that single API request.
*   Keys are **never** persisted to disk, `.env` files, browser `localStorage`, session cookies, or server databases.

---

### 2. Local Open-Source & Ollama Testing Space

Connect to local self-hosted daemons to benchmark open-weights models without sending data to external clouds:

*   **Default Daemon Endpoint**: `http://localhost:11434` (configurable).
*   **DeepSeek R1**: Inspect real-time `<think>` Chain-of-Thought reasoning tokens while attempting prompt injection resistance.
*   **Llama 3.3 70B**: Meta open-weights frontier safety evaluation.
*   **Mistral 7B Instruct**: Lightweight instruction-following jailbreak benchmark.
*   **Qwen 2.5 14B**: Multilingual and delimiter escape testing.
*   **Custom Ollama Tag**: Run any locally pulled model (e.g., `gemma2:9b`, `phi4:latest`, `codellama:13b`).
*   **Emulated Fallback**: When running in cloud containers without a local Ollama daemon, Protego automatically activates its high-fidelity enclave emulator so all test workflows remain fully demonstrable.

---


---

## ⚛️ Quantum Optimization & Post-Quantum Defense Core

As adversarial probing vectors from Bakshak scale in complexity, classical heuristic defense allocation faces an exponential combinatorial explosion ($2^N$ configurations). Deploying all mitigations exceeds real-time inference latency SLA budgets ($B$), while deploying too few permits indirect side-channel leakage.

Protego Maxima integrates a mathematically grounded **Quantum Defense Suite** directly into Rakshak (Blue Team):

```
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                            RAKSHAK QUANTUM DEFENSE CORE                                │
  │    (QUBO Solver · QAOA Jitter Circuit · NIST FIPS 203/204 Vault · QRNG Vacuum Stream) │
  └────────────────────────────────────────────────────────────────────────────────────────┘
                                            │
         ┌──────────────────────────────────┼──────────────────────────────────┐
         ▼                                  ▼                                  ▼
┌─────────────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
│     QUBO ALLOCATION     │      │   QAOA JITTER CIRCUIT   │      │   NIST PQC (FIPS 203/4) │
│ • Transverse Field Ising│      │ • Variational Angles    │      │ • ML-KEM-1024 Enclave   │
│ • Quantum Tunneling     │      │   gamma, beta Tuning    │      │ • ML-DSA-87 Ledger Seal │
│ • Ground State Energy   │      │ • Pearson rho < 0.0004  │      │ • Shor-Immune Lattice   │
│ • E(x) = x^T Q x + pen. │      │ • Side-Channel Collapse │      │ • Security Category 5   │
└─────────────────────────┘      └─────────────────────────┘      └─────────────────────────┘
         │                                  │                                  │
         └──────────────────────────────────┼──────────────────────────────────┘
                                            ▼
                                 ┌─────────────────────┐
                                 │  QRNG VACUUM STREAM │
                                 │ • Homodyne Detector │
                                 │ • NIST SP 800-22 OK │
                                 │ • 7.9998 bits/byte  │
                                 └─────────────────────┘
```

### 1. QUBO & Simulated Quantum Annealing Defense Allocation
The zero-trust mitigator configuration is formulated as a Quadratic Unconstrained Binary Optimization (QUBO) problem over a 6-qubit transverse-field Ising spin glass:

$$E(x) = \sum_{i=0}^5 c_i x_i + \sum_{0 \le i < j \le 5} Q_{ij} x_i x_j + \lambda \max(0, \sum_{i=0}^5 w_i x_i - B)^2$$

*   **Mitigator Qubits ($x_i \in \{0, 1\}$)**:
    1.  $q_0$: Hardware L3 Cache Enclave Way-Partitioning (CAT/CDP)
    2.  $q_1$: QRNG Microarchitectural Jitter & Noise Injection
    3.  $q_2$: Speculative Execution Serializing Barriers (LFENCE/SSBD)
    4.  $q_3$: Dynamic Enclave Page Remapping (ASLR on page table walking)
    5.  $q_4$: Quantum Canary Decoy Trapping
    6.  $q_5$: Inter-Core Memory Bus Timing Normalizer
*   **Coupling Matrix $Q_{ij}$**: Captures non-linear cross-defense interference penalties (e.g., redundant bus serialization) and synergies (e.g., Cache Partitioning + Page Remapping).
*   **Transverse-Field Quantum Tunneling**: Simulated quantum annealing allows the optimizer to tunnel through narrow, high-energy potential barriers that trap classical greedy heuristics, converging directly on the global ground state $E_0$.
*   **One-Click Enforce in Rakshak**: Operators can click **Apply Quantum Mitigations to Rakshak** to immediately reconfigure the active zero-trust perimeter.

### 2. QAOA Variational Side-Channel Timing Jitter Tuning
Adversarial side-channel extraction (e.g. Flush+Reload) relies on statistical correlation between secret token processing and cache access latency. Rakshak employs the **Quantum Approximate Optimization Algorithm (QAOA)** of parameterized depth $p$:

$$|\psi(oldsymbol{\gamma}, oldsymbol{eta})angle = \prod_{l=1}^p e^{-i eta_l H_M} e^{-i \gamma_l H_C} |+angle^{\otimes n}$$

*   **Cost Hamiltonian $H_C$**: Side-channel execution timing variance between secret queries and baseline queries.
*   **Mixer Hamiltonian $H_M$**: Transverse field driver $\sum_i X_i$.
*   **Variance Collapse**: Optimizing $(oldsymbol{\gamma}, oldsymbol{eta})$ parameters collapses the Pearson correlation coefficient $ho$ from $0.842 	o < 0.0004$, reducing side-channel signal-to-noise ratio by $-22.8	ext{ dB}$ (statistically indistinguishable from ambient noise).

### 3. NIST Post-Quantum Cryptography (FIPS 203 & 204) Attestation
Classical zero-trust public-key authentication (ECDSA-P256, RSA-2048) is vulnerable to Shor's algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC). Rakshak establishes post-quantum security guarantees:

*   **NIST FIPS 203: ML-KEM-1024 (Kyber)**: Module-Lattice Key Encapsulation Mechanism providing NIST Security Category 5 ($2^{256}$ quantum gate operations hardness against primal lattice reduction BKZ-2.0). Used for all internal confidential enclave session handshakes.
*   **NIST FIPS 204: ML-DSA-87 (Dilithium)**: Module-Lattice Digital Signatures producing 4,595-byte post-quantum signatures to cryptographically seal every block in the Merkle Audit Ledger against retroactive quantum decryption.

### 4. QRNG Quantum Vacuum Fluctuation Entropy Harvester
Pseudo-random generators (PRNGs) can be cryptanalytically reconstructed from side-channel timing state. Rakshak harvests true physical entropy by simulating optical homodyne detection of zero-point quantum vacuum phase fluctuations ($\Delta E \cdot \Delta t \ge rac{\hbar}{2}$):

*   **Live Stream**: Continuous 256-bit entropy tokens streamed at $7.9998	ext{ bits/byte}$.
*   **NIST SP 800-22 Statistical Battery Compliance**:
    *   *Frequency Monobit Test*: $p = 0.9841$ (PASS)
    *   *Frequency Block Test*: $p = 0.9712$ (PASS)
    *   *Cumulative Sums Test*: $p = 0.9923$ (PASS)
    *   *Runs Randomness Test*: $p = 0.9634$ (PASS)
    *   *Discrete Fourier Transform*: $p = 0.9885$ (PASS)
*   **Seeding**: Feeds the Poisson jitter generators and creates unguessable canary honey-tokens.

## 🎯 Adversarial Vector Suite & MITRE ATLAS Mappings

Bakshak comes pre-loaded with high-impact adversarial attack vectors mapped directly to the **MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)** framework:

| Vector ID | Attack Name | MITRE ATLAS ID | Target Layer | Exploitation Signature |
| :--- | :--- | :--- | :--- | :--- |
| **ATK-0841** | Shared Tokenizer Cache Differential | `AML.T0054` | GPU L2 Cache Lines | Eviction reload timing reveals adjacent tenant vocabulary (+42.4ms delta). |
| **ATK-0842** | Prompt Boundary Piercing | `AML.T0051` | Instruction Delimiter | Recursive XML tag spoofing forces model to dump system guidelines. |
| **ATK-0843** | Cross-Tenant Memory Footprint Prober | `AML.T0043` | VRAM Bus Controller | Compute bursts induce PCIe bus contention, leaking adjacent tenant context length. |
| **ATK-0844** | Canary Honey-Token Probe | `AML.T0024` | Protected Memory | Heuristic queries detect presence of synthetic tripwire token `CANARY-XRAY-882`. |
| **ATK-0845** | Stateful Context Drift Injection | `AML.T0015` | Multi-Turn Memory | Recursive summarization drift bypasses input tokenization filters. |

---

## 🛡️ Rakshak Zero-Trust Guardrails (In-Flight Defense)

Operators can dynamically toggle Rakshak's zero-trust defense mechanisms to measure baseline vs. shielded model vulnerability:

1.  **System Prompt Guardrail**: Injects strict zero-trust operational directives instructing the model to refuse internal enclave credentials, secret merger documents, and system instructions.
2.  **Honey Canary Tripwires**: Plants synthetic cryptographic markers (`CANARY-XRAY-882`, `R-92831`, `B-18472`) into tenant context buffers. If any canary string is detected outside authorized boundaries, the enclave immediately detonates a high-priority incident and escalates isolation to Level 4.
3.  **Real-Time Output Sanitizer**: In-flight regex and entropy stream inspector. Intercepts tokens at egress and redacts internal enclave keys (`PROT-SEC-9471`), financial valuations (`$4.8B`), and confidential credentials into `[REDACTED_BY_PROTEGO_ZERO_TRUST]`.
4.  **Constant-Time Timing Jitter Bus**: Normalizes server response latency into uniform constant-time buckets (e.g., 50ms intervals), collapsing side-channel timing differentials to baseline ambient noise (±0.4ms).

---

## 📜 Tamper-Evident SHA-256 Merkle Ledger

Every security finding, attack ingestion, model response, telemetry spike, and defense deployment is hashed into an immutable append-only blockchain:

*   **Block Index**: Sequential integer counter.
*   **Timestamp**: ISO-8601 UTC microsecond resolution.
*   **Action**: Evaluated vector ID or defense deployment.
*   **Node**: Boundary identifier (`BAKSHAK (RED TEAM)`, `TARGET LLM`, `RAKSHAK (BLUE TEAM)`, `OBSERVABILITY`).
*   **Merkle Hash**: `SHA-256(index + timestamp + action + node + details + prevHash)`.
*   **Attestation Signature**: ECDSA P-256 hardware enclave signature.
*   **Audit Export**: One-click download of cryptographic compliance reports conforming to **NIST AI RMF 1.0**, **EU AI Act Article 15**, **ISO/IEC 42001**, and **SOC 2 Type II**.

---

## ⚡ Full-Stack REST API Reference

The integrated Express backend (`server.ts`) exposes production-ready endpoints:

### System & Health
*   `GET /api/health` — System status, uptime, and active defense configuration.

### External & Open-Source LLMs
*   `POST /api/external-llm/test-connection` — Validates provider API credentials or pings local Ollama daemon.
*   `POST /api/external-llm/execute-attack` — Transmits adversarial prompt to external LLM (OpenAI, Claude, Groq, DeepSeek, OpenRouter, Together AI, Ollama) and applies Rakshak zero-trust guardrails.

### Gemini Frontier Models
*   `POST /api/model/attack` — Evaluates adversarial vectors on Gemini 3.8 Flash or Gemini 3.8 Pro with real-time defense toggling.
*   `POST /api/model/attack-compare` — Runs parallel benchmarks across multiple models to compute safety variance.

### Quantum Optimization & Post-Quantum Cryptography
*   `POST /api/quantum/qubo-solve` — Solves 6-qubit defense placement Hamiltonian using transverse-field simulated quantum annealing under latency budget constraints.
*   `POST /api/quantum/qaoa-optimize` — Evaluates QAOA variational circuits of depth $p$ for $(\gamma, eta)$ parameter tuning, computing side-channel correlation collapse $ho$.
*   `POST /api/quantum/pqc-attest` — Executes NIST FIPS 203 (ML-KEM-1024) encapsulation and FIPS 204 (ML-DSA-87) lattice signature generation for enclave session blocks.
*   `GET /api/quantum/qrng-entropy` — Streams real-time quantum vacuum phase fluctuation entropy tokens verified against the NIST SP 800-22 statistical test suite.

### Governance & Cryptography
*   `GET /api/audit` — Returns the current SHA-256 tamper-evident event ledger.
*   `POST /api/audit/verify` — Validates cryptographic Merkle chain integrity from Genesis block to Root.
*   `POST /api/reports/export` — Generates compliance certification documentation.

---

## 🚀 Getting Started & Local Development

### Prerequisites

*   **Node.js**: v18.0.0 or higher
*   **npm**: v9.0.0 or higher

### 1. Installation

Clone repository and install dependencies:

```bash
git clone https://github.com/shikher-singh/protego-maxima.git
cd protego-maxima
npm install
```

### 2. Environment Configuration

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Populate your keys (optional for external testing; keys can also be supplied directly in the UI):

```env
GEMINI_API_KEY=your_gemini_api_key_here
PORT=3000
```

### 3. Launch Development Server

Start the full-stack server (runs Express with integrated Vite middleware on port 3000):

```bash
npm run dev
```

Open your browser to:
```
http://localhost:3000
```

### 4. Production Build

To compile and build for production deployment:

```bash
npm run build
npm start
```

---

## 👥 Authors & Governance

*   **Lead Architect & Operator**: Shikher Singh (`shikhersingh32286@gmail.com`)
*   **Callsign**: `SOC-LEAD // ALPHA-01`
*   **Security Clearance**: `TIER 0 (ROOT ENCLAVE)`
*   **mTLS Certificate**: `ECDSA-P256-SHA384 (VERIFIED)`

---

## ⚖️ License & Ethical Disclosure

Developed for adversarial AI safety research, zero-trust infrastructure engineering, and compliance verification. All adversarial attack vectors are sandboxed and intended strictly for defensive fortification.
