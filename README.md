# 🚨 THREAT LENS AI: Autonomous Multi-Vector Cyber Defense & SOC Platform

[![React](https://img.shields.io/badge/React-19.2-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-8.x-646CFF?logo=vite&logoColor=white)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4-38B2AC?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Netlify](https://img.shields.io/badge/Deploy-Netlify-00C7B7?logo=netlify&logoColor=white)](https://www.netlify.com/)
[![VirusTotal](https://img.shields.io/badge/Intelligence-VirusTotal_v3-3949AB?logo=virustotal&logoColor=white)](https://www.virustotal.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Tagline:** *Detect. Explain. Respond. Protect.*  
> **Mission:** Democratizing enterprise-grade Security Operations Center (SOC) intelligence with explainable multi-modal AI, real-time threat telemetry, and automated sub-second SOAR containment.

---

## 📑 Table of Contents
1. [Executive Summary & Problem Statement](#-executive-summary--problem-statement)
2. [Master Glossary: Definitions of Every Term & Acronym](#-master-glossary-definitions-of-every-term--acronym)
3. [Architecture & End-to-End Workflow Principle](#-architecture--end-to-end-workflow-principle)
4. [Source Code Map: Where Every Section Lives](#-source-code-map-where-every-section-lives)
5. [Deep Dive: How Each Security Module Operates (Bit by Bit)](#-deep-dive-how-each-security-module-operates-bit-by-bit)
   - [Landing Page: Monumental Hero Command](#1-landing-page-monumental-hero-command)
   - [SOC Command Center & SENTINEL-9 Interceptor](#2-soc-command-center--sentinel-9-interceptor)
   - [Real-Time Phishing & URL Analyzer](#3-real-time-phishing--url-analyzer)
   - [AI Email Phishing & Header Forensic Scanner](#4-ai-email-phishing--header-forensic-scanner)
   - [SMS, WhatsApp & Social Engineering Analyzer](#5-sms-whatsapp--social-engineering-analyzer)
   - [Deepfake & Synthetic AI Image Forensics](#6-deepfake--synthetic-ai-image-forensics)
   - [Network Traffic & C2 Beaconing Analyzer](#7-network-traffic--c2-beaconing-analyzer)
   - [Malicious File & Shannon Entropy Forensic Engine](#8-malicious-file--shannon-entropy-forensic-engine)
   - [CyberGuard AI SOC Copilot](#9-cyberguard-ai-soc-copilot)
   - [Live Attack Simulation Engine](#10-live-attack-simulation-engine)
6. [Complete Technology Stack & Architecture Decisions](#-complete-technology-stack--architecture-decisions)
7. [External APIs, Protocols & Data Contracts](#-external-apis-protocols--data-contracts)
8. [Competitive Differentiation & Why Threat Lens AI Wins](#-competitive-differentiation--why-threat-lens-ai-wins)
9. [Hackathon Pitch Guide & 3-Minute Judge Demo Script](#-hackathon-pitch-guide--3-minute-judge-demo-script)
10. [Installation, Local Development & Netlify Deployment](#-installation-local-development--netlify-deployment)

---

## 🎯 Executive Summary & Problem Statement

### The Real-World Crisis
Cybercrime damages exceed **$10.5 Trillion annually**. Modern attacks no longer rely strictly on executable malware; **over 90% of successful breaches originate through social engineering, phishing, and identity impersonation**:
- **Business Email Compromise (BEC):** The FBI IC3 reports over **$2.9 Billion in direct annual losses** from executive impersonation and wire transfer fraud.
- **Credential Harvesting Phishing:** 3.4 billion phishing emails are transmitted globally daily, bypassing conventional spam filters using lookalike homoglyphs and zero-day hosting domains.
- **AI-Powered Deepfakes:** Attackers now generate synthetic executive video and imagery in seconds to authorize fraudulent financial transactions and bypass KYC biometric verifications.
- **Alert Fatigue in Enterprise SOCs:** Security analysts drown in an average of **11,000 alerts per day**. Over 30% of critical alerts are delayed, with the average breach detection window stretching to **207 days**.

### Why Existing Solutions Fail
| Existing Approach | Fatal Flaw |
| :--- | :--- |
| **Traditional Secure Email Gateways (SEGs)** | Rely on static signature blocklists. Blind to zero-day domains, typosquatting homoglyphs, and cognitive manipulation. |
| **Traditional Antivirus (AV)** | Only scans local disk binaries. Completely incapable of detecting QR-code phishing (Quishing), brand impersonation, or C2 network beaconing. |
| **Naive "AI Wrapper" Hackathon Tools** | Submit entire user mailboxes blindly to commercial LLMs—violating data privacy (GDPR/HIPAA), generating hallucinations, and costing hundreds of dollars in API tokens. |
| **Enterprise SIEMs (Splunk / QRadar)** | Prohibitively expensive ($100k+/year), require months of specialized configuration, and do not provide accessible, human-readable explanations. |

### The Solution: Threat Lens AI
Threat Lens AI provides a **unified, multi-modal autonomous defense platform** combining:
1. **Zero-Trust Indicator Extraction & Heuristic Filters** that flag structural anomalies in milliseconds client-side.
2. **Deterministic Threat Intelligence** cross-referencing findings against **70+ industry Antivirus engines via VirusTotal v3** and **AbuseIPDB v2**.
3. **Explainable AI (XAI)** decomposing risk into transparent, mathematically weighted factor contributions.
4. **Autonomous SOAR Orchestration** executing immediate edge containment (DNS sinkholing, session null-routing, honeypot decoy deployment).

---

## 📖 Master Glossary: Definitions of Every Term & Acronym

| Term / Acronym | Full Form | Clear Technical Definition |
| :--- | :--- | :--- |
| **SOC** | **Security Operations Center** | A centralized command unit within an organization dealing with operational security issues on an organizational and technical level. |
| **SOAR** | **Security Orchestration, Automation, and Response** | Software capabilities that enable organizations to coordinate, execute, and automate incident response tasks (e.g. firewall blocking, quarantine) without human latency. |
| **XAI** | **Explainable Artificial Intelligence** | AI systems designed to explain their reasoning, factor weights, and decisions in human-interpretable language rather than acting as opaque "black boxes." |
| **IoC** | **Indicator of Compromise** | Forensic artifacts (IP addresses, domain names, cryptographic file hashes, registry keys) that indicate a computer system has been breached. |
| **MITRE ATT&CK** | **Adversarial Tactics, Techniques, and Common Knowledge** | A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations (e.g., T1566 Phishing, T1071 C2 Traffic). |
| **Homoglyph Attack** | **Internationalized Domain Name (IDN) Spoofing** | Registering domain names that look identical to a legitimate brand by substituting visually similar characters from other alphabets (e.g., Cyrillic `а` or numeral `1` instead of Latin `a` or `l`: `paypa1.com`). |
| **Typosquatting** | **URL Hijacking** | Registering deliberately misspelled variations of popular domain names (e.g. `g00gle.com` or `amzon.com`) to trap users who make typing mistakes. |
| **Shannon Entropy** | **Information Entropy / File Randomness** | A mathematical measure of bit randomness ranging from `0.0` to `8.0`. Standard plaintext has low entropy (~3.5–5.0), whereas encrypted or packed malware exhibits high entropy (>7.2). |
| **C2 Beaconing** | **Command and Control Periodic Signatures** | Regular, outbound network requests sent at fixed or jittered intervals from compromised endpoints to an attacker's external server to receive instructions or exfiltrate data. |
| **SPF** | **Sender Policy Framework** | An email authentication protocol that specifies which mail servers and IP addresses are authorized to send emails on behalf of a specific domain via DNS TXT records. |
| **DKIM** | **DomainKeys Identified Mail** | A cryptographic authentication method that attaches a digital signature to the email header, proving the email was not forged or altered in transit. |
| **DMARC** | **Domain-based Message Authentication, Reporting, and Conformance** | An email policy protocol combining SPF and DKIM to determine whether an email claiming to come from a domain should be accepted, quarantined, or rejected. |
| **DoH** | **DNS over HTTPS** | A protocol for performing remote Domain Name System resolution via encrypted HTTPS, preventing eavesdropping and DNS spoofing. |
| **Bayer Pattern Noise** | **Physical Sensor Photon Shot Noise** | High-frequency physical sensor noise produced by real optical camera sensors. Synthetic AI-generated images lack authentic Bayer sensor noise distributions. |
| **Vision Transformer (ViT)** | **Visual Deep Learning Model** | A machine learning architecture that applies Transformer self-attention mechanisms to image patches to detect diffusion artifacts and deepfake synthesis. |
| **Honeytoken / Canary** | **Deceptive Defensive Decoy** | Bogus credentials, API keys, or network endpoints deployed to lure adversaries and detect unauthorized reconnaissance. |

---

## ⚙️ Architecture & End-to-End Workflow Principle

Threat Lens AI operates an **Autonomous Closed-Loop Cyber Defense Cycle**:

```
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │                              UNIFIED THREAT LIFECYCLE                                  │
 │                                                                                        │
 │   1. INGESTION  ──►  2. INDICATOR EXTRACTION  ──►  3. THREAT ENRICHMENT                │
 │        │                      │                             │                          │
 │        ▼                      ▼                             ▼                          │
 │   Email / URL /        Domain, Headers,              VirusTotal v3 (70+ AVs)           │
 │   SMS / File /         MIME, Hashes,                 AbuseIPDB (IP Reputation)         │
 │   Media / NetFlow      Entropy, Bytes                Cloudflare DoH (Live DNS)         │
 │                                                             │                          │
 │                                                             ▼                          │
 │   6. CONTAIN (SOAR) ◄── 5. EXPLAIN (XAI)     ◄─── 4. MULTI-MODAL SCORING               │
 │        │                      │                             │                          │
 │        ▼                      ▼                             ▼                          │
 │   Edge BGP Null-Route  Factor Contribution           Composite Risk Engine             │
 │   Perimeter DNS Sink   Weights (+30 / -10)           [0 - 100 Algorithm]               │
 │   Deploy Honeytokens   Human-Readable Reason         SAFE / SUSP / CRITICAL            │
 └────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5-Tier Composite Severity Calculus
$$\text{Risk Score} = \min\left(100, \max\left(0, \sum \text{Threat Indicators} - \sum \text{Trust Factors}\right)\right)$$

- 🟢 **SAFE:** `0 – 20` (Authenticated domains, clean VirusTotal reputation, valid SPF/DKIM)
- 🟢 **LOW RISK:** `21 – 40` (Minor anomalies, unverified headers)
- 🟡 **MEDIUM SUSPICIOUS:** `41 – 60` (Urgent language, recent domain registration < 30 days)
- 🟠 **HIGH RISK:** `61 – 80` (Severe cognitive manipulation, missing reverse DNS, C2 beaconing pattern)
- 🔴 **CRITICAL THREAT:** `81 – 100` (Homoglyph brand spoofing, VirusTotal consensus detection, packed binary entropy > 7.5)

---

## 🗺️ Source Code Map: Where Every Section Lives

| Section / Feature Name | File Path | Primary Function & Logic |
| :--- | :--- | :--- |
| **Landing Page** | `src/pages/LandingPage.tsx` | High-impact kinetic hero interface with direct CTA buttons to Launch Console & Trigger Live Threat Demo. |
| **SOC Command Center Dashboard** | `src/pages/SocDashboard.tsx` | Central telemetry hub with 7 core metric counters, live threat feed, high-risk users, and modality distribution chart. |
| **SENTINEL-9 Threat Interceptor** | `src/components/dashboard/GlobalThreatMap.tsx` | Interactive SVG orbital defense radar, clickable global edge nodes, APT wave simulator, and live hex decompiler with Shannon entropy. |
| **URL & Website Analyzer** | `src/pages/UrlAnalyzerPage.tsx` | Homoglyph typosquatting detector, live VirusTotal v3 URL report, domain age verification, and SSL certificate inspection. |
| **AI Email Phishing Scanner** | `src/pages/EmailAnalyzerPage.tsx` | Inbound email forensic NLP, SPF/DKIM/DMARC header validation, psychological coercion detection, and sandbox detonator. |
| **SMS & WhatsApp Analyzer** | `src/pages/MessageAnalyzerPage.tsx` | Tokenized cognitive urgency parsing, financial lottery/KYC smishing detection, and correlated live VirusTotal link intelligence. |
| **Deepfake & AI Media Scanner** | `src/pages/MediaAnalyzerPage.tsx` | Synthetic AI image forensics, Bayer sensor noise inspection, Fourier spectral grid, and Google Gemini Vision 2.0 API consensus. |
| **Network Threat Radar** | `src/pages/NetworkAnalyzerPage.tsx` | AbuseIPDB v2 reputation checks, NetFlow velocity burst detection, and periodic C2 jitter beaconing analysis. |
| **Malicious File Forensics** | `src/pages/FileAnalyzerPage.tsx` | Static PE/ELF binary header parser, SHA-256 hash generator, and Shannon byte entropy scanner (>7.2 packed threshold). |
| **CyberGuard AI Copilot** | `src/components/copilot/CyberCopilotDrawer.tsx`<br>`src/services/copilotService.ts` | Grounded multi-turn conversational AI analyst powered by Google Gemini API with instant triage action recommendations. |
| **Live Attack Simulator** | `src/components/simulation/AttackSimulationModal.tsx`<br>`src/data/attackScenarios.ts` | Interactive multi-step cyber warfare scenario detonator with real-time audit logging and confetti celebration. |
| **Global State Context** | `src/context/CyberGuardContext.tsx` | Unified React Context managing active threats, incident states, real-time metrics, notifications, and SOAR execution. |
| **URL Intelligence Service** | `src/services/urlIntelligenceService.ts` | VirusTotal v3 REST client, Cloudflare DNS-over-HTTPS resolver, and homoglyph algorithmic classifier. |
| **Network Intelligence Service** | `src/services/networkApiService.ts` | AbuseIPDB v2 REST API integration, IP CIDR analyzer, and port risk scanner. |
| **Deepfake Intelligence Service**| `src/services/deepfakeApiService.ts` | Gemini 2.0 Vision multimodal AI prompt engine with offline synthetic forensic fallback. |
| **Core Threat Engine** | `src/services/threatEngine.ts` | Master rule evaluation engine computing explainable weights (+30/-10) and SOAR action generation. |

---

## 🔍 Deep Dive: How Each Security Module Operates (Bit by Bit)

### 1. Landing Page: Monumental Hero Command
- **File:** `src/pages/LandingPage.tsx`
- **Working Principle:** Built strictly as a high-impact, award-winning entry point designed to captivate hackathon judges immediately.
- **Components:**
  - **Monumental Kinetic Headline:** `THREAT LENS AI` with a luminous radiant gradient on `AI` (`text-6xl sm:text-8xl md:text-9xl lg:text-[9.5rem] font-mono font-black`).
  - **Four Pillars Tagline:** `Detect. • Explain. • Respond. • Protect.` with distinctive neon cyberpunk styling.
  - **Dual Action CTAs:**
    - `[LAUNCH SECURITY CONSOLE]`: Transitions directly into the SOC Command Center (`SocDashboard`).
    - `[RUN LIVE THREAT DEMO]`: Instantly detonates a zero-day phishing attack simulation.
  - **Ambient Atmosphere:** Dynamic radial backdrop glows (`cyan`, `purple`, `blue`) with subtle architectural cyber-grid lines.

---

### 2. SOC Command Center & SENTINEL-9 Interceptor
- **Files:** `src/pages/SocDashboard.tsx`, `src/components/dashboard/GlobalThreatMap.tsx`
- **Working Principle:** Provides an elite, cinematic cybersecurity operations cockpit inspired by CrowdStrike Falcon and Palantir Gotham.
- **Core Elements:**
  - **7 Core Metric Counters:**
    - `Threats Detected` (+14 today)
    - `Critical` (Immediate Action)
    - `Phishing` (URLs & Emails)
    - `Impersonation` (Look-alikes)
    - `Blocked SOAR` (99.2% Mitigated)
    - `Active Incidents` (In Triage)
    - `Protected Nodes` (Endpoints)
  - **Autonomous Global Threat Interceptor (SENTINEL-9 HUD):**
    - **Interactive SVG Radar Mesh:** Features a 360° sweeping beam with real-time azimuth coordinates and range rings.
    - **Global Edge Nodes:** `Frankfurt Core Gateway`, `Ashburn Cloud Fabric`, `Tokyo FinTech Edge`, `Mumbai HyperEdge DC`, and `São Paulo Transit Node`. Clicking any node displays round-trip latency, connection protocols, and active threat status.
    - **Interactive Defense Toolbar:**
      - `[Simulate APT Wave]`: Launches an active adversary intrusion attempt with animated red attack trajectories on the radar.
      - `[Deploy Canary Decoy]`: Dynamically arms honeytoken deception nodes.
      - `[Engage Cloak]`: Toggles perimeter subnet shielding.
      - `[Execute SOAR Containment]`: Performs edge null-routing and session invalidation.
    - **Raw Hex Decompiler & Shannon Entropy Stream:** Displays live decompiled payload fragments and calculates Shannon entropy (`7.94 / 8.0` indicates metamorphic packing/obfuscation).
  - **Threat Distribution by Modality:**
    - Scaled Recharts horizontal bar chart (`min-h-[380px]`) displaying exact counts via `<LabelList>` across 6 vectors:
      - `Phishing` (438)
      - `Malicious Files` (229)
      - `ATO & Auth` (215)
      - `Network C2` (184)
      - `Impersonation` (126)
      - `Deepfake` (92)
  - **Live Multi-Modal Threat Stream:** Real-time event log with play/pause controls and instant SOAR execution buttons.
  - **24-Hour Threat Ingestion & Mitigation Telemetry:** Dynamic Recharts AreaChart tracking hourly total vs. blocked threats.

---

### 3. Real-Time Phishing & URL Analyzer
- **Files:** `src/pages/UrlAnalyzerPage.tsx`, `src/services/urlIntelligenceService.ts`
- **Working Principle:** Evaluates suspicious web addresses in real time before users interact with them.
- **Workflow:**
  1. **Homoglyph & Punycode Scanner:** Detects lookalike character substitutions (`paypa1.com`, `g00gle.com`).
  2. **VirusTotal v3 Consensus:** Base64-encodes the URL and queries 70+ antivirus engines.
  3. **Cloudflare DoH DNS Resolution:** Resolves live DNS `A` records to detect fast-flux evasion and domain registration age.
  4. **SSL/TLS Certificate Forensic:** Flags deceptive HTTPS certificates on newly registered domains.
  5. **Explainable AI Breakdown:** Outputs factor weights (e.g. `+35 Homoglyph Typosquat`, `+40 VirusTotal 14/72 Engines`, `-10 Verified Cloudflare CDN`).

---

### 4. AI Email Phishing & Header Forensic Scanner
- **Files:** `src/pages/EmailAnalyzerPage.tsx`, `src/services/threatEngine.ts`
- **Working Principle:** Comprehensive static forensic analysis of raw email headers, MIME structures, and body copy.
- **Workflow:**
  1. **Header Authentication Validation:**
     - **SPF (Sender Policy Framework):** Verifies if the sending IP is authorized for the domain.
     - **DKIM (DomainKeys Identified Mail):** Validates cryptographic email integrity.
     - **DMARC:** Enforces domain alignment policies (`reject`, `quarantine`, `none`).
  2. **NLP Cognitive Urgency Modeling:** Identifies psychological coercion tactics (*"Account suspended within 2 hours"*, *"Urgent wire transfer required"*).
  3. **Attachment Container Inspection:** Flags weaponized attachments (`.iso`, `.exe`, `.vbs`, `.xlsm`).
  4. **Preset Threat Vectors:** Evaluators can detonate realistic pre-loaded scenarios (CEO Wire Fraud BEC, DHL ISO Trojan Container, PayPal Harvester).

---

### 5. SMS, WhatsApp & Social Engineering Analyzer
- **Files:** `src/pages/MessageAnalyzerPage.tsx`, `src/services/threatEngine.ts`
- **Working Principle:** Protects mobile and remote workforces against Smishing and conversational scams.
- **Workflow:**
  1. **Tokenized Manipulation Detection:** Scans text for high-risk coercion tokens (e.g., `"₹50,000 lottery"`, `"Electricity disconnection"`, `"KYC update required"`).
  2. **Correlated VirusTotal Link Scanning:** Automatically extracts embedded shortlinks (`bit.ly`, `tinyurl.com`, `t.co`) and detonates them against live VirusTotal intelligence.
  3. **Safety Playbook Recommendations:** Generates clear, non-technical guidance for everyday users.

---

### 6. Deepfake & Synthetic AI Image Forensics
- **Files:** `src/pages/MediaAnalyzerPage.tsx`, `src/services/deepfakeApiService.ts`
- **Working Principle:** Distinguishes authentic optical sensor photos from synthetic images generated by Midjourney, DALL-E, Stable Diffusion, and GANs.
- **Workflow:**
  1. **Bayer Sensor Pattern Analysis:** Physical cameras produce photon shot noise adhering to Bayer color filter arrays; generative models produce smoothed, mathematical pixel distributions.
  2. **Fourier Spectral Frequency Grid:** Detects frequency grid artifacts unique to latent diffusion de-noising steps.
  3. **Google Gemini Vision 2.0 Consensus:** Sends image data to Gemini Vision with forensic reasoning prompts (`queryGeminiVisionDeepfakeDetector`) to evaluate iris reflections, subsurface skin scattering, and background perspective desynchronization.

---

### 7. Network Traffic & C2 Beaconing Analyzer
- **Files:** `src/pages/NetworkAnalyzerPage.tsx`, `src/services/networkApiService.ts`
- **Working Principle:** Monitors internal NetFlow traffic to detect active malware infections, data exfiltration, and botnet command-and-control communication.
- **Workflow:**
  1. **NetFlow Burst Telemetry:** Detects abnormal traffic multipliers (>30x baseline connection volume).
  2. **C2 Jitter Beaconing Detection:** Identifies regular outbound requests occurring at fixed intervals (e.g., every 60s matching Cobalt Strike beaconing profiles).
  3. **AbuseIPDB v2 Reputation Query:** Validates destination IPs against global blacklists, retrieving abuse confidence percentages and reported threat categories.

---

### 8. Malicious File & Shannon Entropy Forensic Engine
- **Files:** `src/pages/FileAnalyzerPage.tsx`, `src/services/threatEngine.ts`
- **Working Principle:** Static binary analysis and structural inspection without executing suspicious code on the host machine.
- **Workflow:**
  1. **Cryptographic Hashing:** Computes `MD5`, `SHA-1`, and `SHA-256` hashes in milliseconds.
  2. **Shannon Byte Entropy Scanner:** Calculates bitwise entropy ($H(X) = -\sum P(x) \log_2 P(x)$):
     - Values `> 7.2 / 8.0` indicate high cryptographic packing, compression, or encryption typical of ransomware and obfuscated loaders.
  3. **PE/ELF Header & Macro Forensics:** Inspects file magic bytes and flags dangerous embedded macros (`AutoOpen()`, `WScript.Shell`, PowerShell execution strings).

---

### 9. CyberGuard AI SOC Copilot
- **Files:** `src/components/copilot/CyberCopilotDrawer.tsx`, `src/services/copilotService.ts`
- **Working Principle:** An embedded AI security assistant that reasons through live SOC telemetry using Google Gemini API models (`gemini-flash-lite-latest`, `gemini-flash-latest`).
- **Capabilities:**
  - Contextual awareness: Ingests currently active threats and telemetry automatically.
  - One-click analyst prompts: `[Explain Critical Threats]`, `[Analyze Current Incident]`, `[Recommend Containment Steps]`.
  - Explains CVE vulnerabilities, MITRE techniques, and forensic indicators in plain language.

---

### 10. Live Attack Simulation Engine
- **Files:** `src/components/simulation/AttackSimulationModal.tsx`, `src/data/attackScenarios.ts`
- **Working Principle:** Provides a dynamic, multi-step cyber warfare simulator allowing hackathon judges to witness a complete attack lifecycle from infiltration to containment.
- **Scenarios:**
  - `Zero-Day Phishing Detonation (Homoglyph Attack)`
  - `Executive Wire Fraud BEC Campaign`
  - `APT-37 Botnet C2 Beaconing & Lateral Spikes`
- **Feedback:** Real-time step progression, live terminal output, automated SOAR neutralization, and celebratory confetti upon threat resolution.

---

## 💻 Complete Technology Stack & Architecture Decisions

```
Frontend Architecture:
├── React 19.2 (Concurrent Rendering & High Performance State)
├── TypeScript 5.x / 6.x (Strict Type Safety & Zero Runtime Type Errors)
├── Vite 8.x (Lightning Fast HMR Build Tool & Production Bundler)
├── Tailwind CSS 3.4 (Aerospace Cyberpunk Dark Theme & Custom Glassmorphism)
├── Recharts 3.10 (Real-time Telemetry Graphs & Scaled Bar Visualizations)
├── Lucide React (Clean Cyber Security & Network Icons)
└── Canvas Confetti (Instant Celebratory Feedback on Threat Containment)

Intelligence APIs & Protocols:
├── VirusTotal REST API v3 (70+ Multi-Engine Antivirus Aggregation)
├── AbuseIPDB REST API v2 (IP Reputation & C2 Blacklist Telemetry)
├── Google Gemini 2.0 API (Multimodal AI Vision & SOC Copilot Reasoning)
└── Cloudflare DNS-over-HTTPS (Tamper-Proof DoH DNS Resolution)

Infrastructure & Hosting:
├── Netlify Edge Serverless (Global CDN & Automated Continuous Deployment)
├── Netlify Reverse Proxies (CORS-Bypass for VirusTotal & Threat APIs)
└── Strict Security Headers (X-Frame-Options, X-Content-Type-Options: nosniff)
```

### Architectural Decisions:
1. **Client-Side First Processing:** All text tokenization, header parsing, and heuristic analysis occurs directly in the browser's JavaScript engine. Zero user emails or private chat messages are saved to any external database, ensuring compliance with **GDPR and HIPAA** privacy standards.
2. **Deterministic-First AI Pipeline:** Expensive LLMs are not called blindly for routine classification. Fast heuristic filters and threat intelligence APIs execute first in under 50ms; AI models are reserved strictly for deep multimodal vision and contextual reasoning.
3. **Dual-Mode Offline Resilience:** Built with realistic mock engines and local heuristics. If external API keys expire or network connectivity drops during a live hackathon presentation, the platform seamlessly falls back to offline evaluation without error.

---

## 🌐 External APIs, Protocols & Data Contracts

### 1. VirusTotal REST API v3
- **Endpoint:** `https://www.virustotal.com/api/v3/urls`
- **Data Contract:**
  ```typescript
  // 1. Sanitize & base64-encode URL without padding
  const urlId = btoa(cleanUrl).replace(/=/g, '');

  // 2. Fetch URL report with API key
  GET /api/virustotal/urls/{urlId}
  Headers: { 'x-apikey': '<VITE_VIRUSTOTAL_API_KEY>' }
  ```
- **Aggregation:** Collects analysis statistics across 70+ vendors (`malicious`, `suspicious`, `harmless`, `undetected`). If `malicious + suspicious > 0`, the threat escalates to **CRITICAL**.
- **CORS Proxy:** Handled seamlessly via Netlify/Vite proxy rewriting `/api/virustotal/*` to `https://www.virustotal.com/api/v3/*`.

### 2. AbuseIPDB REST API v2
- **Endpoint:** `https://api.abuseipdb.com/api/v2/check`
- **Function:** Queries IP reputation scores (`abuseConfidenceScore`: 0–100%), ISP ownership, and reported malicious activities.

### 3. Google Gemini 2.0 Vision & Language API
- **Endpoints:** `/v1beta/models/gemini-flash-latest:generateContent`, `/v1beta/models/gemini-2.0-flash:generateContent`
- **Function:** Analyzes multimodal image inputs for generative deepfake artifacts and powers the interactive SOC Copilot conversational reasoning.

### 4. Cloudflare DNS-over-HTTPS (DoH)
- **Endpoint:** `https://cloudflare-dns.com/dns-query?name={domain}&type=A`
- **Function:** Performs encrypted DNS queries to verify domain existence, identify host infrastructure, and detect fast-flux DNS evasion.

---

## 🏆 Competitive Differentiation & Why Threat Lens AI Wins

| Capability | Threat Lens AI | Traditional SEGs (Proofpoint / Mimecast) | Traditional Antivirus (Norton / Defender) | Typical Hackathon Project |
| :--- | :---: | :---: | :---: | :---: |
| **Multi-Vector Defense** | **6+ Vectors Unified** | Email Only | Files & Binaries Only | Single Isolated Feature |
| **Explainable AI (XAI)** | ✅ **Mathematical Factor Weights** | ❌ Opaque Black Box | ❌ Signature Match Only | ❌ Hallucinating LLM |
| **Interactive Defense Mesh** | ✅ **SENTINEL-9 Radar & Nodes** | ❌ None | ❌ None | ❌ Static Dummy Table |
| **Real-time SOAR Playbooks** | ✅ **One-Click Edge Containment** | Requires Add-on License | ❌ Local Quarantine Only | ❌ None |
| **Live Attack Simulator** | ✅ **Interactive Scenarios** | ❌ Complex Enterprise Setup | ❌ Requires Real Malware | ❌ Hardcoded Text |
| **User Privacy** | ✅ **100% Client-Side Ingestion** | Cloud Inspection | Local Scan Only | ❌ Sends inbox to OpenAI |
| **Zero Deployment Lag** | ✅ **Instant Web App on Netlify** | Months of MX Record Setup | Desktop Software Install | Broken Terminal Script |

---

## 🎤 Hackathon Pitch Guide & 3-Minute Judge Demo Script

### ⏱️ Minute 0:00 – 0:45: The Hook & Problem
> *"Good morning judges! Over 90% of all modern cyber breaches start with social engineering, phishing, and identity impersonation—costing the global economy over $10 Trillion. But current solutions have a fatal flaw: enterprise tools are expensive and cause severe alert fatigue, while everyday consumers have no defense at all.*  
> *Meet **THREAT LENS AI**: an autonomous, multi-vector SOC platform that unifies threat detection, explainable AI, and automated SOAR containment into an accessible, high-speed interface."*

### ⏱️ Minute 0:45 – 1:45: Live Threat Interception Demo
> *(Action: Click **RUN LIVE THREAT DEMO** on the Landing Page)*  
> *"Let's watch a zero-day attack unfold in real time. An adversary launches a homoglyph phishing campaign targeting enterprise SSO:*  
> *1. Threat Lens AI detects domain typosquatting (`paypa1-support.com`) in milliseconds.*  
> *2. It detonates the URL against VirusTotal across 70+ antivirus engines.*  
> *3. Our Explainable AI engine calculates a 94/100 Critical Risk Score, decomposing the exact factor weights.*  
> *4. In the SOC Command Center, our SENTINEL-9 Threat Interceptor visualizes the attack vector arriving on our Frankfurt node and executes automated edge containment—null-routing the IP and sinkholing the domain in 0.04s."*

### ⏱️ Minute 1:45 – 2:30: Multi-Modal Defense & Deepfake Forensics
> *(Action: Navigate to **Deepfake & AI Media Scanner** or **Network Threat Radar** via the sidebar)*  
> *"Beyond email and URLs, modern defense requires multi-modal capability. Threat Lens AI inspects synthetic AI imagery, smishing, and weaponized binaries:*  
> *1. In our Deepfake Scanner, we evaluate Bayer sensor noise, Fourier spectral frequencies, and Gemini Vision models to detect AI-generated executive avatars.*  
> *2. In our File Analyzer, we compute Shannon Entropy to detect packed and encrypted ransomware before execution.*  
> *3. And our embedded CYBERGUARD AI Copilot allows any analyst to ask questions in plain English and receive instant containment recommendations."*

### ⏱️ Minute 2:30 – 3:00: Closing & Technical Feasibility
> *"Threat Lens AI is live today on Netlify, built on React 19 and TypeScript, privacy-first, fully type-safe, and ready to protect organizations of any size. Thank you, and we welcome your questions!"*

---

## 🛠️ Installation, Local Development & Netlify Deployment

### Prerequisites
- **Node.js**: Version `20.x` or higher
- **Package Manager**: `npm` (v10+)
- **Modern Browser**: Chrome, Edge, Brave, or Firefox

### 1. Clone & Install
```bash
# Clone the repository
git clone https://github.com/your-username/threat-lens-ai.git

# Navigate into the project directory
cd "SARU Copy"

# Install dependencies
npm install
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory:
```env
# VirusTotal v3 REST API Key
VITE_VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Optional: Google Gemini API Key for Copilot & Vision
VITE_GEMINI_API_KEY=your_gemini_api_key_here
```

### 3. Run Development Server
```bash
npm run dev
```
Open your browser at `http://localhost:5173/` or `http://localhost:5174/`.

### 4. Build for Production
```bash
npm run build
```
Generates an optimized, minified production build in the `dist/` directory.

### 5. Deploy to Netlify
Configured out of the box via `netlify.toml`:
- **Build Command:** `npm run build`
- **Publish Directory:** `dist`
- **Node Version:** `20`
- **Reverse Proxies:** Automatically redirects `/api/virustotal/*` to bypass browser CORS.

---

## 👥 Contributors & License
- **Built with ❤️ for National Cybersecurity Hackathons.**
- **Threat Intelligence Feeds:** Powered by VirusTotal, AbuseIPDB, Cloudflare DoH, and Google Gemini API.
- **License:** Open-source under the [MIT License](LICENSE).
