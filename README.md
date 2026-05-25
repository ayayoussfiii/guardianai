
<div align="center">

```
 ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗ █████╗ ██╗
██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║██╔══██╗██║
██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║███████║██║
██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║██╔══██║██║
╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║██║  ██║██║
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
```

**AI Security Proxy — Shield for Local LLMs**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Ollama](https://img.shields.io/badge/Ollama-local%20LLM-black?style=flat-square)](https://ollama.ai)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)](https://github.com/ayayoussfiii/guardianai/actions)

*An intelligent security layer that intercepts, analyzes, and filters requests to local LLMs — stopping prompt injections, jailbreaks, and multi-turn attacks before they reach your model.*

</div>

---

## Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Team & Responsibilities](#-team--responsibilities)
- [Getting Started](#-getting-started)
- [API Reference](#-api-reference)
- [Security Pipeline](#-security-pipeline)
- [Configuration](#-configuration)
- [Testing](#-testing)
- [Roadmap](#-roadmap)

---

## 🧭 Overview

GuardianAI is a **security proxy** that sits between your application and a local LLM (Ollama). Every request passes through a multi-layer analysis pipeline before reaching the model — detecting and blocking malicious inputs in real time.

### Why GuardianAI?

| Problem | GuardianAI Solution |
|---|---|
| Prompt injection attacks | Pattern-based scanner with 12+ regex rules |
| Jailbreak attempts (DAN, roleplay...) | Signature detection + session context |
| Multi-turn progressive attacks | Stateful session tracking across messages |
| Dirty / malformed inputs | Automatic sanitization and normalization |
| LLM exposure to raw user input | Full proxy abstraction layer |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT APPLICATION                        │
└─────────────────────┬───────────────────────────────────────────┘
                      │  POST /api/chat
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                     GUARDIANAI PROXY (Port 8000)                 │
│                                                                   │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│   │   SCANNER   │──▶│  DETECTOR   │──▶│       FILTER        │   │
│   │             │   │             │   │                     │   │
│   │ Regex rules │   │ Session ctx │   │ Sanitize & clean    │   │
│   │ Signatures  │   │ Multi-turn  │   │ Normalize input     │   │
│   └──────┬──────┘   └──────┬──────┘   └──────────┬──────────┘   │
│          │ blocked?        │ blocked?             │              │
│          ▼                 ▼                      ▼              │
│     ┌─────────┐       ┌─────────┐         ┌────────────┐        │
│     │ BLOCKED │       │ BLOCKED │         │ FORWARDED  │        │
│     │ 🚫 403  │       │ 🚫 403  │         │ to Ollama  │        │
│     └─────────┘       └─────────┘         └─────┬──────┘        │
└───────────────────────────────────────────────── │ ─────────────┘
                                                   │
                      ┌────────────────────────────▼───────────────┐
                      │            OLLAMA (Local LLM)               │
                      │         llama3 / mistral / gemma            │
                      └─────────────────────────────────────────────┘
```

> **Profil B** (AI Engine) plugs into the `Detector` layer via the shared JSON contract to add semantic threat classification.

---

## 📁 Project Structure

```
guardianai/
│
├── 📄 docker-compose.yml          # Orchestration complète (proxy + ollama)
├── 📄 .env.example                # Variables d'environnement à configurer
├── 📄 .gitignore
├── 📄 README.md
│
├── 📁 .github/
│   └── 📁 workflows/
│       └── ci.yml                 # Pipeline CI : lint, tests, build
│
├── 📁 backend/                    # ← Profil A
│   ├── 📄 requirements.txt
│   │
│   ├── 📁 api/
│   │   ├── main.py                # Point d'entrée FastAPI (port 8000)
│   │   ├── routes.py              # Endpoints REST
│   │   └── __init__.py
│   │
│   ├── 📁 middleware/
│   │   ├── scanner.py             # Détection par patterns (regex)
│   │   ├── detector.py            # Suivi de session & attaques multi-tours
│   │   ├── filter.py              # Sanitisation du prompt
│   │   └── __init__.py
│   │
│   └── 📁 tests/
│       ├── test_api.py            # Tests endpoints REST
│       ├── test_scanner.py        # Tests unitaires middleware
│       └── __init__.py
│
├── 📁 dashboard/                  # ← Interface de monitoring
│   ├── package.json
│   └── 📁 src/
│       └── App.jsx
│
└── 📁 sdk/                        # ← Client libraries
    ├── 📁 node/
    │   └── guardianai.js
    └── 📁 python/
        └── guardianai.py
```

---

## 👥 Team & Responsibilities

### 👤 Profil A — Lead Backend & Core Proxy

> **Mission** : Intercepter le trafic, garantir la haute performance et gérer les communications externes.

| Module | Fichier | Rôle |
|---|---|---|
| **Proxy Server** | `api/main.py` | Serveur FastAPI, CORS, routing |
| **REST API** | `api/routes.py` | Endpoints `/chat`, `/models`, `/sessions` |
| **Scanner** | `middleware/scanner.py` | Détection patterns malveillants (12+ règles) |
| **Filter** | `middleware/filter.py` | Sanitisation HTML, control chars, normalisation |
| **Detector** | `middleware/detector.py` | Tracking sessions, attaques multi-tours |
| **Tests** | `tests/` | Couverture unitaire et d'intégration |

### 👤 Profil B — Lead IA, Data & DevOps

> **Mission** : Détecter les menaces sémantiques et assurer la scalabilité du bouclier.

| Module | Rôle |
|---|---|
| **AI Engine** | Modèles ONNX/TensorRT pour classifier les intentions |
| **Vector Pipeline** | Embeddings + Qdrant/ChromaDB pour similarité d'attaques |
| **Orchestration** | LangChain pour chaîner les vérifications de sécurité |
| **DevOps** | Docker, Kubernetes, Prometheus/Grafana |

### 🤝 Shared Contract

Both profiles communicate via a **strict JSON API contract** defined at `middleware/detector.py`:

```json
{
  "prompt": "string",
  "session_id": "string | null",
  "scan_result": {
    "flagged": "boolean",
    "reason": "string | null"
  },
  "detection_result": {
    "malicious": "boolean",
    "reason": "string | null"
  }
}
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.ai) installed and running
- Docker (optional)

### 1. Clone the repository

```bash
git clone https://github.com/ayayoussfiii/guardianai.git
cd guardianai
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and set your OLLAMA_URL
```

### 3. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 4. Pull a model in Ollama

```bash
ollama pull llama3
```

### 5. Start the proxy

```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 6. Or use Docker

```bash
docker-compose up --build
```

The proxy is now live at **http://localhost:8000**
Interactive docs at **http://localhost:8000/docs**

---

## 📡 API Reference

### `POST /api/chat`

Send a prompt through the security pipeline to Ollama.

**Request**
```json
{
  "model": "llama3",
  "prompt": "Explain how neural networks work",
  "stream": false,
  "session_id": "user-abc-123"
}
```

**Response — Safe prompt**
```json
{
  "response": "Neural networks are...",
  "blocked": false,
  "reason": null
}
```

**Response — Blocked prompt**
```json
{
  "response": "",
  "blocked": true,
  "reason": "Prompt injection détectée"
}
```

---

### `GET /api/models`

List available models on the connected Ollama instance.

```bash
curl http://localhost:8000/api/models
```

---

### `GET /api/sessions/{session_id}`

Retrieve session context and security flags.

```json
{
  "session_id": "user-abc-123",
  "message_count": 5,
  "flag_count": 1,
  "flags": ["Escalade détectée : tentative de jailbreak multi-tours"],
  "created_at": 1716800000.0,
  "last_seen": 1716803600.0
}
```

---

### `DELETE /api/sessions/{session_id}`

Clear a session from memory.

---

### `GET /health`

Health check endpoint.

```json
{ "status": "ok", "service": "GuardianAI Proxy" }
```

---

## 🛡 Security Pipeline

Every request goes through **3 sequential layers** before reaching Ollama:

```
Request
   │
   ▼
┌──────────────────────────────────────────┐
│  LAYER 1 — SCANNER                        │
│  • 12+ regex patterns                     │
│  • Prompt injection detection             │
│  • Jailbreak signatures (DAN, roleplay)   │
│  • System extraction attempts             │
│  • Token injection (|system|, [INST])     │
│  • Max length enforcement (4000 chars)    │
└──────────────────┬───────────────────────┘
                   │ PASS
                   ▼
┌──────────────────────────────────────────┐
│  LAYER 2 — DETECTOR                       │
│  • Session tracking (TTL: 1h)            │
│  • Multi-turn escalation analysis        │
│  • Auto-block after 3 flags/session      │
│  • Memory-safe (max 10,000 sessions)     │
│  • Plug-in point for Profil B AI engine  │
└──────────────────┬───────────────────────┘
                   │ PASS
                   ▼
┌──────────────────────────────────────────┐
│  LAYER 3 — FILTER                         │
│  • HTML/XML tag removal                  │
│  • Control character stripping           │
│  • ANSI escape sequence removal          │
│  • Whitespace normalization              │
│  • HTML entity decoding                  │
└──────────────────┬───────────────────────┘
                   │ CLEAN PROMPT
                   ▼
              OLLAMA LLM
```

---

## ⚙️ Configuration

All configuration is done via environment variables in `.env`:

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `MAX_PROMPT_LENGTH` | `4000` | Maximum characters per prompt |
| `SESSION_TTL` | `3600` | Session lifetime in seconds |
| `MAX_SESSIONS` | `10000` | Max concurrent sessions in memory |
| `MAX_FLAGS_PER_SESSION` | `3` | Flags before session is blocked |

---

## 🧪 Testing

Run the full test suite:

```bash
cd backend
pip install pytest pytest-asyncio
pytest tests/ -v
```

Expected output:

```
tests/test_api.py::test_health                          PASSED
tests/test_api.py::test_chat_blocked_injection          PASSED
tests/test_api.py::test_chat_blocked_jailbreak          PASSED
tests/test_api.py::test_chat_clean_prompt               PASSED
tests/test_api.py::test_session_not_found               PASSED
tests/test_scanner.py::test_scanner_clean               PASSED
tests/test_scanner.py::test_scanner_injection           PASSED
tests/test_scanner.py::test_scanner_jailbreak_dan       PASSED
tests/test_scanner.py::test_scanner_system_extraction   PASSED
tests/test_scanner.py::test_scanner_too_long            PASSED
tests/test_scanner.py::test_scanner_token_injection     PASSED
tests/test_scanner.py::test_filter_removes_html         PASSED
tests/test_scanner.py::test_filter_normalizes_spaces    PASSED
tests/test_scanner.py::test_detector_clean              PASSED
tests/test_scanner.py::test_detector_session_created    PASSED

15 passed in 0.87s ✅
```

---

## 🗺 Roadmap

- [x] Core proxy with FastAPI
- [x] Scanner — regex-based threat detection
- [x] Filter — prompt sanitization
- [x] Detector — session tracking & multi-turn detection
- [x] REST API with full CRUD on sessions
- [x] Unit & integration test suite
- [ ] Profil B — Semantic AI engine (ONNX/TensorRT)
- [ ] Profil B — Vector similarity search (Qdrant)
- [ ] Redis cache layer for known attack signatures
- [ ] Rate limiting per session/IP
- [ ] Dashboard monitoring (React + Grafana)
- [ ] SDK — Python & Node.js client libraries
- [ ] Kubernetes deployment manifests

---


<div align="center">

*Built with precision. Deployed with confidence.*

**[Documentation](https://github.com/ayayoussfiii/guardianai) · [Issues](https://github.com/ayayoussfiii/guardianai/issues) · [Pull Requests](https://github.com/ayayoussfiii/guardianai/pulls)**

</div>
