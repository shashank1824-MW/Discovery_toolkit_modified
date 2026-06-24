# Discovery Toolkit — Backend

![Python](https://img.shields.io/badge/python-3.12-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.128-green?logo=fastapi)
![AWS](https://img.shields.io/badge/AWS-deployed-orange?logo=amazon-aws)
![Docker](https://img.shields.io/badge/-docker-2496ED?logo=docker)
![K8s](https://img.shields.io/badge/Kubernetes-ready-326CE5?logo=kubernetes)

The backend service for the **Discovery Toolkit**. It exposes a REST API for authentication, file conversion (CSV/JSON/XLSX), HAR file analysis, and Discovery data retrieval/enrichment — backed by a SQLite auth store and AWS integrations.

## Features

- 🔐 JWT-based authentication
- 📄 File converter (CSV, JSON, XLSX)
- 🔍 HAR file analyzer
- 🌐 Discovery data fetcher with enrichment pipelines
- ☁️ AWS Amplify monitoring & S3 storage integration
- 🐳 Docker, Railway, and Kubernetes deployment configs included

## Tech Stack

| Layer | Tools |
|---|---|
| Runtime | Python 3.12 |
| Framework | FastAPI, Starlette, Uvicorn |
| Data | Pandas, NumPy, OpenPyXL, clevercsv |
| Auth | PyJWT |
| Cloud | boto3 / AWS App Runner |
| Config | pydantic, python-dotenv |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
uvicorn main:app --reload --port 8000
```

## Deploy

| Platform | Command / Config |
|---|---|
| Railway | `railway up` (see `railway.toml`) |
| AWS App Runner | `apprunner.yaml` |
| Kubernetes | `kubectl apply -f kubernetes/` |
| Docker | `docker build -t discovery-backend . && docker run -p 8000:8000 discovery-backend` |

## Project Structure

```
backend/
├── main.py
├── routers/
│   ├── auth.py
│   ├── converter.py
│   ├── discovery.py
│   └── har_analyzer.py
├── utils/
│   ├── data_quality.py
│   └── enrichment.py
├── data/
│   └── auth.db
├── kubernetes/
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── Procfile
└── apprunner.yaml
```

## License

Internal — Meltwater
