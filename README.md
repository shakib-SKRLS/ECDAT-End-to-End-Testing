# ECDAT - Enterprise Cryptographic Discovery & Analysis Tool

A production-quality platform for discovering cryptographic usage across enterprise software/infrastructure, generating Cryptographic Bills of Materials (CBOM), assessing cryptographic and quantum risk, and providing actionable post-quantum cryptography (PQC) migration recommendations.

## Architecture

```
ecd-at/
├── frontend/          # Next.js + TypeScript + Tailwind CSS
├── backend/           # FastAPI + Python + SQLAlchemy
├── scanner/           # Cryptographic detection engine
├── fixtures/          # Test repositories
├── tests/             # Unit, integration, and E2E tests
├── docs/              # Documentation
└── docker-compose.yml # Orchestration
```

## Features

- **Cryptographic Discovery**: Detects algorithms, libraries, protocols, certificates across multiple languages
- **CBOM Generation**: Structured Cryptographic Bill of Materials
- **Risk Assessment**: Classical and quantum risk scoring with Mosca-style urgency analysis
- **PQC Recommendations**: Deterministic migration guidance based on NIST standards
- **Interactive Dashboard**: SOC-style visualization of findings and risks
- **Multi-language Support**: Python, JavaScript, TypeScript, Java, C, C++, Go

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker (optional, for containerized deployment)

### Local Development

1. **Clone and setup**:
```bash
git clone <repo-url>
cd sih-c
```

2. **Backend setup**:
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

3. **Frontend setup**:
```bash
cd frontend
npm install
```

4. **Environment configuration**:
```bash
cp .env.example .env
# Edit .env with your settings
```

5. **Run backend**:
```bash
cd backend
python main.py
```

Backend will be available at `http://localhost:8000`

6. **Run frontend** (in another terminal):
```bash
cd frontend
npm run dev
```

Frontend will be available at `http://localhost:3000`

### Docker Deployment

```bash
docker compose up --build
```

Access:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## Scanner Usage

### CLI

```bash
python -m scanner scan ./sample-project
python -m scanner scan ./sample-project --output cbom.json
python -m scanner scan ./sample-project --format json
```

### API

```bash
# Create project
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "My Project", "description": "Test project"}'

# Start scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"project_id": "<project-id>", "source_type": "local_dir", "source_location": "./sample-project"}'
```

## API Endpoints

### Projects
- `POST /api/projects` - Create project
- `GET /api/projects` - List projects
- `GET /api/projects/{id}` - Get project details
- `DELETE /api/projects/{id}` - Delete project

### Scans
- `POST /api/scans` - Start scan
- `GET /api/scans` - List scans
- `GET /api/scans/{id}` - Get scan details
- `GET /api/scans/{id}/status` - Get scan status

### Assets
- `GET /api/assets` - List crypto assets
- `GET /api/assets/{id}` - Get asset details

### Findings
- `GET /api/findings` - List findings
- `GET /api/findings/{id}` - Get finding details
- `PATCH /api/findings/{id}` - Update finding status

### Risk
- `GET /api/risk/project/{project_id}` - Get risk assessment

### Recommendations
- `GET /api/recommendations/project/{project_id}` - Get recommendations
- `GET /api/recommendations/project/{project_id}/roadmap` - Get migration roadmap

## Testing

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test

# E2E tests (with Playwright)
npx playwright test
```

## Documentation

- [Architecture](docs/architecture.md)
- [Scanner](docs/scanner.md)
- [Risk Model](docs/risk-model.md)
- [CBOM](docs/cbom.md)
- [PQC Migration](docs/pqc-migration.md)
- [Testing](docs/testing.md)

## Security Considerations

- Private key material is never stored in the database
- Only metadata (key type, size, location) is reported
- Scanning happens in controlled environments
- Path traversal and command injection protections
- No execution of arbitrary code from scanned repositories

## Limitations

- Quantum threat horizon is a configurable planning assumption, not a prediction
- Recommendations are investigation starting points, not drop-in replacements
- Scanner uses static analysis; runtime behavior not captured
- Certificate parsing requires OpenSSL CLI where available

## License

See LICENSE file.
