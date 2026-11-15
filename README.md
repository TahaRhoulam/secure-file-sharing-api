# Secure File Sharing API

A REST API for authenticated file storage and time-limited sharing, built with **Python**, **FastAPI**, and **SQLite**.

## Features

- Account registration and login with password hashing (scrypt)
- Bearer-token authentication for private endpoints
- File upload, listing, download, and deletion
- Owner-based access controls
- Time-limited share links
- Upload size limit (2 MiB) and input validation
- Interactive OpenAPI documentation
- Automated API tests with Pytest

## Tech stack

- Python 3.12+
- FastAPI and Uvicorn
- SQLite
- Pytest and HTTPX
- Docker

## Getting started

### 1. Install dependencies

```bash
python -m venv .venv
```

Activate the virtual environment:

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
source .venv/bin/activate
```

Then install dependencies:

```bash
pip install -r requirements.txt
```

### 2. Run the API

```bash
uvicorn app.main:app --reload
```

Open the interactive API documentation at **http://127.0.0.1:8000/docs**.

### 3. Run tests

```bash
python -m pytest -q
```

## Docker

```bash
docker build -t secure-file-sharing-api .
docker run --rm -p 8000:8000 secure-file-sharing-api
```

The container uses local SQLite storage; use a persistent volume and an appropriate database path if you need data to survive container replacement.

## API endpoints

| Method | Endpoint | Purpose | Authentication |
|---|---|---|---|
| `POST` | `/register` | Create a user account | No |
| `POST` | `/login` | Receive a bearer token | No |
| `POST` | `/files` | Upload a file | Yes |
| `GET` | `/files` | List your files | Yes |
| `GET` | `/files/{file_id}` | Download a file you own | Yes |
| `POST` | `/files/{file_id}/share` | Generate an expiring share link | Yes |
| `GET` | `/shared/{token}` | Download via a valid share link | No |
| `DELETE` | `/files/{file_id}` | Delete a file you own | Yes |

To authenticate, send the token returned by `/login` in the header:

```http
Authorization: Bearer <access_token>
```

## How it works

- **Authentication:** Passwords are salted and hashed using `hashlib.scrypt`. Random bearer tokens are generated on login; only their SHA-256 hashes are stored in the database.
- **Authorization:** Private file endpoints check ownership against the authenticated user ID.
- **Sharing:** A share token grants temporary access to one file until its expiry time. Only the token hash is stored.
- **Storage:** Files and metadata are stored in SQLite. Database queries use parameters rather than string interpolation.

## Security considerations

This implementation is intended for local development and demonstration, **not deployment with sensitive files**. Before using it in production, additional safeguards would be needed, including HTTPS, session expiration and revocation, rate limiting, malware scanning, more robust file storage, monitoring, and a security review.

## Possible next steps

- Add logout and session expiration
- Add login rate limiting
- Expand test coverage for expired links and edge cases
- Add continuous integration with GitHub Actions
- Document a threat model and deployment architecture
