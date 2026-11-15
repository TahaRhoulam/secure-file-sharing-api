# Secure File Sharing API (Python)

A learning-oriented REST API built with FastAPI and SQLite. Features registration, login, private uploads, owner-only downloads, time-limited sharing links, and automated tests.

> **Portfolio integrity:** This starter project was generated with AI assistance. Review, run, understand, improve, and test it yourself before presenting it as independently developed work. Do not publish the CV project entry as a completed personal achievement until you have done that work.

## Run locally

```bash
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs for the interactive API documentation.

## Run tests

```bash
python -m pytest -q
```

## API routes

| Method | Route | Description |
|---|---|---|
| POST | `/register` | Create account |
| POST | `/login` | Get bearer token |
| POST | `/files` | Upload private file (2 MiB limit) |
| GET | `/files` | List your files |
| GET | `/files/{id}` | Download your file |
| POST | `/files/{id}/share` | Create expiring link |
| GET | `/shared/{token}` | Download via link |
| DELETE | `/files/{id}` | Delete your file |

## Security notes and limitations

This is a **learning project**, not production-ready. Passwords use salted scrypt; bearer tokens and sharing tokens are randomly generated and stored as SHA-256 hashes. SQL statements are parameterized. Downloads force attachment behavior. Real deployments also need HTTPS, token expiry/revocation, rate limiting, malware scanning, external object storage, operational monitoring, and threat modeling. Files are stored in SQLite for simplicity. Do not upload sensitive personal files.

## Next improvements to make yourself

1. Implement session expiration and logout.
2. Add rate limiting to login.
3. Add tests for expired links and path traversal filenames.
4. Add GitHub Actions CI and deploy a demo.
5. Document a threat model and explain design trade-offs.
