# SecScan

SecScan checks the dependencies of a Python project for known security vulnerabilities. Upload a `requirements.txt` file and SecScan tells you which packages have known vulnerabilities (CVEs) and how severe they are.

> 🚧 Work in progress – this project is under active development.

## Why?

Almost every software project depends on third-party libraries. Older versions of these libraries often contain known security vulnerabilities. SecScan makes it easy to see at a glance whether a project uses vulnerable package versions.

## Features

- Upload a `requirements.txt` file via a REST API
- Parse package names and pinned versions (`package==version`)
- Look up known vulnerabilities for each package in the [OSV.dev](https://osv.dev) database
- Show the CVE ID, severity and a short summary for each vulnerability
- Remove duplicates when the same vulnerability is reported by multiple sources (e.g. GitHub and PyPA)
- Skip comments and report unpinned packages (e.g. `django` or `requests>=2.25.0`) instead of silently ignoring them
- Recommend the lowest version that fixes all known vulnerabilities

## Example

Input (`test-requirements.txt`):

```
flask==2.0.1
flask==3.1.3
```

Output (shortened):

```json
{
  "filename": "test-requirements.txt",
  "packages": [
    {
      "name": "flask",
      "version": "2.0.1",
      "vulnerabilities": [
        {
          "cve": "CVE-2023-30861",
          "severity": "HIGH",
          "summary": "Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header"
        }
      ]
    },
    {
      "name": "flask",
      "version": "3.1.3",
      "vulnerabilities": []
    }
  ],
  "skipped": []
}
```

## Tech Stack

- Python 3.12
- [FastAPI](https://fastapi.tiangolo.com) – web framework for the REST API
- [httpx](https://www.python-httpx.org) – HTTP client for querying OSV.dev
- [OSV.dev API](https://osv.dev) – open vulnerability database

## Installation

```bash
git clone https://github.com/mertblr/secscan.git
cd secscan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Start the server:

```bash
fastapi dev main.py
```

Then either:

- open http://127.0.0.1:8000/docs in your browser and upload a file to the `POST /scan` endpoint, or
- use `curl`:

```bash
curl -F "file=@test-requirements.txt" http://127.0.0.1:8000/scan
```

## Roadmap

- [x] Scan `requirements.txt` for known vulnerabilities
- [x] Show the version that fixes each vulnerability
- [ ] Website security header and TLS check
- [ ] AI-generated explanations and fix suggestions
- [ ] Simple web frontend
- [ ] Docker, automated tests and CI/CD (GitHub Actions)
- [ ] Deployment
