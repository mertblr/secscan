import httpx
from fastapi import FastAPI, UploadFile

OSV_URL = "https://api.osv.dev/v1/query"

app = FastAPI()


async def query_osv(name, version):
    payload = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    async with httpx.AsyncClient() as client:
        response = await client.post(OSV_URL, json=payload)
    data = response.json()
    return data.get("vulns", [])

def extract_info(vuln):
    cve = vuln["id"]
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve = alias

    severity = vuln.get("database_specific", {}).get("severity", "UNKNOWN")
    summary = vuln.get("summary", "")

    fixed_versions = []
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            for event in r.get("events", []):
                if "fixed" in event:
                    fixed_versions.append(event["fixed"])

    return {"cve": cve, "severity": severity, "summary": summary, "fixed_in": fixed_versions}



@app.get("/")
def root():
    return {"message": "SecScan läuft"}


@app.get("/health")
def check_health():
    return {"status": "ok"}


@app.post("/scan")
async def scan(file: UploadFile):
    content = await file.read()
    text = content.decode("utf-8")
    lines = text.splitlines()

    packages = []
    skipped = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            skipped.append(line)
            continue
        name, version = line.split("==")
        vulns = await query_osv(name, version)
        unique = {}
        for vuln in vulns:
            info = extract_info(vuln)
            cve = info["cve"]
            if cve not in unique or unique[cve]["severity"] == "UNKNOWN":
                unique[cve] = info
        vulnerabilities = list(unique.values())
        packages.append({"name": name, "version": version, "vulnerabilities": vulnerabilities})

    return {"filename": file.filename, "packages": packages, "skipped": skipped}