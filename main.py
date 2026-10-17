from packaging.version import Version
import httpx
from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse

OSV_URL = "https://api.osv.dev/v1/query"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}

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

def severity_rank(vuln):
    return SEVERITY_ORDER.get(vuln["severity"], 5)


def deduplicate(vulns):
    unique = {}
    for vuln in vulns:
        info = extract_info(vuln)
        cve = info["cve"]
        if cve not in unique or unique[cve]["severity"] == "UNKNOWN":
            unique[cve] = info
    return sorted(unique.values(), key=severity_rank)


def recommend_version(current, vulnerabilities):
    current_v = Version(current)
    needed = []
    for vuln in vulnerabilities:
        candidates = []
        for fixed in vuln["fixed_in"]:
            fixed_v = Version(fixed)
            if fixed_v > current_v:
                candidates.append(fixed_v)
        if candidates:
            needed.append(min(candidates))
    if not needed:
        return None
    return str(max(needed))



@app.get("/")
def root():
    return FileResponse("static/index.html")


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
        vulnerabilities = deduplicate(vulns)
        recommended = recommend_version(version, vulnerabilities)
        packages.append({"name": name, "version": version, "recommended_version": recommended, "vulnerabilities": vulnerabilities})

    return {"filename": file.filename, "packages": packages, "skipped": skipped}