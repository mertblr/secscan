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
    for line in lines:
        line = line.strip()
        if not line:
            continue
        name, version = line.split("==")
        vulns = await query_osv(name, version)
        packages.append({"name": name, "version": version, "vuln_count": len(vulns)})

    return {"filename": file.filename, "packages": packages}