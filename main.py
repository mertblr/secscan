from fastapi import FastAPI, UploadFile

app = FastAPI()

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
        packages.append({"name": name, "version": version}) 

    return {"filename": file.filename, "packages": packages}  