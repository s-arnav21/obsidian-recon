from fastapi import FastAPI

app = FastAPI(title="Obsidian Recon API")

@app.get("/")
def read_root():
    return {"status": "Obsidian Recon backend is running"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
