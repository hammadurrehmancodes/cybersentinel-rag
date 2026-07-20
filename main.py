# main.py
from fastapi import FastAPI
from copilot.routes import router as copilot_router

app = FastAPI(
    title="CyberSentinel - AI Security Copilot API",
    version="1.0.0",
    description="Local vector RAG agent analyzing logs against NIST guidelines & MITRE ATT&CK."
)

# Wire the copilot router directly into your application root
app.include_router(copilot_router, prefix="/api/copilot", tags=["Security Copilot"])

@app.get("/")
async def root():
    return {"status": "online", "message": "CyberSentinel Copilot Core is active."}
