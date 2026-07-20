"""
CyberSentinel - Security Copilot API Routes
=============================================
Drop this into your existing FastAPI backend.

Mount in your main.py like:
    from copilot.routes import router as copilot_router
    app.include_router(copilot_router, prefix="/api/copilot", tags=["Security Copilot"])

Endpoints:
    POST /api/copilot/analyze-logs     → Analyze raw log text
    POST /api/copilot/ask              → Ask a security question
    POST /api/copilot/investigate-ip   → Investigate a specific IP
    GET  /api/copilot/health           → Health check
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional
import json
import io


from copilot.security_copilot import SecurityCopilot, CopilotResponse
from copilot.report_generator import generate_pdf_report

router = APIRouter()

# Single instance - reuses loaded models
copilot = SecurityCopilot()


# ─────────────────────────────────────────────
# Request/Response Schemas
# ─────────────────────────────────────────────

class LogAnalysisRequest(BaseModel):
    log_text: str = Field(..., description="Raw log content to analyze", min_length=10)
    include_pdf: bool = Field(False, description="Whether to generate PDF report")

class QuestionRequest(BaseModel):
    question: str = Field(..., description="Security question to answer", min_length=3)
    platform_context: Optional[dict] = Field(None, description="Live platform data for enrichment")

class IPInvestigationRequest(BaseModel):
    ip_address: str = Field(..., description="IP address to investigate")
    platform_data: Optional[dict] = Field(None, description="Existing platform data for this IP")

class PlaybookStepResponse(BaseModel):
    priority: int
    timeframe: str
    action: str
    reason: str

class CopilotAPIResponse(BaseModel):
    mode: str
    plain_english_summary: str
    severity_overall: str
    threat_types_detected: list[str]
    suspicious_ips: list[str]
    playbook: list[PlaybookStepResponse]
    recommendations: list[str]
    sources_used: list[str]
    raw_log_analysis: Optional[str] = None


def _format_response(copilot_response: CopilotResponse) -> CopilotAPIResponse:
    """Convert internal CopilotResponse to API response schema."""
    return CopilotAPIResponse(
        mode=copilot_response.mode,
        plain_english_summary=copilot_response.plain_english_summary,
        severity_overall=copilot_response.severity_overall,
        threat_types_detected=copilot_response.threat_types_detected,
        suspicious_ips=copilot_response.suspicious_ips,
        playbook=[
            PlaybookStepResponse(
                priority=step.priority,
                timeframe=step.timeframe,
                action=step.action,
                reason=step.reason
            )
            for step in copilot_response.playbook
        ],
        recommendations=copilot_response.recommendations,
        sources_used=copilot_response.sources_used,
        raw_log_analysis=copilot_response.raw_log_analysis
    )


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@router.get("/health")
async def health_check():
    """Check if the copilot is ready."""
    kb_status = "ready" if copilot.collection else "knowledge_base_missing"
    return {
        "status": "online",
        "knowledge_base": kb_status,
        "model": "llama-3.3-70b-versatile",
        "provider": "Groq"
    }


@router.post("/analyze-logs", response_model=CopilotAPIResponse)
async def analyze_logs(request: LogAnalysisRequest):
    """
    Analyze raw firewall/system logs.
    
    Supports: Windows Firewall, Linux UFW, IPTables, SSH auth logs
    
    Returns:
    - Plain English explanation of what happened
    - Severity assessment
    - Step-by-step incident response playbook
    - Long-term recommendations
    """
    try:
        result = copilot.analyze_logs(request.log_text)
        return _format_response(result)
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/analyze-logs/pdf")
async def analyze_logs_pdf(request: LogAnalysisRequest):
    """
    Analyze logs and return a downloadable PDF report.
    """
    try:
        result = copilot.analyze_logs(request.log_text)
        pdf_bytes = generate_pdf_report(result)
        
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=cybersentinel_report.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.post("/ask", response_model=CopilotAPIResponse)
async def ask_question(request: QuestionRequest):
    """
    Ask the Security Copilot a cybersecurity question.
    
    Examples:
    - "What is an SSH brute force attack?"
    - "Why was IP 185.220.101.45 blocked?"
    - "Summarize today's security events"
    - "What should I do about this threat?"
    
    Optionally pass platform_context with live data from CyberSentinel
    for enriched, context-aware answers.
    """
    try:
        result = copilot.answer_question(
            request.question,
            platform_context=request.platform_context
        )
        return _format_response(result)
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Question failed: {str(e)}")


@router.post("/investigate-ip", response_model=CopilotAPIResponse)
async def investigate_ip(request: IPInvestigationRequest):
    """
    Investigate a specific IP address.
    
    Combines platform data (AbuseIPDB score, VirusTotal results, 
    packet history) with knowledge base to generate investigation report.
    """
    try:
        # Build enriched question with IP context
        question = f"Investigate IP address {request.ip_address} and tell me if it's a threat and what I should do."
        
        # Include existing platform data if available
        context = request.platform_data or {}
        context["investigated_ip"] = request.ip_address
        
        result = copilot.answer_question(question, platform_context=context)
        return _format_response(result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.post("/summarize-events")
async def summarize_events(platform_context: dict):
    """
    Summarize recent security events from the platform.
    
    Pass the current dashboard data and get a plain-English summary
    of what's happening and what needs attention.
    """
    try:
        question = "Summarize the current security status based on the platform data. What are the most important things I need to know and do right now?"
        result = copilot.answer_question(question, platform_context=platform_context)
        return _format_response(result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Summarization failed: {str(e)}")
