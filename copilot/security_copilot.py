"""
CyberSentinel — Security Copilot (App Layer)
=============================================
Read-only. Queries chroma_storage/ — never writes to it.
seed_db.py is responsible for building the database.

Two public methods:
    copilot.analyze_logs(log_text)           → CopilotResponse
    copilot.answer_question(question, ctx)   → CopilotResponse
"""

import os
import json
import requests
import chromadb
from chromadb.utils import embedding_functions
from dotenv import load_dotenv
from dataclasses import dataclass, field
from typing import Optional

from copilot.log_analyzer import LogParser, LogAnalysisResult

load_dotenv()

# ── Config ───────────────────────────────────────────────────
GROQ_API_KEY    = os.getenv("GROQ_API_KEY")
GROQ_MODEL      = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
CHROMA_PATH     = os.getenv("CHROMA_PATH", "./chroma_storage")
COLLECTION_NAME = "security_frameworks"
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
GROQ_URL        = "https://api.groq.com/openai/v1/chat/completions"


# ── Response Models ───────────────────────────────────────────

@dataclass
class PlaybookStep:
    priority:  int
    timeframe: str    # immediate | short_term | long_term
    action:    str
    reason:    str


@dataclass
class CopilotResponse:
    mode:                   str
    plain_english_summary:  str
    severity_overall:       str
    threat_types_detected:  list[str]
    suspicious_ips:         list[str]
    playbook:               list[PlaybookStep]
    recommendations:        list[str]
    sources_used:           list[str]
    raw_log_analysis:       Optional[str] = None


# ── Core Class ────────────────────────────────────────────────

class SecurityCopilot:

    def __init__(self):
        self.parser = LogParser()
        self.collection = self._connect_db()

    def _connect_db(self):
        """
        Connect to the pre-built ChromaDB.
        Read-only: this method only gets the collection, never creates or seeds it.
        """
        try:
            client = chromadb.PersistentClient(path=CHROMA_PATH)
            embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=EMBEDDING_MODEL
            )
            collection = client.get_collection(
                name=COLLECTION_NAME,
                embedding_function=embedding_fn
            )
            print(f"[Copilot] Knowledge base ready — {collection.count()} documents.")
            return collection

        except Exception as e:
            print(f"[Copilot] WARNING: Could not connect to knowledge base: {e}")
            print("[Copilot] Run 'python seed_db.py' to build it.")
            return None

    # ── Public API ────────────────────────────────────────────

    def analyze_logs(self, log_text: str) -> CopilotResponse:
        """
        Analyze raw firewall/auth log text.
        Returns plain-English summary + incident response playbook.
        """
        log_result  = self.parser.parse(log_text)
        event_types = list(set(e.event_type for e in log_result.events))
        query = (
            f"incident response playbook for {', '.join(event_types)}"
            if event_types
            else "suspicious network activity firewall blocks response"
        )
        context, sources = self._retrieve(query, n=5)
        system_prompt    = self._log_system_prompt(context)
        user_message     = self._log_user_message(log_result)
        raw              = self._call_groq(system_prompt, user_message)
        return self._parse(raw, mode="log_analysis", log_result=log_result, sources=sources)

    def answer_question(
        self,
        question: str,
        platform_context: Optional[dict] = None
    ) -> CopilotResponse:
        """
        Answer a plain-English security question.
        Optionally enriched with live CyberSentinel platform data.
        """
        context, sources = self._retrieve(question, n=5)
        system_prompt    = self._question_system_prompt(context, platform_context)
        raw              = self._call_groq(system_prompt, question)
        return self._parse(raw, mode="question", sources=sources)

    # ── Private: Retrieval ────────────────────────────────────

    def _retrieve(self, query: str, n: int = 5) -> tuple[str, list[str]]:
        if not self.collection:
            return "", []
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=min(n, self.collection.count())
            )
            parts, sources = [], []
            for i, doc in enumerate(results["documents"][0]):
                meta = results["metadatas"][0][i]
                parts.append(f"[{meta.get('title', 'Reference')}]\n{doc}")
                src = meta.get("source", "CyberSentinel KB")
                if src not in sources:
                    sources.append(src)
            return "\n\n---\n\n".join(parts), sources
        except Exception as e:
            print(f"[Copilot] Retrieval error: {e}")
            return "", []

    # ── Private: LLM ─────────────────────────────────────────

    def _call_groq(self, system_prompt: str, user_message: str) -> str:
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not set. Check your .env file.")
        payload = {
            "model":           GROQ_MODEL,
            "temperature":     0.2,
            "max_tokens":      2000,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message}
            ]
        }
        resp = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    # ── Private: Prompts ──────────────────────────────────────

    def _log_system_prompt(self, context: str) -> str:
        return f"""You are the CyberSentinel Security Copilot — an expert cybersecurity analyst embedded in a SOC platform.

RETRIEVED SECURITY KNOWLEDGE (NIST / MITRE / Pattern Library):
{context}

RULES:
- Ground every playbook step in the retrieved knowledge above. Do not invent steps.
- Use plain English a non-technical manager can understand.
- Prioritize by severity: immediate threats always come first.
- If data exfiltration or successful compromise is possible, say so explicitly.
- Be specific: name the IP, port, service, and exact action to take.

RESPOND IN THIS EXACT JSON FORMAT — no extra keys, no markdown fences:
{{
    "plain_english_summary": "2-3 sentences explaining what happened and how serious it is",
    "severity_overall": "critical|high|medium|low",
    "threat_types_detected": ["brute_force", "port_scan"],
    "playbook": [
        {{
            "priority": 1,
            "timeframe": "immediate|short_term|long_term",
            "action": "Exact action to take",
            "reason": "Why this specific action is necessary"
        }}
    ],
    "recommendations": [
        "Long-term security control to implement"
    ]
}}"""

    def _log_user_message(self, log_result) -> str:
        events_json = [
            {"type": e.event_type, "severity": e.severity, "source_ip": e.source_ip,
             "port": e.destination_port, "count": e.count, "details": e.details}
            for e in log_result.events[:10]
        ]
        return f"""Analyze this log data and generate an incident response:

LOG SUMMARY:
{log_result.summary}

DETECTED EVENTS:
{json.dumps(events_json, indent=2)}

SUSPICIOUS IPs: {log_result.suspicious_ips}
TOP TARGETED PORTS: {log_result.top_attacked_ports[:5]}
LOG FORMAT: {log_result.log_type}"""

    def _question_system_prompt(self, context: str, platform_context) -> str:
        platform_block = ""
        if platform_context:
            platform_block = f"\nLIVE PLATFORM DATA:\n{json.dumps(platform_context, indent=2)}\n"
        return f"""You are the CyberSentinel Security Copilot — an expert cybersecurity analyst.

RETRIEVED KNOWLEDGE:
{context}
{platform_block}
Respond in this exact JSON format:
{{
    "plain_english_summary": "Direct answer",
    "severity_overall": "info|low|medium|high|critical",
    "threat_types_detected": [],
    "playbook": [{{"priority": 1, "timeframe": "immediate", "action": "...", "reason": "..."}}],
    "recommendations": []
}}"""

    # ── Private: Parse ────────────────────────────────────────

    def _parse(self, raw, mode, log_result=None, sources=None) -> CopilotResponse:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {"plain_english_summary": raw[:500], "severity_overall": "medium",
                    "threat_types_detected": [], "playbook": [], "recommendations": []}

        playbook = [
            PlaybookStep(priority=s.get("priority", i+1), timeframe=s.get("timeframe", "immediate"),
                         action=s.get("action", ""), reason=s.get("reason", ""))
            for i, s in enumerate(data.get("playbook", []))
        ]

        return CopilotResponse(
            mode=mode,
            plain_english_summary=data.get("plain_english_summary", ""),
            severity_overall=data.get("severity_overall", "medium"),
            threat_types_detected=data.get("threat_types_detected", []),
            suspicious_ips=log_result.suspicious_ips if log_result else [],
            playbook=playbook,
            recommendations=data.get("recommendations", []),
            sources_used=sources or [],
            raw_log_analysis=log_result.summary if log_result else None
        )
