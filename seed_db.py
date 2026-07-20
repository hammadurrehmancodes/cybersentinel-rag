"""
CyberSentinel — seed_db.py
===========================
Standalone ingestion pipeline. Run this ONCE before starting the app.
Run again whenever you update files in data/.

What it does:
  1. Reads data/nist_800_61.md       → chunks by section header
  2. Reads data/log_patterns.json    → one chunk per pattern
  3. Downloads MITRE ATT&CK STIX     → one chunk per technique
  4. Embeds everything with sentence-transformers (local, free)
  5. Saves to chroma_storage/        → app reads from here, never writes

Usage:
  python seed_db.py                  # full run, downloads MITRE
  python seed_db.py --skip-mitre     # skip MITRE download (offline mode)
  python seed_db.py --reset          # wipe and rebuild from scratch

The app never calls this. Clean separation.
"""

import os
import sys
import json
import argparse
import re
import requests
import chromadb
from chromadb.utils import embedding_functions

# ── Config ──────────────────────────────────────────────────
DATA_DIR         = "./data"
CHROMA_PATH      = "./chroma_storage"
COLLECTION_NAME  = "security_frameworks"
EMBEDDING_MODEL  = "all-MiniLM-L6-v2"

MITRE_STIX_URL = "./data/enterprise-attack.json"

# How many MITRE techniques to index (full set is ~700, slow on first run)
# Increase to 200+ for a richer knowledge base
MITRE_TECHNIQUE_LIMIT = 100


# ── Helpers ─────────────────────────────────────────────────

def log(msg: str):
    print(f"  {msg}")


def chunk_markdown_by_section(filepath: str) -> list[dict]:
    """
    Split a markdown file into chunks at every ## header.
    Each chunk = one section. Preserves the header as part of the chunk.

    Returns list of dicts: {id, content, metadata}
    """
    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()

    # Split on ## headers (not ###)
    sections = re.split(r"\n(?=## )", raw)
    chunks = []

    for i, section in enumerate(sections):
        section = section.strip()
        if not section:
            continue

        # Extract title from first line
        lines = section.split("\n")
        title = lines[0].replace("##", "").strip().replace("# ", "")

        chunks.append({
            "id": f"nist_{i:03d}",
            "content": section,
            "metadata": {
                "source": "NIST SP 800-61 Rev 2",
                "title": title,
                "category": "incident_response",
                "file": os.path.basename(filepath)
            }
        })

    return chunks


def chunk_log_patterns(filepath: str) -> list[dict]:
    """
    Load log_patterns.json and convert each pattern into one chunk.
    Formats the JSON fields into readable prose for better embedding quality.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    chunks = []
    for pattern in data["patterns"]:
        # Build human-readable content from structured fields
        indicators_text = "\n".join(f"- {ind}" for ind in pattern.get("log_indicators", []))
        thresholds = pattern.get("thresholds", {})
        thresholds_text = "\n".join(f"- {k}: {v}" for k, v in thresholds.items())
        ports = pattern.get("affected_ports", [])
        ports_text = ", ".join(str(p) for p in ports) if ports else "Various"

        # Sensitive ports map (for LP-005)
        sensitive = pattern.get("sensitive_ports", {})
        sensitive_text = ""
        if sensitive:
            sensitive_text = "\nSensitive ports to monitor:\n"
            sensitive_text += "\n".join(f"- Port {p}: {desc}" for p, desc in sensitive.items())

        content = f"""ATTACK PATTERN: {pattern['name']}
ID: {pattern['id']}
Type: {pattern['attack_type']}
Severity: {pattern['severity_default'].upper()}
Response Category: {pattern['response_category']}

Description:
{pattern['description']}

Log Indicators:
{indicators_text}

Detection Thresholds:
{thresholds_text}

Affected Ports: {ports_text}
{sensitive_text}"""

        chunks.append({
            "id": f"lp_{pattern['id'].lower().replace('-', '_')}",
            "content": content,
            "metadata": {
                "source": "CyberSentinel Log Pattern Library",
                "title": pattern["name"],
                "category": pattern["response_category"],
                "attack_type": pattern["attack_type"],
                "severity": pattern["severity_default"],
                "file": os.path.basename(filepath)
            }
        })

    return chunks


def fetch_mitre_stix(limit: int = 100) -> list[dict]:
    """
    Download MITRE ATT&CK Enterprise STIX JSON and extract techniques.
    Each technique becomes one chunk. Only takes techniques, not sub-techniques,
    groups, or software objects — keeps the knowledge base focused.

    Returns list of dicts: {id, content, metadata}
    """
    log(f"Downloading MITRE ATT&CK STIX from GitHub (limit: {limit} techniques)...")

    try:
        response = requests.get(MITRE_STIX_URL, timeout=60)
        response.raise_for_status()
        stix_data = response.json()
    except requests.RequestException as e:
        log(f"Failed to download MITRE data: {e}")
        log("Continuing without MITRE ATT&CK data.")
        return []

    chunks = []
    count = 0

    for obj in stix_data.get("objects", []):
        # Only process non-revoked techniques (not sub-techniques)
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False):
            continue
        if obj.get("x_mitre_is_subtechnique", False):
            continue

        # Extract MITRE ID (e.g., T1110)
        technique_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break

        if not technique_id:
            continue

        name        = obj.get("name", "Unknown")
        description = obj.get("description", "No description available.")
        detection   = obj.get("x_mitre_detection", "No detection guidance available.")
        platforms   = ", ".join(obj.get("x_mitre_platforms", []))
        kill_chain  = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                kill_chain.append(phase.get("phase_name", ""))

        # Truncate long descriptions for reasonable chunk size
        description = description[:1200] if len(description) > 1200 else description
        detection   = detection[:600]   if len(detection) > 600   else detection

        content = f"""MITRE ATT&CK TECHNIQUE: {name}
ID: {technique_id}
Platforms: {platforms}
Tactic: {', '.join(kill_chain)}

Description:
{description}

Detection Guidance:
{detection}"""

        chunks.append({
            "id": f"mitre_{technique_id.lower().replace('.', '_')}",
            "content": content,
            "metadata": {
                "source": f"MITRE ATT&CK {technique_id}",
                "title": f"{technique_id}: {name}",
                "category": "mitre_attack",
                "technique_id": technique_id,
                "platforms": platforms,
                "file": "mitre_attack_enterprise_stix"
            }
        })

        count += 1
        if count >= limit:
            break

    log(f"Extracted {len(chunks)} MITRE ATT&CK techniques.")
    return chunks


def build_database(chunks: list[dict], reset: bool = False):
    """
    Embed all chunks and store in ChromaDB.
    App will query this — it never writes to it.
    """
    log(f"Connecting to ChromaDB at: {CHROMA_PATH}")
    client = chromadb.PersistentClient(path=CHROMA_PATH)

    # Reset if requested
    if reset:
        try:
            client.delete_collection(name=COLLECTION_NAME)
            log("Existing collection deleted.")
        except Exception:
            pass

    # Use local sentence-transformers (free, no API key needed)
    log(f"Loading embedding model: {EMBEDDING_MODEL}")
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
        metadata={"description": "CyberSentinel security knowledge base"}
    )

    # Upsert in batches of 50
    batch_size = 50
    total = len(chunks)

    for i in range(0, total, batch_size):
        batch = chunks[i : i + batch_size]
        collection.upsert(
            ids       = [c["id"]       for c in batch],
            documents = [c["content"]  for c in batch],
            metadatas = [c["metadata"] for c in batch]
        )
        done = min(i + batch_size, total)
        log(f"Indexed {done}/{total} chunks...")

    log(f"Done. Collection '{COLLECTION_NAME}' has {collection.count()} documents.")
    return collection


# ── Main ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberSentinel knowledge base seeder")
    parser.add_argument("--skip-mitre", action="store_true", help="Skip MITRE download (offline mode)")
    parser.add_argument("--reset",      action="store_true", help="Wipe and rebuild the database")
    args = parser.parse_args()

    print("\n" + "=" * 55)
    print("  CyberSentinel — Knowledge Base Seeder")
    print("=" * 55)

    all_chunks = []

    # 1. NIST 800-61
    nist_path = os.path.join(DATA_DIR, "nist_800_61.md")
    if os.path.exists(nist_path):
        log("Reading NIST SP 800-61...")
        nist_chunks = chunk_markdown_by_section(nist_path)
        log(f"Produced {len(nist_chunks)} NIST chunks.")
        all_chunks += nist_chunks
    else:
        log(f"WARNING: {nist_path} not found. Skipping NIST data.")

    # 2. Log Patterns
    patterns_path = os.path.join(DATA_DIR, "log_patterns.json")
    if os.path.exists(patterns_path):
        log("Reading log_patterns.json...")
        pattern_chunks = chunk_log_patterns(patterns_path)
        log(f"Produced {len(pattern_chunks)} log pattern chunks.")
        all_chunks += pattern_chunks
    else:
        log(f"WARNING: {patterns_path} not found. Skipping log patterns.")

    # 3. MITRE ATT&CK (optional)
    if not args.skip_mitre:
        mitre_chunks = fetch_mitre_stix(limit=MITRE_TECHNIQUE_LIMIT)
        all_chunks += mitre_chunks
    else:
        log("Skipping MITRE ATT&CK (--skip-mitre flag set).")

    if not all_chunks:
        print("\nERROR: No chunks to index. Check your data/ directory.")
        sys.exit(1)

    print(f"\n  Total chunks to index: {len(all_chunks)}")

    # 4. Build ChromaDB
    print("\n  Building vector database...")
    build_database(all_chunks, reset=args.reset)

    print("\n" + "=" * 55)
    print("  Seeding complete. You can now start the app.")
    print(f"  Database location: {os.path.abspath(CHROMA_PATH)}")
    print("=" * 55 + "\n")


if __name__ == "__main__":
    main()
