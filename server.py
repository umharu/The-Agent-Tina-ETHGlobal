from fastapi import FastAPI, Request, BackgroundTasks
from agentarena_client import get_task_details, download_repository
import zipfile
import os
import requests

app = FastAPI()

def run_agent_job(payload: dict):
    task_id = payload["task_id"]

    # 1) detalles
    details = get_task_details(payload["task_details_url"])
    print("📄 Task details OK")

    # 2) descargar repo zip
    archive_path = download_repository(payload["task_repository_url"], task_id)
    print("📦 Repo descargado:", archive_path)

    # 3) extraer repo
    extract_dir = f"data/{task_id}"
    os.makedirs(extract_dir, exist_ok=True)

    with zipfile.ZipFile(archive_path, "r") as zip_ref:
        zip_ref.extractall(extract_dir)

    print("📂 Repo extraído en:", extract_dir)

    # 4) finding dummy
    findings = {
    "task_id": task_id,
    "findings": [
        {
            "title": "Pipeline OK",
            "severity": "Info",
            "description": "Repository downloaded and extracted successfully.",
            "file_paths": [
                "data/TESTTASK"
            ],
            "recommendation": "Replace this with real audit."
        }
    ],
    "meta": {
        "agent_name": "Agent-Tina"
    }
}


    # 5) post findings al arbiter
    api_key = os.getenv("AGENTARENA_API_KEY", "").strip()
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    r = requests.post(payload["post_findings_url"], json=findings, headers=headers, timeout=60)
    print("🧾 Arbiter response:", r.status_code, r.text[:200])

@app.post("/webhook")
async def webhook(request: Request, background: BackgroundTasks):
    payload = await request.json()
    print("🔔 Webhook recibido:", payload)
    background.add_task(run_agent_job, payload)
    return {"status": "ok"}
