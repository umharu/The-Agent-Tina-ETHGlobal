import os
import requests
from dotenv import load_dotenv

load_dotenv()

def headers():
    api_key = os.getenv("AGENTARENA_API_KEY")
    if not api_key:
        raise RuntimeError("Falta AGENTARENA_API_KEY")
    return {
        "Authorization": f"Bearer {api_key}",
        "X-API-Key": api_key,
        "Accept": "*/*",
    }

def get_task_details(url: str) -> dict:
    r = requests.get(url, headers=headers(), timeout=60)
    r.raise_for_status()
    return r.json()

def download_repository(url: str, task_id: str) -> str:
    r = requests.get(url, headers=headers(), stream=True, timeout=120)
    r.raise_for_status()

    os.makedirs("data", exist_ok=True)
    archive_path = f"data/{task_id}.zip"

    with open(archive_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    return archive_path
