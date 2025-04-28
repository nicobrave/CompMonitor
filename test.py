#!/usr/bin/env python3
import os
import json
import hashlib
import difflib
import feedparser
import re
import requests
import openai
from datetime import datetime, timezone
from dotenv import load_dotenv
import warnings

# ── Configuración inicial ──
warnings.filterwarnings("ignore", category=FutureWarning)
load_dotenv()

DOMAINS = ["island.io", "guardz.com", "here.io"]
STATE_FILE = "state.json"
TEAMS_WEBHOOK = os.getenv("TEAMS_WEBHOOK_URL")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY")
openai.api_key = OPENAI_API_KEY

# ── Funciones Base ──
def load_state():
    if os.path.isfile(STATE_FILE):
        return json.load(open(STATE_FILE, encoding="utf-8"))
    else:
        return {"sites": {}, "seen_alerts": []}

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)

def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()

def fetch_site(domain: str) -> str:
    try:
        print(f"[INFO] Accediendo a {domain}...")
        r = requests.get(f"https://{domain}", timeout=30)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[ERROR] Error al acceder a {domain}: {e}")
        return ""

def diff_html(old: str, new: str) -> str:
    return "\n".join(difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=3))

def extract_text_from_html(html: str) -> str:
    html = re.sub(r'<script[\s\S]*?</script>', '', html)
    html = re.sub(r'<style[\s\S]*?</style>', '', html)
    html = re.sub(r'<[^>]+>', ' ', html)
    return re.sub(r'\s+', ' ', html).strip()

def post_to_teams(message: str):
    if not TEAMS_WEBHOOK:
        print("[ERROR] No hay webhook configurado.")
        return
    requests.post(TEAMS_WEBHOOK, json={"text": message}, headers={"Content-Type": "application/json"}, timeout=10)

def call_perplexity(prompt: str) -> str:
    endpoint = "https://api.perplexity.ai/chat/completions"
    headers = {"Authorization": f"Bearer {PERPLEXITY_API_KEY}", "Content-Type": "application/json"}
    try:
        payload = {
            "model": "sonar",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }
        r = requests.post(endpoint, headers=headers, json=payload, timeout=900)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[ERROR] Perplexity fallo: {e}")
        return "No disponible"

def analyze_products(domain: str, html: str) -> dict:
    text = extract_text_from_html(html)
    try:
        resp = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": (
                f"Analiza la web de {domain} y extrae en JSON:\nproducts, features, pricing, target_audience. Texto:\n{text[:4000]}...")
            }],
            temperature=0.2,
            response_format={"type": "json_object"}
        )
        return json.loads(resp.choices[0].message.content.strip())
    except Exception as e:
        print(f"[ERROR] OpenAI fallo analizando {domain}: {e}")
        return {}

def fetch_alerts():
    feeds = [
        "https://www.cisa.gov/news-events/cybersecurity-advisories/feed",
        "https://www.ncsc.gov.uk/api/1/services/feed/alerts/rss",
    ]
    alerts = []
    for url in feeds:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:5]:
                alerts.append({"title": entry.title, "link": entry.link, "published": entry.get("published", "")})
        except Exception:
            continue
    return alerts

# ── Main ──
def main():
    print("\n[START] Ejecutando Monitor de Competidores")
    state = load_state()
    report = []
    changes = False

    report.append(f"# Reporte Diario ({datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC})\n")

    for domain in DOMAINS:
        print(f"[INFO] Procesando competidor: {domain}")
        section = [f"## Competidor: {domain}", ""]
        html = fetch_site(domain)
        h = sha1(html)
        prev = state.get("sites", {}).get(domain, {})

        section.append("### Revisión de Sitio")
        if prev.get("hash") != h:
            diff = diff_html(prev.get("html", ""), html)
            section.append(f"- Cambio detectado:\n```diff\n{diff[:500]}...\n```\n")
            state.setdefault("sites", {})[domain] = {"hash": h, "html": html}
            changes = True
            prod = analyze_products(domain, html)
            if prod:
                section.append("### Productos/Servicios:")
                for p in prod.get("products", []):
                    section.append(f"- {p}")
                section.append("\n### Características:")
                for f in prod.get("features", []):
                    section.append(f"- {f}")
                if prod.get("pricing"):
                    section.append("\n### Precios/Modelo:")
                    for pr in prod.get("pricing", []):
                        section.append(f"- {pr}")
                if prod.get("target_audience"):
                    section.append(f"\n### Público Objetivo:\n- {prod['target_audience']}")
        else:
            section.append("- Sin cambios detectados.")

        print(f"[INFO] Consultando noticias para {domain}")
        news_summary = call_perplexity(f"In the last 24 hours, any important cybersecurity news about {domain}? Summarize in 5 sentences.")
        section.append("\n### Noticias Últimas 24h")
        section.append(news_summary)
        section.append("")

        report.extend(section)

    print("[INFO] Consultando tendencias globales")
    trends = call_perplexity("Current cybersecurity trends and emerging threats summarized.")
    report.append("## Tendencias de Ciberseguridad\n")
    report.append(trends)

    print("[INFO] Consultando insights estratégicos")
    insights = call_perplexity("Recent cybersecurity product launches or competitor movements summarized.")
    report.append("\n## Insights Estratégicos\n")
    report.append(insights)

    print("[INFO] Consultando alertas oficiales")
    alerts = fetch_alerts()
    if alerts:
        report.append("\n## Alertas Críticas\n")
        for alert in alerts:
            report.append(f"- [{alert['title']}]({alert['link']}) - {alert['published']}")

    full_report = "\n".join(report)

    print("[INFO] Generando resumen ejecutivo final")
    try:
        summary_prompt = "Genera un resumen ejecutivo breve destacando hallazgos por competidor, tendencias y alertas:\n" + full_report
        resp = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": summary_prompt}],
            temperature=0.3,
        )
        summary = resp.choices[0].message.content.strip()
    except Exception as e:
        print(f"[ERROR] OpenAI fallo: {e}")
        summary = full_report

    post_to_teams(f"**Reporte Diario de Competidores y Ciberseguridad**\n\n{summary}")
    save_state(state)
    print("[DONE] Reporte enviado y estado actualizado.\n")

if __name__ == "__main__":
    main()
