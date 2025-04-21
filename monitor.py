#!/usr/bin/env python3
import os
import json
import hashlib
import difflib
from datetime import datetime, timezone
from collections import Counter

import requests
import openai
from dotenv import load_dotenv
from pytrends.request import TrendReq
import warnings

# ── Suprime warnings inofensivos ───────────────────────────────────────────────
warnings.filterwarnings("ignore", category=FutureWarning)

# ── Carga de .env ─────────────────────────────────────────────────────────────
load_dotenv()

# ── Configuración ────────────────────────────────────────────────────────────
DOMAINS        = ["island.io", "guardz.com", "here.io"]
STATE_FILE     = "state.json"
NEWSAPI_KEY    = os.getenv("NEWSAPI_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
TEAMS_WEBHOOK  = os.getenv("TEAMS_WEBHOOK_URL")
openai.api_key = OPENAI_API_KEY

# ── Estado ───────────────────────────────────────────────────────────────────
def load_state():
    if os.path.isfile(STATE_FILE):
        st = json.load(open(STATE_FILE, encoding="utf-8"))
    else:
        st = {"sites": {}, "last_run": None, "seen_news": [], "seen_trends": []}
    st.setdefault("sites", {})
    st.setdefault("seen_news", [])
    st.setdefault("seen_trends", [])
    return st

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)

# ── Utilitarios ──────────────────────────────────────────────────────────────
def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()

def fetch_site(domain: str) -> str:
    r = requests.get(f"https://{domain}", timeout=15)
    r.raise_for_status()
    return r.text

def diff_html(old: str, new: str) -> str:
    return "\n".join(difflib.unified_diff(
        old.splitlines(), new.splitlines(),
        fromfile="antes", tofile="ahora", lineterm="", n=3
    ))

def fetch_news(domain: str) -> list[dict]:
    if not NEWSAPI_KEY:
        return []
    # Buscar específicamente el competidor en contexto de ciberseguridad
    competitor = domain.split('.')[0]
    query = f"{competitor} cybersecurity"
    url = "https://newsapi.org/v2/everything"
    params = {
        "q": query,
        "from": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sortBy": "publishedAt",
        "apiKey": NEWSAPI_KEY,
        "pageSize": 5
    }
    r = requests.get(url, params=params, timeout=10)
    articles = r.json().get("articles", [])
    one_day_ago = datetime.now(timezone.utc).timestamp() - 86400
    recent = []
    for a in articles:
        ts = datetime.fromisoformat(a["publishedAt"].replace("Z", "+00:00")).timestamp()
        if ts >= one_day_ago:
            recent.append({"title": a["title"], "url": a["url"], "source": a["source"]["name"]})
    return recent

def fetch_trends(keyword: str, timeframe: str = "now 7-d") -> dict:
    py = TrendReq(hl="en-US", tz=0)
    try:
        py.build_payload([keyword], timeframe=timeframe, geo="")
    except Exception:
        return {"rising_queries": [], "interest_last_7d": {}}

    try:
        rq = (py.related_queries() or {}).get(keyword) or {}
        if rq.get("rising") is not None and not rq["rising"].empty:
            top_rising = rq["rising"]["query"].head(5).tolist()
        else:
            top_rising = []
    except Exception:
        top_rising = []

    try:
        df = py.interest_over_time().fillna(False).infer_objects(copy=False)
        if keyword in df:
            series = df[keyword]
            interest_dict = {d.strftime("%Y-%m-%d"): int(v) for d, v in series.tail(7).items()}
        else:
            interest_dict = {}
    except Exception:
        interest_dict = {}

    return {"rising_queries": top_rising, "interest_last_7d": interest_dict}

# ── Generación de Resumen ────────────────────────────────────────────────────
def generate_summary(raw_report: str) -> str:
    prompt = (
        "Eres un asistente experto en análisis competitivo para ciberseguridad.\n"
        "A partir de este reporte crudo (dividido por competidor y con tendencias), "
        "genera un **Resumen Ejecutivo** con estas secciones:\n"
        "1. Hallazgos por competidor (revisión de sitio + noticias nuevas)\n"
        "2. Análisis de mercado (tendencias globales generales)\n\n"
        + raw_report
    )
    resp = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    return resp.choices[0].message.content.strip()

def post_to_teams(message: str):
    if not TEAMS_WEBHOOK:
        print("No WEBHOOK configurado.")
        return
    requests.post(
        TEAMS_WEBHOOK,
        json={"text": message},
        headers={"Content-Type": "application/json"},
        timeout=10
    ).raise_for_status()

# ── Flujo Principal ───────────────────────────────────────────────────────────
def main():
    state      = load_state()
    per_domain = {}
    report     = []

    for domain in DOMAINS:
        section = [f"## Competidor: {domain}", ""]
        html    = fetch_site(domain)
        h       = sha1(html)
        prev    = state["sites"].get(domain, {})

        # Revisión de sitio
        section.append("### Revisión de sitio")
        if prev.get("hash") != h:
            diff = diff_html(prev.get("html", ""), html)
            section.append(f"- Cambio detectado:\n```diff\n{diff[:500]}...\n```")
        else:
            section.append("- Sin cambios detectados.")
        section.append("")
        state["sites"][domain] = {"hash": h, "html": html}

        # Noticias nuevas
        section.append("### Noticias últimas 24h")
        news = fetch_news(domain)
        new_news = [a for a in news if a["url"] not in state["seen_news"]]
        if new_news:
            for a in new_news:
                section.append(f"- [{a['title']}]({a['url']}) ({a['source']})")
                state["seen_news"].append(a["url"])
        else:
            section.append("- No hay noticias nuevas.")
        section.append("")

        # Tendencias nuevas
        trends     = fetch_trends(domain)
        per_domain[domain] = trends
        new_trends = [q for q in trends["rising_queries"] if q not in state["seen_trends"]]
        if new_trends:
            section.append("### Nuevas Tendencias búsqueda (últimos 7d)")
            for q in new_trends:
                section.append(f"- {q}")
                state["seen_trends"].append(q)
        section.append("")

        report.extend(section)

    # Análisis general de mercado
    report.append("## Análisis de Mercado por Tendencias")
    all_rising = Counter()
    for trends in per_domain.values():
        all_rising.update(trends["rising_queries"])
    top_general = [q for q, _ in all_rising.most_common(5) if q not in state["seen_trends"]]
    if top_general:
        for q in top_general:
            report.append(f"- {q}")
            state["seen_trends"].append(q)
    else:
        report.append("- No hay tendencias generales nuevas.")
    report.append("")

    # Generar y enviar resumen
    header     = f"Reporte crudo Competidores ({datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC})\n\n"
    raw_report = header + "\n".join(report)
    summary    = generate_summary(raw_report)
    post_to_teams(f"**Resumen Ejecutivo Competidores**\n\n{summary}")

    # Guardar estado
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    save_state(state)

if __name__ == "__main__":
    main()
