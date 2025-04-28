#!/usr/bin/env python3
import os
import json
import hashlib
import difflib
import feedparser
import urllib.parse
import re
from datetime import datetime, timezone, timedelta
from collections import Counter

import requests
import openai
from dotenv import load_dotenv
from pytrends.request import TrendReq
import warnings

# ── Suprime warnings inofensivos ──
warnings.filterwarnings("ignore", category=FutureWarning)

# ── Carga de .env ──
load_dotenv()

# ── Configuración ──
DOMAINS        = ["island.io", "guardz.com", "here.io"]
STATE_FILE     = "state.json"
NEWSAPI_KEY    = os.getenv("NEWSAPI_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
TEAMS_WEBHOOK  = os.getenv("TEAMS_WEBHOOK_URL")
VULN_QUERY     = "cybersecurity vulnerability OR CVE"
MAX_VULN_ITEMS = 10
FOCUS_COUNTRY  = "chile"  # País de enfoque

openai.api_key = OPENAI_API_KEY

# ── Estado ──
def load_state():
    if os.path.isfile(STATE_FILE):
        st = json.load(open(STATE_FILE, encoding="utf-8"))
    else:
        st = {
            "sites": {}, 
            "last_run": None, 
            "seen_news": [], 
            "seen_trends": [], 
            "seen_vuln": {}, # Cambiado a diccionario
            "industry_alerts": []
        }
    st.setdefault("sites", {})
    st.setdefault("seen_news", [])
    st.setdefault("seen_trends", [])
    
    # Asegúrate de que seen_vuln sea un diccionario
    if isinstance(st.get("seen_vuln"), list):
        # Migrar de lista a diccionario si es necesario
        old_vuln = st.get("seen_vuln", [])
        st["seen_vuln"] = {"general": old_vuln}
    elif st.get("seen_vuln") is None:
        st["seen_vuln"] = {}
        
    st.setdefault("industry_alerts", [])
    return st

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)

# ── Utilitarios ──
def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()

def fetch_site(domain: str) -> str:
    try:
        r = requests.get(f"https://{domain}", timeout=15)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"Error fetching {domain}: {str(e)}")
        return ""

def diff_html(old: str, new: str) -> str:
    return "\n".join(difflib.unified_diff(
        old.splitlines(), new.splitlines(),
        fromfile="antes", tofile="ahora", lineterm="", n=3
    ))

def extract_text_from_html(html: str) -> str:
    """Extrae el texto visible de HTML eliminando tags"""
    if not html:
        return ""
    # Eliminar scripts y estilos
    html = re.sub(r'<script[\s\S]*?</script>', '', html)
    html = re.sub(r'<style[\s\S]*?</style>', '', html)
    # Eliminar todos los tags
    html = re.sub(r'<[^>]+>', ' ', html)
    # Normalizar espacios
    html = re.sub(r'\s+', ' ', html).strip()
    return html

def fetch_news(domain: str) -> list[dict]:
    if not NEWSAPI_KEY:
        return []
    competitor = domain.split('.')[0]
    query = f"{competitor} cybersecurity"
    url = "https://newsapi.org/v2/everything"
    params = {
        "q": query,
        "from": (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sortBy": "publishedAt",
        "apiKey": NEWSAPI_KEY,
        "pageSize": 5
    }
    try:
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        articles = r.json().get("articles", [])
        one_day = datetime.now(timezone.utc).timestamp() - 86400
        return [
            {
                "title": a["title"], 
                "url": a["url"], 
                "source": a["source"]["name"],
                "summary": a.get("description", "").strip()
            }
            for a in articles
            if datetime.fromisoformat(a["publishedAt"].replace("Z", "+00:00")).timestamp() >= one_day
        ]
    except Exception as e:
        print(f"Error fetching news for {domain}: {str(e)}")
        return []

def fetch_trends(keyword: str, timeframe: str = "now 7-d", geo: str = "") -> dict:
    """Manejo mejorado de errores para PyTrends"""
    try:
        py = TrendReq(hl="en-US", tz=0, timeout=(10, 25), retries=2, backoff_factor=0.5)
        py.build_payload([keyword], timeframe=timeframe, geo=geo)
        
        # Rising queries
        rising_queries = []
        try:
            rq = py.related_queries()
            if rq and keyword in rq and rq[keyword] and 'rising' in rq[keyword] and not rq[keyword]['rising'].empty:
                rising_queries = rq[keyword]['rising']['query'].tolist()[:5]
        except Exception as e:
            print(f"Error getting rising queries for {keyword}: {str(e)}")
        
        # Interest over time
        interest = {}
        try:
            iot = py.interest_over_time()
            if not iot.empty and keyword in iot.columns:
                series = iot[keyword]
                interest = {d.strftime("%Y-%m-%d"): int(v) for d, v in series.tail(7).items()}
        except Exception as e:
            print(f"Error getting interest over time for {keyword}: {str(e)}")
        
        return {"rising_queries": rising_queries, "interest_last_7d": interest}
    except Exception as e:
        print(f"General error in fetch_trends for {keyword}: {str(e)}")
        return {"rising_queries": [], "interest_last_7d": {}}

def fetch_country_trends(keyword: str, country_code: str = "CL") -> dict:
    """Obtiene tendencias específicas para un país con control de errores"""
    try:
        return fetch_trends(keyword, geo=country_code)
    except Exception as e:
        print(f"Error fetching country trends for {keyword} in {country_code}: {str(e)}")
        return {"rising_queries": [], "interest_last_7d": {}}

def get_security_news():
    """Función mejorada para obtener noticias de seguridad por categorías y regiones"""
    # Definir las categorías y fuentes de noticias
    categories = {
        "vulnerabilidades": ["cve", "vulnerabilidad", "brecha", "security breach", "exploit", "falla", "exposición de datos"],
        "phishing": ["phishing", "suplantación", "fraude", "estafa digital", "spoofing", "correo malicioso"],
        "malware": ["malware", "virus", "troyano", "spyware", "adware", "código malicioso"],
        "ransomware": ["ransomware", "secuestro de datos", "extorsión digital", "rescate", "encryption"]
    }
    
    # Fuentes de noticias con enfoque en Chile y global
    sources = {
        "chile": [
            "https://www.csirt.gob.cl/feed/",                  # CSIRT Chile
            "https://www.fayerwayer.com/chile/category/seguridad/feed/",
        ],
        "global": [
            "https://feeds.feedburner.com/TheHackersNews",     # The Hacker News
            "https://www.bleepingcomputer.com/feed/",          # Bleeping Computer
            "https://krebsonsecurity.com/feed/",              # Krebs on Security
        ]
    }
    
    results = {
        "chile": {cat: [] for cat in categories},
        "global": {cat: [] for cat in categories}
    }
    
    # Función para procesar cada fuente de noticias
    def fetch_news_from_source(source_url, region):
        try:
            feed = feedparser.parse(source_url)
            for entry in feed.entries[:15]:  # Limitar a 15 noticias más recientes por fuente
                title = entry.title.lower()
                url = entry.link
                published = entry.get('published', 'Sin fecha')
                description = entry.get('description', entry.get('summary', ''))
                
                # Extraer texto real de la descripción si contiene HTML
                description = extract_text_from_html(description)
                
                # Verificar si la noticia es de los últimos 3 días
                try:
                    if 'published_parsed' in entry:
                        pub_date = datetime(*entry.published_parsed[:6])
                        if (datetime.now() - pub_date).days > 3:
                            continue
                except:
                    pass  # Si hay error en parsing fecha, incluir la noticia
                
                content_text = f"{title} {description}".lower()
                
                # Clasificar en las categorías correspondientes
                for category, keywords in categories.items():
                    if any(keyword.lower() in content_text for keyword in keywords):
                        results[region][category].append({
                            "title": entry.title,
                            "url": url,
                            "published": published,
                            "source": feed.feed.title if hasattr(feed, 'feed') and hasattr(feed.feed, 'title') else source_url,
                            "summary": description[:150] + "..." if len(description) > 150 else description
                        })
        except Exception as e:
            print(f"Error al procesar {source_url}: {str(e)}")
    
    # Procesar todas las fuentes
    for region, source_list in sources.items():
        for source in source_list:
            fetch_news_from_source(source, region)
    
    return results

def fetch_vuln_news(limit: int = MAX_VULN_ITEMS) -> list[dict]:
    """Versión original - mantenida para compatibilidad"""
    q = urllib.parse.quote(VULN_QUERY)
    feed_url = f"https://news.google.com/rss/search?q={q}&hl=en-US&gl=US&ceid=US:en"
    try:
        feed = feedparser.parse(feed_url)
        entries = feed.entries[:limit]
        one_day = datetime.now(timezone.utc).timestamp() - 86400
        news = []
        for e in entries:
            try:
                published = datetime(*e.published_parsed[:6], tzinfo=timezone.utc).timestamp()
                if published >= one_day:
                    news.append({"title": e.title, "url": e.link})
            except Exception as e_inner:
                print(f"Error processing entry in fetch_vuln_news: {str(e_inner)}")
        return news
    except Exception as e:
        print(f"Error in fetch_vuln_news: {str(e)}")
        return []

def generate_vuln_report(report, state):
    """Incorpora noticias de vulnerabilidades categorizadas al reporte"""
    # Obtener noticias de vulnerabilidades
    all_news = get_security_news()
    changes = False
    
    # Preparar las secciones del reporte
    for region in ["chile", "global"]:
        region_title = "Chile" if region == "chile" else "Global"
        report.append(f"## Noticias de Seguridad - {region_title}")
        report.append("")
        
        # Procesar cada categoría
        for category, news_items in all_news[region].items():
            cat_title = category.capitalize()
            report.append(f"### {cat_title}")
            
            # Inicializar categoría en el estado si no existe
            if not state["seen_vuln"].get(category):
                state["seen_vuln"][category] = []
                
            # Filtrar noticias nuevas
            new_items = [item for item in news_items if item["url"] not in state["seen_vuln"].get(category, [])]
            
            if new_items:
                for item in new_items:
                    report.append(f"- [{item['title']}]({item['url']}) - {item['source']} ({item['published']})")
                    if item.get("summary"):
                        report.append(f"  > {item['summary']}")
                    state["seen_vuln"][category].append(item['url'])
                    changes = True
            else:
                report.append(f"- No hay noticias nuevas sobre {cat_title.lower()}")
            
            report.append("")
    
    return changes

def fetch_industry_alerts() -> list[dict]:
    """Obtiene alertas críticas de la industria de ciberseguridad"""
    sources = [
        "https://www.cisa.gov/news-events/cybersecurity-advisories/feed",
        "https://www.ncsc.gov.uk/api/1/services/feed/alerts/rss",
    ]
    
    alerts = []
    for source in sources:
        try:
            feed = feedparser.parse(source)
            for entry in feed.entries[:5]:
                alerts.append({
                    "title": entry.title,
                    "url": entry.link,
                    "date": entry.get('published', 'Sin fecha'),
                    "source": feed.feed.title if hasattr(feed, 'feed') and hasattr(feed.feed, 'title') else source
                })
        except Exception as e:
            print(f"Error fetching alerts from {source}: {str(e)}")
    
    return alerts

# ── Enviar a Teams ──
def post_to_teams(message: str):
    if not TEAMS_WEBHOOK:
        print("No WEBHOOK configurado.")
        return
    
    # Divide mensajes muy largos en partes
    max_length = 28000  # Teams tiene un límite aproximado
    if len(message) > max_length:
        parts = [message[i:i+max_length] for i in range(0, len(message), max_length)]
        for i, part in enumerate(parts):
            part_msg = f"**Parte {i+1}/{len(parts)}**\n\n{part}"
            try:
                requests.post(
                    TEAMS_WEBHOOK,
                    json={"text": part_msg},
                    headers={"Content-Type": "application/json"},
                    timeout=10
                ).raise_for_status()
            except Exception as e:
                print(f"Error sending to Teams (part {i+1}): {str(e)}")
    else:
        try:
            requests.post(
                TEAMS_WEBHOOK,
                json={"text": message},
                headers={"Content-Type": "application/json"},
                timeout=10
            ).raise_for_status()
        except Exception as e:
            print(f"Error sending to Teams: {str(e)}")

def analyze_competitor_products(domain: str, html: str) -> dict:
    """Analiza la página web del competidor para extraer información sobre productos"""
    if not html or not OPENAI_API_KEY:
        return {"products": [], "features": [], "pricing": [], "target_audience": ""}
    
    # Extraer texto para análisis
    text = extract_text_from_html(html)
    
    # Solicitar análisis a OpenAI
    try:
        product_prompt = (
            f"Analiza la siguiente página web de {domain} y extrae información sobre:\n"
            "1. Productos o servicios ofrecidos\n"
            "2. Características principales\n"
            "3. Precios o modelo de negocio (si se menciona)\n"
            "4. Público objetivo\n\n"
            f"Texto de la página: {text[:4000]}...\n\n"
            "Responde en formato JSON con estas claves: products, features, pricing, target_audience"
        )
        
        resp = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": product_prompt}],
            temperature=0.2,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(resp.choices[0].message.content.strip())
        return result
    except Exception as e:
        print(f"Error analyzing products for {domain}: {str(e)}")
        return {"products": [], "features": [], "pricing": [], "target_audience": ""}

# ── Principal ──
def main():
    state = load_state()
    per_domain = {}
    report = []
    changes = False

    # Fecha y hora del reporte
    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report.append(f"# Reporte de Competidores y Ciberseguridad ({report_date})")
    report.append("")

    # Análisis de competidores
    for domain in DOMAINS:
        section = [f"## Competidor: {domain}", ""]
        html = fetch_site(domain)
        h = sha1(html) if html else "error_fetching"
        prev = state["sites"].get(domain, {})

        section.append("### Revisión de sitio")
        if html:
            diff = diff_html(prev.get("html", ""), html)
            if prev.get("hash") != h and diff:
                section.append(f"- Cambio detectado:\n```diff\n{diff[:500]}...\n```")
                changes = True
                
                # Analizar productos en caso de cambios
                product_analysis = analyze_competitor_products(domain, html)
                if product_analysis.get("products") or product_analysis.get("features"):
                    section.append("\n### Análisis de Productos/Servicios")
                    
                    if product_analysis.get("products"):
                        section.append("#### Productos/Servicios:")
                        for product in product_analysis["products"]:
                            section.append(f"- {product}")
                    
                    if product_analysis.get("features"):
                        section.append("\n#### Características Destacadas:")
                        for feature in product_analysis["features"]:
                            section.append(f"- {feature}")
                    
                    if product_analysis.get("pricing"):
                        section.append("\n#### Modelo de Precios:")
                        for price in product_analysis["pricing"]:
                            section.append(f"- {price}")
                    
                    if product_analysis.get("target_audience"):
                        section.append(f"\n#### Público Objetivo: {product_analysis['target_audience']}")
            else:
                section.append("- Sin cambios detectados.")
        else:
            section.append("- Error al acceder al sitio.")
        section.append("")
        
        if html:
            state["sites"][domain] = {"hash": h, "html": html}

        section.append("### Noticias últimas 24h")
        news = fetch_news(domain)
        new_news = [a for a in news if a["url"] not in state["seen_news"]]
        if new_news:
            for a in new_news:
                section.append(f"- [{a['title']}]({a['url']}) ({a['source']})")
                if a.get("summary"):
                    section.append(f"  > {a['summary']}")
                state["seen_news"].append(a["url"])
            changes = True
        else:
            section.append("- No hay noticias nuevas.")
        section.append("")

        # Tendencias globales - con manejo de errores mejorado
        try:
            trends = fetch_trends(domain)
            per_domain[domain] = trends
            new_trends = [q for q in trends.get("rising_queries", []) if q not in state["seen_trends"]]
            if new_trends:
                section.append("### Nuevas Tendencias búsqueda global (últimos 7d)")
                for q in new_trends:
                    section.append(f"- {q}")
                    state["seen_trends"].append(q)
                changes = True
        except Exception as e:
            print(f"Error processing global trends for {domain}: {str(e)}")
            section.append("### Nuevas Tendencias búsqueda global (últimos 7d)")
            section.append("- Error al obtener tendencias globales")
            
        # Tendencias específicas de Chile - con manejo de errores mejorado
        try:
            cl_trends = fetch_country_trends(domain, "CL")
            new_cl_trends = [q for q in cl_trends.get("rising_queries", []) if q not in state["seen_trends"]]
            if new_cl_trends:
                section.append("\n### Nuevas Tendencias búsqueda en Chile (últimos 7d)")
                for q in new_cl_trends:
                    section.append(f"- {q}")
                    state["seen_trends"].append(q)
                changes = True
        except Exception as e:
            print(f"Error processing Chile trends for {domain}: {str(e)}")
            section.append("\n### Nuevas Tendencias búsqueda en Chile (últimos 7d)")
            section.append("- Error al obtener tendencias para Chile")
            
        section.append("")
        report.extend(section)

    # Noticias de Vulnerabilidades usando la función mejorada
    try:
        vuln_changes = generate_vuln_report(report, state)
        changes = changes or vuln_changes
    except Exception as e:
        print(f"Error generating vulnerability report: {str(e)}")
        report.append("## Noticias de Seguridad")
        report.append("- Error al generar el reporte de vulnerabilidades")
        report.append("")

    # Alertas críticas de la industria
    try:
        alerts = fetch_industry_alerts()
        new_alerts = [a for a in alerts if a["url"] not in state["industry_alerts"]]
        if new_alerts:
            report.append("## Alertas Críticas de la Industria")
            report.append("")
            for alert in new_alerts:
                report.append(f"- [{alert['title']}]({alert['url']}) - {alert['source']} ({alert['date']})")
                state["industry_alerts"].append(alert["url"])
            report.append("")
            changes = True
    except Exception as e:
        print(f"Error fetching industry alerts: {str(e)}")
        report.append("## Alertas Críticas de la Industria")
        report.append("- Error al obtener alertas de la industria")
        report.append("")

    # Mercado
    report.append("## Análisis de Mercado por Tendencias")
    all_rising = Counter()
    for trends in per_domain.values():
        all_rising.update(trends.get("rising_queries", []))
    top_general = [q for q, _ in all_rising.most_common(5) if q not in state["seen_trends"]]
    if top_general:
        for q in top_general:
            report.append(f"- {q}")
            state["seen_trends"].append(q)
        changes = True
    else:
        report.append("- No hay tendencias generales nuevas.")
    report.append("")

    # Si no hay novedades
    if not changes:
        print("Sin novedades hoy. No se envía resumen.")
        save_state(state)
        return

    # Generar resumen con GPT
    header = f"Reporte crudo Competidores y Ciberseguridad ({report_date})\n\n"
    raw_report = header + "\n".join(report)
    
    # Verificar si hay API key de OpenAI
    if OPENAI_API_KEY:
        try:
            prompt = (
                "Eres un asistente experto en análisis competitivo para empresas de ciberseguridad enfocadas en Chile y Latinoamérica.\n"
                "Genera un Resumen Ejecutivo detallado dividido en:\n"
                "1. Hallazgos clave por competidor (cambios en sitios web, nuevos productos/servicios)\n"
                "2. Noticias relevantes de vulnerabilidades (priorizando las de Chile)\n"
                "3. Tendencias del mercado (globales y enfocadas en Chile)\n"
                "4. Recomendaciones estratégicas basadas en los hallazgos\n"
                "5. Alertas y acciones sugeridas\n\n"
                "Destaca cualquier cambio significativo, especialmente relacionado con competidores o amenazas específicas para Chile.\n\n"
                + raw_report
            )

            resp = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
            )
            summary = resp.choices[0].message.content.strip()
        except Exception as e:
            print(f"Error generating summary with OpenAI: {str(e)}")
            summary = f"**REPORTE DE COMPETIDORES Y CIBERSEGURIDAD ({report_date})**\n\n" + raw_report
    else:
        # No hay API key de OpenAI, enviar reporte crudo
        summary = f"**REPORTE DE COMPETIDORES Y CIBERSEGURIDAD ({report_date})**\n\n" + raw_report

    post_to_teams(f"**Daily Competitive Intelligence Report**\n\n{summary}")
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    save_state(state)

if __name__ == "__main__":
    main()