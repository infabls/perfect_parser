# save as domain_scan_async.py
import asyncio
import aiofiles
import aiohttp
import aiodns
import csv
import re
import json
import whois  # python-whois, used as fallback for registration date
from dns.asyncresolver import Resolver
from pathlib import Path
from typing import Optional
from tqdm.asyncio import tqdm_asyncio

# CONFIG
CONCURRENCY = 50
REQUEST_TIMEOUT = 15
RETRIES = 2
OUTPUT_CSV = "domains_result.csv"
DOMAINS_FILE = "domains.txt"

# Regex patterns
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', re.I)
PHONE_RE = re.compile(r'(?:(?:\+?\d{1,3})?[\s\-.(]*)?(?:\d{2,4}[\s\-).]*){2,5}\d{2,4}')
TELEGRAM_RE = re.compile(r'(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z0-9_]+)', re.I)
WHATSAPP_RE = re.compile(r'(?:https?://)?(?:(?:api\.whatsapp\.com/send\?phone=)|(?:wa\.me/)|(?:chat\.whatsapp\.com/))([A-Za-z0-9_\-?=&]+)', re.I)
MAILTO_RE = re.compile(r'href=["\']mailto:([^"\'>\s]+)', re.I)
TEL_LINK_RE = re.compile(r'href=["\']tel:([^"\']+)', re.I)

# Async DNS resolver (dnspython)
resolver = Resolver(configure=True)

# Helper: read domains
def load_domains(path: str):
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"{path} not found")
    return [line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]

# HTTP fetch with aiohttp
async def fetch_url(session: aiohttp.ClientSession, url: str, timeout=REQUEST_TIMEOUT) -> Optional[str]:
    for attempt in range(RETRIES + 1):
        try:
            async with session.get(url, ssl=False, timeout=timeout) as resp:
                # only accept text/html
                content_type = resp.headers.get("Content-Type", "")
                text = await resp.text(errors="ignore")
                return text
        except Exception as e:
            if attempt == RETRIES:
                return None
            await asyncio.sleep(0.5 + attempt * 0.5)
    return None

# Check site availability: try https then http
async def check_site(session, domain):
    urls = [f"https://{domain}", f"http://{domain}"]
    for u in urls:
        text = await fetch_url(session, u)
        if text is not None:
            return {"url": u, "status": "up", "content": text}
    return {"url": None, "status": "down", "content": None}

# DNS TXT
async def get_txt(domain):
    try:
        answers = await resolver.resolve(domain, "TXT")
        # answers may be iterable of strings or bytes
        txts = []
        for r in answers:
            # r.strings might be bytes
            try:
                if hasattr(r, "strings"):
                    txts.extend([s.decode() if isinstance(s, (bytes, bytearray)) else str(s) for s in r.strings])
                else:
                    txts.append(str(r))
            except Exception:
                txts.append(str(r))
        return list(set(txts))
    except Exception:
        return []

# RDAP WHOIS via python-whois fallback
async def get_registration_date(domain):
    # First try RDAP via whois library (blocking) in executor or use whois python lib blocking
    loop = asyncio.get_running_loop()
    try:
        data = await loop.run_in_executor(None, whois.whois, domain)
        # whois.whois returns object/dict; try to get creation_date
        cd = data.creation_date
        # sometimes creation_date is list
        if isinstance(cd, list):
            cd = cd[0]
        if cd:
            return str(cd)
    except Exception:
        return None
    return None

# Parse page content for contacts
def parse_contacts(html_text: str):
    found = {"emails": [], "phones": [], "telegrams": [], "whatsapps": []}
    if not html_text:
        return found
    # mailto links
    for m in MAILTO_RE.findall(html_text):
        found["emails"].append(m.strip())
    # emails in text
    for m in EMAIL_RE.findall(html_text):
        found["emails"].append(m.strip())
    # tel links
    for t in TEL_LINK_RE.findall(html_text):
        found["phones"].append(t.strip())
    # phones in text
    for p in PHONE_RE.findall(html_text):
        # filter short matches and non-numeric-only garbage
        cleaned = re.sub(r'[^\d+]', '', p)
        if len(re.sub(r'\D', '', cleaned)) >= 6:
            found["phones"].append(cleaned)
    # telegram
    for tg in TELEGRAM_RE.findall(html_text):
        found["telegrams"].append(tg.strip())
    # whatsapp
    for wa in WHATSAPP_RE.findall(html_text):
        found["whatsapps"].append(wa.strip())
    # unique
    for k in found:
        found[k] = list(dict.fromkeys([x for x in found[k] if x]))
    return found

# Worker per domain
async def process_domain(domain, session, sem):
    async with sem:
        result = {
            "domain": domain,
            "site_status": "unknown",
            "site_url": "",
            "txt_records": [],
            "registration_date": None,
            "emails": [],
            "phones": [],
            "telegrams": [],
            "whatsapps": [],
            "error": None
        }
        try:
            # DNS TXT
            txts = await get_txt(domain)
            result["txt_records"] = txts

            # HTTP site check and parse
            site = await check_site(session, domain)
            result["site_status"] = site["status"]
            result["site_url"] = site["url"] or ""

            if site["content"]:
                parsed = parse_contacts(site["content"])
                result["emails"] = parsed["emails"]
                result["phones"] = parsed["phones"]
                result["telegrams"] = parsed["telegrams"]
                result["whatsapps"] = parsed["whatsapps"]

            # registration date via WHOIS/RDAP (blocking call inside executor)
            reg = await get_registration_date(domain)
            result["registration_date"] = reg

        except Exception as e:
            result["error"] = str(e)
        return result

# Main runner
async def main():
    domains = load_domains(DOMAINS_FILE)
    sem = asyncio.Semaphore(CONCURRENCY)
    connector = aiohttp.TCPConnector(limit_per_host=10, ttl_dns_cache=300)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers={"User-Agent":"Mozilla/5.0 (compatible; domain-scanner/1.0)"}) as session:
        tasks = [process_domain(d, session, sem) for d in domains]
        # use tqdm_asyncio for progress
        results = []
        for r in await tqdm_asyncio.gather(*tasks, return_exceptions=False):
            results.append(r)

    # Save CSV and JSON
    keys = ["domain","site_status","site_url","txt_records","registration_date","emails","phones","telegrams","whatsapps","error"]
    # CSV
    async with aiofiles.open(OUTPUT_CSV, "w", encoding="utf-8", newline='') as f:
        writer = csv.writer(await f.__aenter__())
        await f.write(",".join(keys) + "\n")
        for row in results:
            # flatten lists as JSON strings
            csv_row = [row.get(k) if not isinstance(row.get(k), (list,dict)) else json.dumps(row.get(k), ensure_ascii=False) for k in keys]
            line = ",".join('"' + (str(x).replace('"','""') if x is not None else '') + '"' for x in csv_row) + "\n"
            await f.write(line)
    # also write JSON
    async with aiofiles.open("domains_result.json", "w", encoding="utf-8") as f:
        await f.write(json.dumps(results, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
