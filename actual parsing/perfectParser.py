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
CONCURRENCY = 30
REQUEST_TIMEOUT = 15
RETRIES = 2
OUTPUT_CSV = "domains_result.csv"
DOMAINS_FILE = "domains.txt"

# Exclude known non-user emails
EMAIL_BLACKLIST = {
    "61b30ccdbd7bc003a750ee837c497280@sentry.io",
}

# Regex patterns
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', re.I)
PHONE_RE = re.compile(r'(?:(?:\+?\d{1,3})?[\s\-.(]*)?(?:\d{2,4}[\s\-).]*){2,5}\d{2,4}')
TELEGRAM_RE = re.compile(r'(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z0-9_]+)', re.I)
# WhatsApp: capture number or chat code and allow full URL reconstruction
WHATSAPP_URL_RE = re.compile(
    r'(?:https?://)?(?:'
    r'(?:api\.whatsapp\.com/send\?(?:[^\s"\'>]*&)?phone=(?P<num_api>\+?\d+)[^\s"\'>]*)|'
    r'(?:wa\.me/(?P<num_wa>\+?\d+)(?:[^\s"\'>]*)?)|'
    r'(?:chat\.whatsapp\.com/(?P<chat>[A-Za-z0-9_-]+)(?:[^\s"\'>]*)?)'
    r')',
    re.I
)
MAILTO_RE = re.compile(r'href=["\']mailto:([^"\'>\s]+)', re.I)
TEL_LINK_RE = re.compile(r'href=["\']tel:([^"\']+)', re.I)
FACEBOOK_RE = re.compile(r'(?:https?://)?(?:www\.)?(?:facebook\.com|fb\.com)/[A-Za-z0-9_.\-/?=&#]+', re.I)
INSTAGRAM_RE = re.compile(r'(?:https?://)?(?:www\.)?instagram\.com/[A-Za-z0-9_.-]+', re.I)
YOUTUBE_RE = re.compile(r'(?:https?://)?(?:www\.)?(?:youtube\.com|youtu\.be)/[\w@\-/?=&#.]+', re.I)
X_RE = re.compile(r'(?:https?://)?(?:www\.)?x\.com/[A-Za-z0-9_.-]+', re.I)
REDDIT_RE = re.compile(r'(?:https?://)?(?:www\.)?reddit\.com/[A-Za-z0-9_\-/?=&#.]+', re.I)
TIKTOK_RE = re.compile(r'(?:https?://)?(?:www\.)?tiktok\.com/@[A-Za-z0-9_.-]+', re.I)
VK_RE = re.compile(r'(?:https?://)?(?:www\.)?vk\.com/[A-Za-z0-9_.-]+', re.I)
TRUSTPILOT_RE = re.compile(r'(?:https?://)?(?:www\.)?trustpilot\.com/(?:review|evaluate|view)/[A-Za-z0-9_.\-/]+', re.I)

# Language extraction helpers
HTML_LANG_RE = re.compile(r'<html[^>]*\blang=["\']([a-zA-Z]{2,3})(?:-[a-zA-Z0-9-]+)?["\']', re.I)
TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)
META_DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', re.I | re.S)

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
    found = {"emails": [], "phones": [], "telegrams": [], "whatsapps": [],
             "facebook": [], "instagram": [], "youtube": [], "x": [], "reddit": [], "tiktok": [], "vk": [], "trustpilot": []}
    if not html_text:
        return found
    # mailto links
    for m in MAILTO_RE.findall(html_text):
        email_value = m.strip()
        if email_value.lower() not in EMAIL_BLACKLIST:
            found["emails"].append(email_value)
    # emails in text
    for m in EMAIL_RE.findall(html_text):
        email_value = m.strip()
        if email_value.lower() not in EMAIL_BLACKLIST:
            found["emails"].append(email_value)
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
        username = tg.strip().lstrip('@')
        if username:
            found["telegrams"].append(f"https://t.me/{username}")
    # whatsapp: normalize links and extract phone numbers
    for m in WHATSAPP_URL_RE.finditer(html_text):
        num = m.group('num_api') or m.group('num_wa')
        chat = m.group('chat')
        if num:
            digits_only = re.sub(r'\D', '', num)
            link = f"https://wa.me/{digits_only}"
            found["whatsapps"].append(link)
            # also add phone number
            if digits_only:
                found["phones"].append("+" + digits_only)
        elif chat:
            link = f"https://chat.whatsapp.com/{chat}"
            found["whatsapps"].append(link)
    # facebook
    for fb in FACEBOOK_RE.findall(html_text):
        found["facebook"].append(fb if isinstance(fb, str) else fb[0])
    # instagram
    for ig in INSTAGRAM_RE.findall(html_text):
        found["instagram"].append(ig if isinstance(ig, str) else ig[0])
    # youtube
    for yt in YOUTUBE_RE.findall(html_text):
        found["youtube"].append(yt if isinstance(yt, str) else yt[0])
    # x.com
    for x in X_RE.findall(html_text):
        found["x"].append(x if isinstance(x, str) else x[0])
    # reddit
    for rd in REDDIT_RE.findall(html_text):
        found["reddit"].append(rd if isinstance(rd, str) else rd[0])
    # tiktok
    for tk in TIKTOK_RE.findall(html_text):
        found["tiktok"].append(tk if isinstance(tk, str) else tk[0])
    # vk
    for vk in VK_RE.findall(html_text):
        found["vk"].append(vk if isinstance(vk, str) else vk[0])
    # trustpilot
    for tp in TRUSTPILOT_RE.findall(html_text):
        found["trustpilot"].append(tp if isinstance(tp, str) else tp[0])
    # unique
    for k in found:
        found[k] = list(dict.fromkeys([x for x in found[k] if x]))
    # final email blacklist filter
    found["emails"] = [e for e in found["emails"] if e.lower() not in EMAIL_BLACKLIST]
    return found

def detect_language(html_text: str) -> Optional[str]:
    if not html_text:
        return None
    # 1) HTML lang attribute
    m = HTML_LANG_RE.search(html_text)
    if m:
        return m.group(1).lower()
    # 2) Title / Meta description text
    candidates = []
    t = TITLE_RE.search(html_text)
    if t:
        candidates.append(t.group(1))
    d = META_DESC_RE.search(html_text)
    if d:
        candidates.append(d.group(1))
    sample = " ".join(candidates)[:1000]
    # Simple unicode range heuristics
    if re.search(r"[\u0400-\u04FF]", sample):
        return "ru"
    if re.search(r"[\u0600-\u06FF]", sample):
        return "ar"
    if re.search(r"[\u0590-\u05FF]", sample):
        return "he"
    if re.search(r"[\u4E00-\u9FFF]", sample):
        return "zh"
    if re.search(r"[\u3040-\u30FF]", sample):
        return "ja"
    if re.search(r"[\uAC00-\uD7AF]", sample):
        return "ko"
    # Turkish characters
    if re.search(r"[ğüşöçıİĞÜŞÖÇ]", sample):
        return "tr"
    # Default
    return "en"

def extract_title(html_text: str) -> Optional[str]:
    if not html_text:
        return None
    m = TITLE_RE.search(html_text)
    if m:
        # collapse whitespace
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return None

def extract_meta_description(html_text: str) -> Optional[str]:
    if not html_text:
        return None
    m = META_DESC_RE.search(html_text)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return None

# Worker per domain
async def process_domain(domain, session, sem):
    async with sem:
        result = {
            "domain": domain,
            "site_status": "unknown",
            "site_url": "",
            "language": "",
            "title": "",
            "description": "",
            # "txt_records": [],  # DNS временно отключено
            "registration_date": None,
            "emails": [],
            "phones": [],
            "telegrams": [],
            "whatsapps": [],
            "facebook": [],
            "instagram": [],
            "youtube": [],
            "x": [],
            "reddit": [],
            "tiktok": [],
            "vk": [],
            "trustpilot": [],
            "error": None
        }
        try:
            # DNS TXT
            # txts = await get_txt(domain)
            # result["txt_records"] = txts

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
                result["facebook"] = parsed["facebook"]
                result["instagram"] = parsed["instagram"]
                result["youtube"] = parsed["youtube"]
                result["x"] = parsed["x"]
                result["reddit"] = parsed["reddit"]
                result["tiktok"] = parsed["tiktok"]
                result["vk"] = parsed["vk"]
                result["trustpilot"] = parsed["trustpilot"]
                # language detection
                result["language"] = detect_language(site["content"]) or ""
                # title & description
                result["title"] = extract_title(site["content"]) or ""
                result["description"] = extract_meta_description(site["content"]) or ""

            # registration date via WHOIS/RDAP (blocking call inside executor)
            # reg = await get_registration_date(domain)
            # result["registration_date"] = reg

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
        results = await tqdm_asyncio.gather(*tasks)

    # Save CSV and JSON
    keys = ["domain","site_status","site_url","language","title","description","registration_date","emails","phones","telegrams","whatsapps","facebook","instagram","youtube","x","reddit","tiktok","vk","trustpilot","error"]
    # CSV
    async with aiofiles.open(OUTPUT_CSV, "w", encoding="utf-8", newline='') as f:
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
