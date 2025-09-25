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
import gspread
from oauth2client.service_account import ServiceAccountCredentials

# CONFIG
CONCURRENCY = 50
REQUEST_TIMEOUT = 15
RETRIES = 2
OUTPUT_CSV = "domains_result.csv"
OUTPUT_JSON = "domains_result.json"
DOMAINS_FILE = "domains.txt"
GOOGLE_SHEET_URL = "https://docs.google.com/spreadsheets/d/10J67cLWeKQSGrqJL0tdsQ_OFBHLlR2N9DgR3mnyLHng/"
GOOGLE_CREDENTIALS_FILE = "credentials.json"

# MODE SETTINGS
APPEND_MODE = True  # True = добавлять новые результаты к существующим, False = перезаписывать все
SKIP_EXISTING_DOMAINS = True  # True = пропускать домены, которые уже есть в результатах, False = обрабатывать все домены из domains.txt

# ИНСТРУКЦИЯ ПО ИСПОЛЬЗОВАНИЮ:
# 1. APPEND_MODE = True, SKIP_EXISTING_DOMAINS = True - добавляет только новые домены к существующим результатам
# 2. APPEND_MODE = False, SKIP_EXISTING_DOMAINS = True - обрабатывает только новые домены, но перезаписывает файлы полностью
# 3. APPEND_MODE = True, SKIP_EXISTING_DOMAINS = False - обрабатывает все домены из domains.txt и добавляет к существующим
# 4. APPEND_MODE = False, SKIP_EXISTING_DOMAINS = False - полная перезапись всех результатов

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
# Chat widgets/providers presence
GETBUTTON_RE = re.compile(r'getbutton\.io', re.I)
TAWK_RE = re.compile(r'tawk\.to', re.I)
JIVOSITE_RE = re.compile(r'jivosite', re.I)
FACEBOOK_RE = re.compile(r'(?:https?://)?(?:www\.)?(?:facebook\.com|fb\.com)/[A-Za-z0-9_.\-/?=&#]+', re.I)
INSTAGRAM_RE = re.compile(r'(?:https?://)?(?:www\.)?instagram\.com/[A-Za-z0-9_.-]+', re.I)
YOUTUBE_RE = re.compile(r'(?:https?://)?(?:www\.)?(?:youtube\.com|youtu\.be)/[\w@\-/?=&#.]+', re.I)
X_RE = re.compile(r'(?:https?://)?(?:www\.)?x\.com/[A-Za-z0-9_.-]+', re.I)
REDDIT_RE = re.compile(r'(?:https?://)?(?:www\.)?reddit\.com/[A-Za-z0-9_\-/?=&#.]+', re.I)
TIKTOK_RE = re.compile(r'(?:https?://)?(?:www\.)?tiktok\.com/@[A-Za-z0-9_.-]+', re.I)
VK_RE = re.compile(r'(?:https?://)?(?:www\.)?vk\.com/[A-Za-z0-9_.-]+', re.I)
TRUSTPILOT_RE = re.compile(r'(?:https?://)?(?:www\.)?trustpilot\.com/(?:review|evaluate|view)/[A-Za-z0-9_.\-/]+', re.I)
# Analytics detectors
# Google: GA4 gtag id param (G-XXXX...), legacy UA-XXXX-Y, GTM-XXXXXX
GA_GTAG_RE = re.compile(r'googletagmanager\.com/gtag/js\?id=([A-Z]+-[A-Z0-9]+)', re.I)
GA_UA_RE = re.compile(r"['\"](UA-\d{4,}-\d+)['\"]", re.I)
GTM_RE = re.compile(r'GTM-[A-Z0-9]+', re.I)
# Yandex.Metrika: noscript watch/<id>, ym(<id>, 'init'), older yaCounter<id>
YM_WATCH_RE = re.compile(r'mc\.yandex\.ru/watch/(\d+)', re.I)
YM_FUNC_RE = re.compile(r'ym\(\s*(\d{6,})\s*,\s*["\']init["\']', re.I)
YM_COUNTER_RE = re.compile(r'yaCounter(\d{6,})', re.I)

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

# Helper: load existing results
def load_existing_results():
    """Load existing results from CSV and JSON files"""
    existing_domains = set()
    existing_results = []
    
    # Try to load from CSV first
    csv_path = Path(OUTPUT_CSV)
    if csv_path.exists():
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain = row.get('domain', '').strip('"')
                    if domain:
                        existing_domains.add(domain)
                        existing_results.append(row)
        except Exception as e:
            print(f"Warning: Could not load existing CSV results: {e}")
    
    # Try to load from JSON as backup
    json_path = Path(OUTPUT_JSON)
    if json_path.exists() and not existing_results:
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        domain = item.get('domain', '')
                        if domain:
                            existing_domains.add(domain)
                            existing_results.append(item)
        except Exception as e:
            print(f"Warning: Could not load existing JSON results: {e}")
    
    return existing_domains, existing_results

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
    # temporary collectors for phone priority
    wa_phones = []
    tel_phones = []
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
    # tel links (only from anchor href)
    for t in TEL_LINK_RE.findall(html_text):
        raw = t.strip()
        digits_only = re.sub(r'\D', '', raw)
        if len(digits_only) >= 6:
            tel_phones.append("+" + digits_only)
    # telegram
    for tg in TELEGRAM_RE.findall(html_text):
        username = tg.strip().lstrip('@')
        if username:
            found["telegrams"].append(f"https://t.me/{username}")
    # whatsapp: normalize links and extract phone numbers (priority)
    for m in WHATSAPP_URL_RE.finditer(html_text):
        num = m.group('num_api') or m.group('num_wa')
        chat = m.group('chat')
        if num:
            digits_only = re.sub(r'\D', '', num)
            link = f"https://wa.me/{digits_only}"
            found["whatsapps"].append(link)
            # also collect phone number with priority
            if digits_only:
                wa_phones.append("+" + digits_only)
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
    # apply phone priority: use whatsapp numbers if present, else tel numbers
    found["phones"] = wa_phones if wa_phones else tel_phones
    # unique
    for k in found:
        found[k] = list(dict.fromkeys([x for x in found[k] if x]))
    # final email blacklist filter
    found["emails"] = [e for e in found["emails"] if e.lower() not in EMAIL_BLACKLIST]
    return found

def detect_analytics(html_text: str):
    if not html_text:
        return {"ga_ids": [], "ym_ids": []}
    ga_ids = []
    ym_ids = []
    # Google Analytics / Tag
    for m in GA_GTAG_RE.findall(html_text):
        ga_ids.append(m.strip())
    for m in GA_UA_RE.findall(html_text):
        ga_ids.append(m.strip())
    for m in GTM_RE.findall(html_text):
        ga_ids.append(m.strip())
    # Yandex.Metrika
    for m in YM_WATCH_RE.findall(html_text):
        ym_ids.append(m.strip())
    for m in YM_FUNC_RE.findall(html_text):
        ym_ids.append(m.strip())
    for m in YM_COUNTER_RE.findall(html_text):
        ym_ids.append(m.strip())
    # unique
    ga_ids = list(dict.fromkeys([x for x in ga_ids if x]))
    ym_ids = list(dict.fromkeys([x for x in ym_ids if x]))
    return {"ga_ids": ga_ids, "ym_ids": ym_ids}

def detect_chat_widgets(html_text: str):
    if not html_text:
        return {"getbutton": "нет", "tawk": "нет", "jivosite": "нет"}
    has_getbutton = "да" if GETBUTTON_RE.search(html_text) else "нет"
    has_tawk = "да" if TAWK_RE.search(html_text) else "нет"
    has_jivosite = "да" if JIVOSITE_RE.search(html_text) else "нет"
    return {"getbutton": has_getbutton, "tawk": has_tawk, "jivosite": has_jivosite}

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
            "ga_ids": [],
            "ym_ids": [],
            "getbutton": "нет",
            "tawk": "нет",
            "jivosite": "нет",
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
                # analytics
                analytics = detect_analytics(site["content"])
                result["ga_ids"] = analytics["ga_ids"]
                result["ym_ids"] = analytics["ym_ids"]
                # chat widgets
                widgets = detect_chat_widgets(site["content"])
                result["getbutton"] = widgets["getbutton"]
                result["tawk"] = widgets["tawk"]
                result["jivosite"] = widgets["jivosite"]
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
    # Load domains to process
    all_domains = load_domains(DOMAINS_FILE)
    
    # Load existing results if in append mode
    existing_domains = set()
    existing_results = []
    if APPEND_MODE or SKIP_EXISTING_DOMAINS:
        existing_domains, existing_results = load_existing_results()
        print(f"Found {len(existing_domains)} existing domains in results")
    
    # Filter domains based on settings
    if SKIP_EXISTING_DOMAINS:
        domains_to_process = [d for d in all_domains if d not in existing_domains]
        print(f"Processing {len(domains_to_process)} new domains (skipping {len(all_domains) - len(domains_to_process)} existing)")
    else:
        domains_to_process = all_domains
        print(f"Processing {len(domains_to_process)} domains")
    
    if not domains_to_process:
        print("No new domains to process!")
        return
    
    # Process domains
    sem = asyncio.Semaphore(CONCURRENCY)
    connector = aiohttp.TCPConnector(limit_per_host=10, ttl_dns_cache=300)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers={"User-Agent":"Mozilla/5.0 (compatible; domain-scanner/1.0)"}) as session:
        tasks = [process_domain(d, session, sem) for d in domains_to_process]
        # use tqdm_asyncio for progress
        new_results = await tqdm_asyncio.gather(*tasks)

    # Combine results
    if APPEND_MODE:
        all_results = existing_results + new_results
        print(f"Total results: {len(all_results)} ({len(existing_results)} existing + {len(new_results)} new)")
    else:
        all_results = new_results
        print(f"Total results: {len(all_results)}")

    # Save CSV and JSON
    keys = ["domain","site_status","site_url","language","title","description","registration_date","emails","phones","telegrams","whatsapps","facebook","instagram","youtube","x","reddit","tiktok","vk","trustpilot","ga_ids","ym_ids","getbutton","tawk","jivosite","error"]
    
    # CSV - always overwrite with complete data
    async with aiofiles.open(OUTPUT_CSV, "w", encoding="utf-8", newline='') as f:
        await f.write(",".join(keys) + "\n")
        for row in all_results:
            # flatten lists as JSON strings
            csv_row = [row.get(k) if not isinstance(row.get(k), (list,dict)) else json.dumps(row.get(k), ensure_ascii=False) for k in keys]
            line = ",".join('"' + (str(x).replace('"','""') if x is not None else '') + '"' for x in csv_row) + "\n"
            await f.write(line)
    
    # JSON - always overwrite with complete data
    async with aiofiles.open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        await f.write(json.dumps(all_results, ensure_ascii=False, indent=2))

    # Export to Google Sheets
    try:
        await export_to_google_sheets(all_results, keys, append_mode=APPEND_MODE)
    except Exception as e:
        # don't fail the whole run on export error
        print(f"Google Sheets export failed: {e}")

def to_sheet_rows(results, keys):
    header = keys
    rows = [header]
    for row in results:
        values = []
        for k in keys:
            v = row.get(k)
            if isinstance(v, (list, dict)):
                values.append(json.dumps(v, ensure_ascii=False))
            else:
                values.append(v if v is not None else "")
        rows.append(values)
    return rows

async def export_to_google_sheets(results, keys, append_mode=False):
    # Use service account credentials
    scope = [
        'https://spreadsheets.google.com/feeds',
        'https://www.googleapis.com/auth/drive',
    ]
    creds = ServiceAccountCredentials.from_json_keyfile_name(GOOGLE_CREDENTIALS_FILE, scope)
    gc = gspread.authorize(creds)
    sh = gc.open_by_url(GOOGLE_SHEET_URL)

    # Prepare data in memory first
    rows = to_sheet_rows(results, keys)

    # Get the first worksheet
    ws = sh.sheet1
    
    if append_mode:
        # In append mode, only add new rows (skip header)
        new_rows = rows[1:] if len(rows) > 1 else []
        if new_rows:
            # Get existing data to find where to append
            try:
                existing_records = ws.get_all_records()
                existing_domains = {record.get('domain', '') for record in existing_records}
                
                # Filter out rows that already exist
                truly_new_rows = []
                for row in new_rows:
                    domain = row[0] if row else ''  # domain is first column
                    if domain not in existing_domains:
                        truly_new_rows.append(row)
                
                if truly_new_rows:
                    # Append new rows
                    ws.append_rows(truly_new_rows)
                    print(f"Added {len(truly_new_rows)} new rows to Google Sheets")
                else:
                    print("No new rows to add to Google Sheets")
            except Exception as e:
                print(f"Error in append mode, falling back to overwrite: {e}")
                append_mode = False
    
    if not append_mode:
        # Overwrite mode: clear all worksheets, keep first worksheet and overwrite
        # Delete extra worksheets to keep the file clean
        for w in sh.worksheets():
            if w.id != ws.id:
                try:
                    sh.del_worksheet(w)
                except Exception:
                    pass
        # Clear existing data
        ws.clear()
        # Batch update values in one call
        # Determine range size
        num_rows = len(rows)
        num_cols = len(rows[0]) if rows else 0
        if num_rows == 0 or num_cols == 0:
            return
        end_col_letter = chr(ord('A') + num_cols - 1) if num_cols <= 26 else 'Z'
        cell_range = f"A1:{end_col_letter}{num_rows}"
        ws.update(cell_range, rows)
        print(f"Updated Google Sheets with {num_rows} rows")

if __name__ == "__main__":
    asyncio.run(main())
