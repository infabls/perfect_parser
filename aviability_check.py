import aiohttp
import asyncio
import csv

# Загружаем чёрный список из файла
with open("blacklist.txt") as bl_file:
    blacklist = [line.strip().lower() for line in bl_file if line.strip()]

results = []  # Список для хранения результатов
MAX_CONCURRENT = 50  # Одновременные соединения
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

async def check_domain(session, domain):
    for scheme in ["http", "https"]:
        try:
            async with session.get(f"{scheme}://{domain}", timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                text = await resp.text()
                if resp.history:
                    final_url = str(resp.url).rstrip('/')
                    orig_url = f"{scheme}://{domain}".rstrip('/')
                    if final_url != orig_url:
                        status = f"REDIRECT ({scheme.upper()} {resp.status})"
                        print(f"{domain} — {status}")
                        results.append([domain, status, resp.status])
                        return
                if any(word in text.lower() for word in blacklist):
                    status = f"TECHNICAL ({scheme.upper()} 200)"
                    print(f"{domain} — {status}")
                    results.append([domain, status, resp.status])
                    return
                else:
                    status = f"OK ({scheme.upper()} 200)"
                    print(f"{domain} — {status}")
                    results.append([domain, status, resp.status])
                    return
        except Exception as e:
            pass
    status = "FAIL"
    print(f"{domain} — {status}")
    results.append([domain, status, None])

async def safe_check_domain(session, domain):
    async with semaphore:
        await check_domain(session, domain)

async def main():
    with open("satu.kz.txt") as f:
        domains = [line.strip() for line in f]

    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [safe_check_domain(session, d) for d in domains]
        await asyncio.gather(*tasks)

    # Сохраняем результаты в CSV
    with open('satu.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Domain', 'Status', 'HTTP Code'])
        writer.writerows(results)

asyncio.run(main())
