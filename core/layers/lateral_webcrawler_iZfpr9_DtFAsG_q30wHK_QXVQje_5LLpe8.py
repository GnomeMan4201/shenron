from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# lateral_webcrawler.py - SHENRON Lateral Movement Web Crawler

import requests
import socket
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin

TIMEOUT = 3
CRAWL_DEPTH = 2
CRAWL_LOG = os.path.expanduser("~/SHENRON/logs/webcrawler_hits.txt")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def extract_links(url, depth=0):
    links = set()
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup.find_all("a", href=True):
            full_link = urljoin(url, tag["href"])
            if full_link.startswith("http"):
                links.add(full_link)
        if depth > 0:
            for link in list(links):
                links |= extract_links(link, depth-1)
    except:
        pass
    return links

def crawl_subnet(subnet):
    open_hosts = []
    for i in range(1, 255):
        host = f"{subnet}.{i}"
        try:
            r = requests.get(f"http://{host}", timeout=TIMEOUT)
            if r.status_code in [200, 401, 403]:
                open_hosts.append(f"http://{host}")
        except:
            pass
    return open_hosts

@register_payload(name="lateral_webcrawler_iZfpr9_DtFAsG_q30wHK_QXVQje_5LLpe8")
def main():
    print("[*] Scanning local web apps for lateral targets...")
    local_ip = get_local_ip()
    subnet = ".".join(local_ip.split(".")[:3])
    targets = crawl_subnet(subnet)

    with open(CRAWL_LOG, "w") as f:
        for base in targets:
            links = extract_links(base, CRAWL_DEPTH)
            f.write(f"--- {base} ---\n")
            for link in links:
                f.write(link + "\n")
            f.write("\n")
    print(f"[‚úì] Scan complete. Log saved to {CRAWL_LOG}")

if __name__ == "__main__":
    main()

ù <—!Â|ÊÁƒ9*nƒÃX˜å(6á‚TŒﬁ~∆ªª«#MORPHED

m˝ÑÒ‡L›\sêÿ#MORPHED

v·Z∆õ£SFÃX¨ÊÃ1ò/#MORPHED

X„]’∑é|îˇ‚”ﬁtç7_Àπvû?ıçöRÄ÷Ï#MORPHED

≠ö8r§âö˘DŸ¨ vJP°î(‡kŸÌ•Ì‹‰cµzJÖ-Êﬂî√#MORPHED
