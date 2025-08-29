import requests
from bs4 import BeautifulSoup
from googlesearch import search
import re
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import logging
import random
import threading

# Configuration
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile Safari/604.1",
]
MAX_RESULTS = 50  # Number of search results to process
MAX_THREADS = 10  # Limit for concurrent threads
CRAWL_DEPTH = 2  # Depth for recursive crawling

# Logging Setup
logging.basicConfig(
    filename="recon_errors.log", level=logging.ERROR, format="%(asctime)s %(levelname)s %(message)s"
)

# Thread-safe queue for results
result_queue = Queue()
lock = threading.Lock()


# Google Search Function
def google_search(query, num_results=10):
    print(f"Searching Google for '{query}'...")
    search_results = []
    try:
        for url in search(query, num_results=num_results):
            search_results.append(url)
    except Exception as e:
        logging.error(f"Error during Google search: {e}")
    return search_results


# Scrape Website Function
def scrape_website(url, name, depth=1):
    if depth > CRAWL_DEPTH:
        return []

    print(f"Scraping {url} at depth {depth}...")
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    try:
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses
        soup = BeautifulSoup(response.text, "html.parser")

        # Extract visible text
        paragraphs = soup.find_all(["p", "div"])
        text = " ".join(p.get_text() for p in paragraphs)

        # Search for name mentions
        matches = re.findall(rf"\b{name}\b", text, re.IGNORECASE)
        if matches:
            result = {
                "url": url,
                "mentions": len(matches),
                "content_preview": " ".join(text.split()[:50]),
            }
            with lock:  # Ensure thread-safe access
                result_queue.put(result)

        # Find additional links for crawling
        links = [a["href"] for a in soup.find_all("a", href=True) if link_valid(a["href"])]
        for link in links[:5]:  # Limit to 5 additional links per page
            scrape_website(link, name, depth + 1)

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error for {url}: {e}")
    except Exception as e:
        logging.error(f"Error scraping {url}: {e}")


# Helper: Validate Links
def link_valid(link):
    return link.startswith("http") and "linkedin.com" not in link and "facebook.com" not in link


# Perform Recon Task
def perform_recon(name):
    query = f'"{name}"'
    search_results = google_search(query, num_results=MAX_RESULTS)

    def process_url(url):
        try:
            scrape_website(url, name)
        except Exception as e:
            logging.error(f"Error processing {url}: {e}")

    # Use ThreadPoolExecutor for controlled concurrency
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(process_url, search_results)

    # Collect all results from the queue
    all_results = []
    while not result_queue.empty():
        all_results.append(result_queue.get())

    return all_results


# Save Results to File
def save_results_to_file(results, filename="results.txt"):
    with open(filename, "w") as file:
        for result in results:
            file.write(f"URL: {result['url']}\n")
            file.write(f"Mentions: {result['mentions']}\n")
            file.write(f"Content Preview: {result['content_preview']}\n")
            file.write("-" * 40 + "\n")
    print(f"Results saved to {filename}")


# Main Execution
if __name__ == "__main__":
    target_name = input("Enter the name to search: ").strip()
    recon_results = perform_recon(target_name)

    print("\n--- Recon Results ---")
    for result in recon_results:
        print(f"URL: {result['url']}")
        print(f"Mentions: {result['mentions']}")
        print(f"Content Preview: {result['content_preview']}")
        print("-" * 40)

    save_results_to_file(recon_results)
