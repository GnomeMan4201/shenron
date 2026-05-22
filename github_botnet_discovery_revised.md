---
title: I Found a Coordinated GitHub Follow Botnet Hiding in My Followers
published: true
tags: security, github, python, opensource
cover_image: 
description: Eight accounts, six years of creation dates, following counts within a range of 25. Here's how following-list overlap analysis exposed a coordinated inauthentic network that cross-follow detection completely missed.
---

I've been building a personal analytics stack for my GitHub and DEV.to presence — traffic reports, bot audits, the works. While auditing my 97 GitHub followers today, I noticed something in the heuristic scores that didn't add up. Eight accounts, created across different years, flagged for mass following. Nothing unusual on the surface.

Then I looked at the following counts.

```
canestein   → 29,835 following  (created 2015)
hazexone    → 29,857 following  (created 2017)
domcomit    → 29,833 following  (created 2018)
kylehyne    → 29,837 following  (created 2018)
jaderytm    → 29,832 following  (created 2018)
vierystein  → 29,833 following  (created 2019)
hanyvert    → 29,839 following  (created 2020)
mariwatts   → 29,832 following  (created 2021)
```

Eight accounts. Created across a six-year span. Following counts within a range of **25**.

That's a hard pattern to explain organically. GitHub's API and UI both expose following behavior at scale, and accounts that hit a shared ceiling tend to stop there — whether by design or because the automation was never told to go further. Worth noting: it's also *possible* these accounts independently approached a natural platform-level follow limit. What makes this interesting isn't the ceiling alone — it's what the following-list overlap reveals underneath it.

*These are publicly visible GitHub accounts. I am publishing their names because the methodology is only verifiable if the data is reproducible.*

---

## The Naive Test Failed — By Design

First thing I did was check whether they followed each other. Classic botnet detection — if accounts are from the same operator, they often follow each other to build mutual social proof.

```
Cross-follow matrix:
              canestein  hazexone  domcomit  kylehyne  jaderytm  vierystein  hanyvert  mariwatts
canestein         -         no        no        no        no        no          no        no
hazexone         no          -        no        no        no        no          no        no
domcomit         no         no         -        no        no        no          no        no
kylehyne         no         no        no         -        no        no          no        no
jaderytm         no         no        no        no         -        no          no        no
vierystein       no         no        no        no        no         -          no        no
hanyvert         no         no        no        no        no        no           -        no
mariwatts        no         no        no        no        no        no          no         -
```

All zeros. Clean matrix. A naive detector would stop here and clear them.

They do **not** follow each other — which is exactly why a shallow detector would miss them. That's the evasion. The absence of cross-following isn't an innocent signal; it's a design choice.

---

## The Important Signal Wasn't Cross-Following

The important signal was not that these accounts followed each other. They did not. The important signal was that they followed almost the exact same external population. Cross-follow analysis missed the cluster entirely. Following-list overlap exposed it.

I pulled the full following lists for all 8 accounts — ~29,800 entries each, roughly **238,000 following records total** requiring ~2,400 paginated API requests — and computed pairwise Jaccard similarity scores.

```
account_a       account_b         shared    jaccard    a_overlap  b_overlap
jaderytm        mariwatts          29,829    0.9998     0.9999     0.9999
kylehyne        mariwatts          29,831    0.9998     0.9998     1.0000
kylehyne        jaderytm           29,831    0.9998     0.9998     1.0000
domcomit        hanyvert           29,831    0.9997     0.9999     0.9997
canestein       jaderytm           29,828    0.9996     0.9998     0.9999
canestein       mariwatts          29,827    0.9996     0.9997     0.9998
canestein       kylehyne           29,829    0.9995     0.9998     0.9997
jaderytm        vierystein         29,810    0.9985     0.9993     0.9992
vierystein      mariwatts          29,810    0.9985     0.9992     0.9993
kylehyne        vierystein         29,812    0.9985     0.9992     0.9993
canestein       hanyvert           29,813    0.9984     0.9993     0.9991
domcomit        jaderytm           29,808    0.9984     0.9992     0.9992
domcomit        mariwatts          29,807    0.9983     0.9991     0.9992
domcomit        kylehyne           29,809    0.9983     0.9992     0.9991
canestein       vierystein         29,808    0.9983     0.9991     0.9992
canestein       domcomit           29,807    0.9982     0.9991     0.9991
jaderytm        hanyvert           29,807    0.9981     0.9992     0.9989
hanyvert        mariwatts          29,807    0.9981     0.9989     0.9992
kylehyne        hanyvert           29,809    0.9981     0.9991     0.9990
domcomit        vierystein         29,789    0.9971     0.9985     0.9985
vierystein      hanyvert           29,788    0.9968     0.9985     0.9983
hazexone        domcomit           29,732    0.9925     0.9958     0.9966
hazexone        hanyvert           29,730    0.9921     0.9957     0.9963
hazexone        vierystein         29,708    0.9909     0.9950     0.9958
hazexone        jaderytm           29,707    0.9908     0.9950     0.9958
hazexone        mariwatts          29,706    0.9908     0.9949     0.9958
hazexone        kylehyne           29,708    0.9907     0.9950     0.9957
canestein       hazexone           29,706    0.9907     0.9957     0.9949
```

Jaccard similarity of 0.99+ means two sets are nearly identical. Every single pair in this cluster scored above **0.99**.

The cluster-level result:

> **29,682 accounts followed by all 8 members simultaneously.**

Eight accounts, created across six years, following an almost identical list of ~29,800 GitHub users. This pattern is consistent with a shared operator, shared automation pipeline, or shared seed-list source. I'm treating this as behavioral evidence of coordination, not as proof of who controls the accounts.

---

## Reading the Evidence

**Aged accounts** — created 2015-2021, not fresh throwaways. Aged accounts pass basic trust signals because they appear to have history. Whether that aging was deliberate or these are compromised/repurposed accounts is an open question, but from a detection standpoint it's the primary reason shallow heuristics miss them.

**No cross-following** — they do not follow each other. Whether intentional or an artifact of how the automation was written, the effect is the same: it defeats the most common network detection method.

**Identical seed list** — the ~29,682 common follows are the operator's target list. I'm on it. So are ~29,681 other GitHub users. The practical use case for maintaining aged accounts following a curated list of ~30,000 developers: engagement laundering (inflating follower counts on accounts used for phishing or spam campaigns), social proof for repositories seeding malicious packages, or resale as "established" GitHub accounts. The concrete finding here is the shared seed list itself. The downstream use is inference.

**The tell they missed** — following-list overlap. When you avoid cross-following but still use the same seed list, the overlap becomes the fingerprint. The more accounts in a cluster, the stronger the signal — and the harder it is to retroactively randomize without defeating the product.

---

## Alternative Explanations and False Positives

Before calling something coordinated, it is worth asking what else could produce this pattern.

Could these accounts independently follow the same popular list? Possible for one or two pairs at moderate overlap. Not plausible at 0.9998 Jaccard across 29,800 accounts over eight accounts created years apart.

Could a shared import tool or browser extension have seeded them? Theoretically. That would still mean a shared automation pipeline — coordination by another name.

Could one of these be a legitimate account that happened to import a large follow list? Possible individually. The cluster-level result — all eight sharing 29,682 common accounts — rules this out as a coincidence across the group.

I am not proving malicious intent or ownership. I am documenting a statistically anomalous pattern that is consistent with coordinated inauthentic behavior and inconsistent with organic independent activity.

---

## The Detection Method

Naive botnet detection looks for who accounts follow each other. Sophisticated operators defeat this. But they can't easily defeat *what* they follow — because the seed list is the product. Changing it defeats the purpose.

The method:

1. Identify candidate cluster by shared behavioral signatures — following count ceiling, account age spread
2. Fetch full following lists for all candidates
3. Compute pairwise Jaccard similarity
4. Cluster-level intersection to find the common seed

**Signal interpretation:**

| Jaccard Range | Interpretation |
|---|---|
| < 0.50 | No meaningful overlap — likely independent |
| 0.50 – 0.80 | Possible shared source, weak signal |
| 0.80 – 0.95 | Suspicious — warrants deeper analysis |
| 0.95 – 0.99 | Coordination likely — shared automation or seed list |
| > 0.99 | Strong coordination signal — near-identical following behavior |

This generalizes to any platform that exposes following lists via API.

---

## The Code

> **Rate limit note before you run this:** fetching ~29,800 following entries per account costs ~300 API calls. GitHub's authenticated limit is 5,000/hour. Eight accounts at this scale will approach that ceiling — spread runs across rate limit windows if your cluster is larger. GitHub also enforces secondary rate limits on rapid sequential requests *independent* of the hourly cap. If you hit a `403` or `429`, respect the `Retry-After` header before retrying. Increasing `time.sleep()` from `0.1` to `0.5` between pages is safer for large clusters.

The full audit script is in [BANANA_TREE](https://github.com/GnomeMan4201/BANANA_TREE/blob/main/gh_botnet_audit.py). Core logic:

```python
import urllib.request, json, os, time
from itertools import combinations

token = os.environ.get("GH_TOKEN")
headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "gh-botnet-audit"
}

def get_following(login):
    following = set()
    page = 1
    while True:
        url = f"https://api.github.com/users/{login}/following?per_page=100&page={page}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        if not data:
            break
        following.update(u['login'] for u in data)
        if len(data) < 100:
            break
        page += 1
        time.sleep(0.1)
    return following

def jaccard(a, b):
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union else 0

following_sets = {}
for login in cluster:
    following_sets[login] = get_following(login)

for a, b in combinations(cluster, 2):
    shared = len(following_sets[a] & following_sets[b])
    j = jaccard(following_sets[a], following_sets[b])
    print(f"{a:<20} {b:<20} shared={shared} jaccard={j:.4f}")

common = set.intersection(*following_sets.values())
print(f"Followed by ALL accounts: {len(common)}")
```

Run it as: `python3 gh_botnet_audit.py GnomeMan4201`

---

## Reporting

I've reported this cluster to GitHub via their abuse reporting system with the account names, Jaccard scores, and the 29,682 common following count as supporting evidence.

To find candidate clusters in your own followers:

- Multiple accounts with suspiciously similar following counts
- Following count > 500 with no corresponding follower ratio
- Account ages spread across years (evasion signal, not conclusive alone)

The overlap analysis is what turns the heuristic into a defensible finding. The heuristics tell you where to look. The Jaccard matrix is what you bring to a report.

---

## Tools

All tooling used in this research is in [BANANA_TREE](https://github.com/GnomeMan4201/BANANA_TREE):

- `gh_botnet_audit.py` — GitHub follower scoring + overlap analysis
- `traffic_report.py` — GitHub + DEV.to analytics in one terminal run
- Python stdlib only — no external dependencies

---

*This started as a weird follower-audit result. The real lesson is broader: when coordinated accounts avoid obvious links to each other, the shared target population becomes the fingerprint. Cross-following tells you who is connected. Following-list overlap tells you who was seeded from the same map.*

*The accounts named are publicly visible GitHub profiles. If you've run similar analysis on your own followers and found overlapping accounts from this same seed list, drop a comment — I'm curious how wide the network actually is.*
