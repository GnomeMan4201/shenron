"""
social_botnet_corpus.py
SHENRON canonical layer — category: identity

Synthetic DEV.to coordinated follow network corpus generator.
Produces inert behavioral fingerprint datasets for testing detection
and governance systems against real-world observed bot patterns.

Patterns sourced from live investigation of @gnomeman4201 follower list,
May 2026. Full writeup: dev.to/gnomeman4201

SHENRON philosophy: generates synthetic/inert signals only.
No accounts created. No API calls. No real platform interaction.

Usage (standalone):
    python3 social_botnet_corpus.py
    python3 social_botnet_corpus.py --tier ghost --count 500 --waves 3
    python3 social_botnet_corpus.py --all-tiers --output corpus.json

Usage (SHENRON):
    python3 shenron.py --run social_botnet_corpus
"""

import argparse
import hashlib
import json
import math
import os
import random
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

# ── SHENRON integration ───────────────────────────────────────────────────────
try:
    from core.engine.payload_registry import register_payload
    _SHENRON_MODE = True
except ImportError:
    # Standalone mode
    def register_payload(name=None, category=None):
        def decorator(fn):
            return fn
        return decorator
    _SHENRON_MODE = False

# ── Constants ─────────────────────────────────────────────────────────────────

LAYER_NAME = "social_botnet_corpus"
LAYER_CATEGORY = "identity"
VERSION = "1.0.0"

# Observed fingerprint tiers from live investigation (May 2026, n=2557)
# Each tier maps to a behavioral cluster with documented prevalence
TIERS = {
    "ghost": {
        "description": "Pure ghost — no bio, no social, no activity",
        "observed_count": 1405,
        "observed_pct": 54.9,
        "bio": False,
        "social_linked": False,
        "posts": 0,
        "comments": 0,
        "avatar_pool": True,       # likely from shared image pool
        "bot_score_range": (55, 85),
        "username_generated_pct": 0.72,
    },
    "semi_dressed": {
        "description": "Bio present, no social links — slightly more credible",
        "observed_count": 578,
        "observed_pct": 22.6,
        "bio": True,
        "social_linked": False,
        "posts": 0,
        "comments": 0,
        "avatar_pool": True,
        "bot_score_range": (35, 60),
        "username_generated_pct": 0.45,
    },
    "credible": {
        "description": "Bio + social linked — premium tier, designed for inspection",
        "observed_count": 314,
        "observed_pct": 12.3,
        "bio": True,
        "social_linked": True,
        "posts": 0,
        "comments": 0,
        "avatar_pool": True,
        "bot_score_range": (25, 50),
        "username_generated_pct": 0.28,
    },
    "mixed": {
        "description": "No bio, social linked — inconsistent identity signals",
        "observed_count": 260,
        "observed_pct": 10.2,
        "bio": False,
        "social_linked": True,
        "posts": 0,
        "comments": 0,
        "avatar_pool": False,
        "bot_score_range": (30, 55),
        "username_generated_pct": 0.35,
    },
}

# Observed registration waves — basis for wave generator
OBSERVED_WAVES = [
    {"label": "Wave 1", "start_offset_days": -16, "duration_days": 7,
     "account_count": 170, "avg_bot_score": 33.9},
    {"label": "Wave 2", "start_offset_days": -8,  "duration_days": 7,
     "account_count": 1352, "avg_bot_score": 44.2},
    {"label": "Wave 3", "start_offset_days": 0,   "duration_days": 7,
     "account_count": 381, "avg_bot_score": 47.1},
]

# Observed follow burst parameters
OBSERVED_BURSTS = [
    {"window_seconds": 102, "account_count": 5, "avg_bot_score": 52,
     "post_trigger_hours": 18.6},
    {"window_seconds": 116, "account_count": 5, "avg_bot_score": 52,
     "post_trigger_hours": 6.3},
    {"window_seconds": 86,  "account_count": 6, "avg_bot_score": 48,
     "post_trigger_hours": 5.1},
    {"window_seconds": 106, "account_count": 5, "avg_bot_score": 47,
     "post_trigger_hours": 13.8},
]

# Username generation patterns observed in corpus
FIRST_NAMES = [
    "james", "john", "anna", "maria", "david", "sarah", "michael", "emma",
    "robert", "lisa", "william", "karen", "richard", "susan", "joseph",
    "jessica", "thomas", "helen", "charles", "ashley", "ali", "omar",
    "fatima", "ahmed", "priya", "raj", "nina", "ivan", "elena", "marco",
    "lucia", "felix", "amara", "kwame", "yuki", "hana", "chen", "wei",
    "aisha", "tariq", "vikram", "ananya", "soren", "ingrid", "pascal",
]

LAST_NAMES = [
    "smith", "jones", "brown", "davis", "wilson", "taylor", "anderson",
    "thomas", "jackson", "white", "harris", "martin", "thompson", "garcia",
    "martinez", "robinson", "clark", "rodriguez", "lewis", "lee", "walker",
    "hall", "allen", "young", "hernandez", "king", "wright", "lopez",
    "hill", "scott", "green", "adams", "baker", "gonzalez", "nelson",
    "carter", "mitchell", "perez", "roberts", "turner", "patel", "sharma",
    "khan", "ali", "ahmed", "hussain", "chen", "wang", "liu", "kim",
]

# Bio templates observed in the bio:present clusters
# These are synthetic approximations of real observed patterns
BIO_TEMPLATES = [
    "Aspiring {role} developer",
    "Learning {stack} every day",
    "{role} | {interest} enthusiast",
    "Building things with {stack}",
    "Developer. Learner. {interest}.",
    "Passionate about {stack} and {interest}",
    "Full stack developer | {interest}",
    "{role} developer based in {location}",
    "Exploring {stack} and modern web",
    "Code. Learn. Repeat.",
    "Software developer | {interest} lover",
    "Turning ideas into {stack} solutions",
    "{interest} | Developer | Open source",
    "Junior {role} developer",
    "Aspiring {role} with a pinch of AI",
]

BIO_VARS = {
    "role": ["full-stack", "backend", "frontend", "Python", "JavaScript",
             "React", "Node.js", "cloud", "DevOps", "mobile"],
    "stack": ["Python", "React", "Node.js", "TypeScript", "Go", "Rust",
              "Vue", "Django", "FastAPI", "AWS", "Kubernetes"],
    "interest": ["AI", "open source", "blockchain", "cybersecurity",
                 "machine learning", "web3", "data science", "DevOps"],
    "location": ["India", "Nigeria", "Brazil", "Pakistan", "Bangladesh",
                 "Indonesia", "Philippines", "Egypt", "Vietnam", "Turkey"],
}

# Avatar pool cluster IDs — synthetic representations of 20 observed pools
AVATAR_POOLS = [f"pool_{i:02d}" for i in range(1, 21)]

# Colors
R = "\033[91m"
Y = "\033[93m"
G = "\033[92m"
C = "\033[96m"
M = "\033[95m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ── Generators ────────────────────────────────────────────────────────────────

def _hex_suffix(length: int = None, seed: int = None) -> str:
    """
    Generate a hex suffix matching observed patterns.
    Length distribution: 8-22 chars, modal at 11-13.
    Hash character distribution is uniform (high entropy).
    """
    if length is None:
        # Weighted toward observed modal range
        weights = [56, 89, 108, 143, 158, 128, 69, 63, 39, 35, 21, 25, 15, 18, 2]
        lengths = list(range(8, 23))
        length = random.choices(lengths, weights=weights)[0]

    if seed is not None:
        # Simulate hash-derived suffix (input unknown, output reproducible)
        salt = random.randbytes(8).hex()
        raw = hashlib.sha256(f"{seed}:{salt}".encode()).hexdigest()
        return raw[:length]
    else:
        return ''.join(random.choices('0123456789abcdef', k=length))


def generate_username(generated: bool = True, seed: int = None) -> str:
    """Generate a synthetic username matching observed patterns."""
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)

    if generated:
        suffix = _hex_suffix(seed=seed)
        return f"{first}_{last}_{suffix}"
    else:
        # Clean username — no suffix
        styles = [
            f"{first}{last}",
            f"{first}_{last}",
            f"{first}{last}{random.randint(1, 999)}",
            f"{first[0]}{last}",
            f"{first}_{last[0]}",
        ]
        return random.choice(styles)


def generate_bio(tier_config: dict) -> Optional[str]:
    """Generate a synthetic bio if tier has bio:True."""
    if not tier_config["bio"]:
        return None
    template = random.choice(BIO_TEMPLATES)
    bio = template
    for key, options in BIO_VARS.items():
        placeholder = f"{{{key}}}"
        if placeholder in bio:
            bio = bio.replace(placeholder, random.choice(options))
    return bio


def generate_avatar(tier_config: dict) -> dict:
    """Generate synthetic avatar metadata."""
    pool = random.choice(AVATAR_POOLS) if tier_config["avatar_pool"] else None
    uid = random.randint(3800000, 3999999)
    img_hash = ''.join(random.choices('0123456789abcdef', k=32))
    return {
        "url_pattern": f"dev-to-uploads.s3.amazonaws.com/uploads/user/profile_image/{uid}/{img_hash}.png",
        "avatar_pool": pool,
        "is_pooled": pool is not None,
    }


def generate_social_links(tier_config: dict) -> dict:
    """Generate synthetic social profile links."""
    if not tier_config["social_linked"]:
        return {"github": None, "twitter": None, "website": None}

    # Most linked accounts only have one social link
    link_type = random.choices(
        ["github_only", "twitter_only", "website_only", "github_twitter"],
        weights=[45, 25, 20, 10]
    )[0]

    uname = generate_username(generated=False)
    return {
        "github": uname if "github" in link_type else None,
        "twitter": uname if "twitter" in link_type else None,
        "website": f"https://{uname}.dev" if "website" in link_type else None,
    }


def generate_account(tier_name: str, joined_at: datetime,
                     seed: int = None) -> dict:
    """Generate a single synthetic account profile."""
    tier = TIERS[tier_name]
    is_generated_username = random.random() < tier["username_generated_pct"]
    uname = generate_username(generated=is_generated_username, seed=seed)
    score_min, score_max = tier["bot_score_range"]

    return {
        "synthetic": True,
        "generator": LAYER_NAME,
        "generator_version": VERSION,
        "tier": tier_name,
        "username": uname,
        "name": " ".join(uname.split("_")[:2]).title() if "_" in uname else uname.title(),
        "bio": generate_bio(tier),
        "joined_at": joined_at.strftime("%B %-d, %Y"),
        "joined_at_iso": joined_at.isoformat(),
        "articles_count": 0,
        "comments_count": 0,
        "social": generate_social_links(tier),
        "avatar": generate_avatar(tier),
        "username_has_hex_suffix": bool(re.search(r'_([a-f0-9]{8,})$', uname)),
        "synthetic_bot_score": random.randint(score_min, score_max),
        "fingerprint": (
            f"bio:{'present' if tier['bio'] else 'empty'}|"
            f"posts:0|comments:0|"
            f"avatar:{'pooled' if tier['avatar_pool'] else 'custom'}|"
            f"social:{'linked' if tier['social_linked'] else 'none'}"
        ),
    }


def generate_registration_wave(wave_config: dict,
                               base_date: datetime,
                               tier_distribution: dict) -> list:
    """
    Generate a synthetic account registration wave.
    wave_config: dict with start_offset_days, duration_days, account_count
    tier_distribution: {tier_name: fraction} — must sum to 1.0
    """
    start = base_date + timedelta(days=wave_config["start_offset_days"])
    duration = timedelta(days=wave_config["duration_days"])
    count = wave_config["account_count"]

    accounts = []
    for i in range(count):
        # Distribute registrations across the wave window
        # Heavier toward middle of wave (bell-ish distribution)
        frac = random.betavariate(2, 2)
        joined = start + timedelta(seconds=duration.total_seconds() * frac)

        # Pick tier based on distribution
        tier = random.choices(
            list(tier_distribution.keys()),
            weights=list(tier_distribution.values())
        )[0]

        acc = generate_account(tier, joined, seed=i)
        acc["wave_label"] = wave_config.get("label", "unknown")
        accounts.append(acc)

    return accounts


def generate_follow_burst(post_published_at: datetime,
                          burst_config: dict) -> list:
    """
    Generate a synthetic follow burst event.
    burst_config: window_seconds, account_count, post_trigger_hours
    """
    trigger_offset = timedelta(hours=burst_config["post_trigger_hours"])
    burst_start = post_published_at + trigger_offset

    events = []
    window = burst_config["window_seconds"]
    for i in range(burst_config["account_count"]):
        follow_ts = burst_start + timedelta(
            seconds=random.uniform(0, window)
        )
        tier = random.choices(
            ["ghost", "semi_dressed", "credible"],
            weights=[0.5, 0.3, 0.2]
        )[0]
        acc = generate_account(tier, follow_ts - timedelta(days=random.randint(1, 20)))
        acc["follow_timestamp"] = follow_ts.isoformat()
        acc["burst_window_seconds"] = window
        acc["post_trigger_hours"] = burst_config["post_trigger_hours"]
        events.append(acc)

    return sorted(events, key=lambda x: x["follow_timestamp"])


# ── Corpus builder ────────────────────────────────────────────────────────────

def build_corpus(
    tiers: list = None,
    count_per_tier: int = 100,
    include_waves: bool = True,
    include_bursts: bool = True,
    base_date: datetime = None,
) -> dict:
    """Build a full synthetic corpus matching observed investigation patterns."""

    if base_date is None:
        base_date = datetime.now(timezone.utc)
    if tiers is None:
        tiers = list(TIERS.keys())

    corpus = {
        "meta": {
            "generator": LAYER_NAME,
            "version": VERSION,
            "generated_at": base_date.isoformat(),
            "source_investigation": "dev.to/gnomeman4201",
            "observation_date": "2026-05-22",
            "observation_n": 2557,
            "synthetic": True,
            "inert": True,
        },
        "tiers": {},
        "waves": [],
        "bursts": [],
        "stats": {},
    }

    # ── Per-tier accounts ─────────────────────────────────────────────────────
    all_accounts = []
    for tier_name in tiers:
        tier_cfg = TIERS[tier_name]
        accounts = []
        for i in range(count_per_tier):
            # Distribute joins across last 30 days
            age_days = random.betavariate(1.5, 5) * 30
            joined = base_date - timedelta(days=age_days)
            acc = generate_account(tier_name, joined, seed=i)
            accounts.append(acc)
        corpus["tiers"][tier_name] = {
            "config": tier_cfg,
            "accounts": accounts,
        }
        all_accounts.extend(accounts)

    # ── Registration waves ────────────────────────────────────────────────────
    if include_waves:
        tier_dist = {
            "ghost": 0.549,
            "semi_dressed": 0.226,
            "credible": 0.123,
            "mixed": 0.102,
        }
        for wave_cfg in OBSERVED_WAVES:
            wave_accounts = generate_registration_wave(
                wave_cfg, base_date, tier_dist
            )
            corpus["waves"].append({
                "label": wave_cfg["label"],
                "start_offset_days": wave_cfg["start_offset_days"],
                "duration_days": wave_cfg["duration_days"],
                "observed_count": wave_cfg["account_count"],
                "observed_avg_bot_score": wave_cfg["avg_bot_score"],
                "synthetic_count": len(wave_accounts),
                "accounts": wave_accounts,
            })

    # ── Follow bursts ─────────────────────────────────────────────────────────
    if include_bursts:
        post_date = base_date - timedelta(days=2)
        for burst_cfg in OBSERVED_BURSTS:
            burst_events = generate_follow_burst(post_date, burst_cfg)
            corpus["bursts"].append({
                "post_published_at": post_date.isoformat(),
                "trigger_hours": burst_cfg["post_trigger_hours"],
                "window_seconds": burst_cfg["window_seconds"],
                "observed_count": burst_cfg["account_count"],
                "observed_avg_bot_score": burst_cfg["avg_bot_score"],
                "events": burst_events,
            })

    # ── Stats ─────────────────────────────────────────────────────────────────
    total = len(all_accounts)
    hex_suffix_count = sum(1 for a in all_accounts if a["username_has_hex_suffix"])
    avatar_pooled = sum(1 for a in all_accounts if a["avatar"]["is_pooled"])

    corpus["stats"] = {
        "total_synthetic_accounts": total,
        "hex_suffix_pct": round(100 * hex_suffix_count / total, 1) if total else 0,
        "avatar_pooled_pct": round(100 * avatar_pooled / total, 1) if total else 0,
        "zero_post_comment_pct": 100.0,  # all synthetic accounts have 0 activity
        "tier_distribution": {
            t: round(100 * len(corpus["tiers"][t]["accounts"]) / total, 1)
            for t in corpus["tiers"]
        } if total else {},
        "wave_count": len(corpus["waves"]),
        "burst_count": len(corpus["bursts"]),
        "total_wave_accounts": sum(w["synthetic_count"] for w in corpus["waves"]),
    }

    return corpus


# ── Terminal display ──────────────────────────────────────────────────────────

def print_corpus_summary(corpus: dict):
    stats = corpus["stats"]
    meta = corpus["meta"]

    print(f"\n{BOLD}{M}  SHENRON // {LAYER_NAME}{RESET}")
    print(f"  {DIM}category: {LAYER_CATEGORY} | v{VERSION}{RESET}\n")

    print(f"  {BOLD}Corpus Summary:{RESET}")
    print(f"  Generated:          {meta['generated_at'][:19].replace('T', ' ')} UTC")
    print(f"  Source observation: n={meta['observation_n']} ({meta['observation_date']})")
    print(f"  Synthetic:          {R}YES — inert patterns only{RESET}\n")

    print(f"  {BOLD}Account Tiers:{RESET}")
    for tier_name, tier_data in corpus["tiers"].items():
        cfg = tier_data["config"]
        count = len(tier_data["accounts"])
        print(f"  {M}  {tier_name:<15}{RESET}  {count:>5} accounts  "
              f"{DIM}(observed: {cfg['observed_count']}){RESET}")
        print(f"  {DIM}  {cfg['description']}{RESET}")

    print(f"\n  {BOLD}Pattern Statistics:{RESET}")
    print(f"  Hex-suffix usernames: {R}{stats['hex_suffix_pct']}%{RESET}  "
          f"{DIM}(observed: 38.2%){RESET}")
    print(f"  Avatar pool members:  {R}{stats['avatar_pooled_pct']}%{RESET}  "
          f"{DIM}(observed: 44% of sample){RESET}")
    print(f"  Zero post/comment:    {R}{stats['zero_post_comment_pct']}%{RESET}  "
          f"{DIM}(observed: 100%){RESET}")

    if corpus["waves"]:
        print(f"\n  {BOLD}Registration Waves:{RESET}")
        for w in corpus["waves"]:
            print(f"  {M}  {w['label']}{RESET}  "
                  f"{w['synthetic_count']} synthetic accounts  "
                  f"{DIM}(observed: {w['observed_count']}){RESET}")

    if corpus["bursts"]:
        print(f"\n  {BOLD}Follow Bursts:{RESET}")
        for b in corpus["bursts"]:
            print(f"  {M}  +{b['trigger_hours']}h post-publish{RESET}  "
                  f"{len(b['events'])} accounts in {b['window_seconds']}s window")

    print(f"\n  {BOLD}Total:{RESET} {stats['total_synthetic_accounts']} synthetic accounts  "
          f"| {stats['wave_count']} waves  "
          f"| {stats['burst_count']} bursts\n")


# ── SHENRON entry point ───────────────────────────────────────────────────────

@register_payload(name=LAYER_NAME, category=LAYER_CATEGORY)
def main():
    """SHENRON entry point — generates default corpus and prints summary."""
    corpus = build_corpus(
        tiers=list(TIERS.keys()),
        count_per_tier=50,
        include_waves=True,
        include_bursts=True,
    )
    print_corpus_summary(corpus)

    # Write corpus to SHENRON data dir if available
    data_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data", "corpora"
    )
    if os.path.isdir(os.path.dirname(data_dir)):
        os.makedirs(data_dir, exist_ok=True)
        out_path = os.path.join(data_dir, f"social_botnet_{int(time.time())}.json")
        with open(out_path, "w") as fh:
            json.dump(corpus, fh, indent=2, default=str)
        print(f"  {G}✓{RESET} Corpus written to {out_path}\n")

    return corpus


# ── Standalone CLI ────────────────────────────────────────────────────────────

def cli():
    parser = argparse.ArgumentParser(
        description="SHENRON social_botnet_corpus — synthetic DEV.to bot fingerprint generator"
    )
    parser.add_argument("--tier", choices=list(TIERS.keys()),
                        help="Generate single tier only")
    parser.add_argument("--all-tiers", action="store_true",
                        help="Generate all tiers (default)")
    parser.add_argument("--count", type=int, default=100,
                        help="Accounts per tier (default: 100)")
    parser.add_argument("--no-waves", action="store_true",
                        help="Skip registration wave generation")
    parser.add_argument("--no-bursts", action="store_true",
                        help="Skip follow burst generation")
    parser.add_argument("--output", metavar="FILE",
                        help="Write corpus JSON to file")
    parser.add_argument("--summary-only", action="store_true",
                        help="Print summary only, no file output")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    tiers = [args.tier] if args.tier else list(TIERS.keys())

    corpus = build_corpus(
        tiers=tiers,
        count_per_tier=args.count,
        include_waves=not args.no_waves,
        include_bursts=not args.no_bursts,
    )

    print_corpus_summary(corpus)

    if not args.summary_only:
        out_path = args.output or f"social_botnet_corpus_{int(time.time())}.json"
        with open(out_path, "w") as fh:
            json.dump(corpus, fh, indent=2, default=str)
        print(f"  {G}✓{RESET} Corpus written to {out_path}\n")


if __name__ == "__main__":
    if _SHENRON_MODE:
        main()
    else:
        cli()
