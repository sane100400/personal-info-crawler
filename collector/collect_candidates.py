#!/usr/bin/env python3
"""Collect and immediately de-identify public-web research candidates.

The script intentionally does not support login, CAPTCHA handling, attachments,
or access-control bypass. Search result pages are used only to discover final
content URLs; they never become dataset samples.
"""

from __future__ import annotations

import argparse
import base64
import copy
import csv
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import random
import re
import secrets
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import (
    parse_qs,
    parse_qsl,
    quote_plus,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

import requests
import trafilatura
import yaml
from bs4 import BeautifulSoup
from openpyxl import load_workbook
from openpyxl.styles import Alignment
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options

SCHEMA = [
    "sample_id",
    "collected_at",
    "source_type",
    "registrable_domain",
    "url_hmac",
    "http_status",
    "final_url_hmac",
    "page_type",
    "live_status",
    "extraction_status",
    "masked_title",
    "masked_text",
    "language_mix",
    "obfuscation_type",
    "intent_label",
    "target_label",
    "contact_label",
    "final_label",
    "evidence_spans",
    "annotator_1",
    "annotator_2",
    "adjudicated_label",
    "near_duplicate_cluster",
    "near_duplicate_fingerprint",
    "campaign_group",
]

LOG_SCHEMA = [
    "url_hmac",
    "query_group",
    "outcome",
    "http_status",
    "reason",
    "attempted_at",
    "text_chars",
    "extraction_method",
]

EXTRACTION_FAILURE_SCHEMA = [
    "url_hmac",
    "query_group",
    "attempted_at",
    "http_status",
    "reason",
    "extraction_status",
    "text_chars",
    "extraction_method",
]

KEYWORD_EXPANSION_SCHEMA = [
    "round_number",
    "query_group",
    "detection_type",
    "query",
    "document_frequency",
    "domain_frequency",
]

SEARCH_HOSTS = {
    "google.com",
    "www.google.com",
    "google.co.kr",
    "www.google.co.kr",
    "bing.com",
    "www.bing.com",
    "search.naver.com",
    "naver.com",
    "www.naver.com",
    "duckduckgo.com",
    "html.duckduckgo.com",
}

BLOCKED_EXTENSIONS = {
    ".7z",
    ".apk",
    ".avi",
    ".bin",
    ".csv",
    ".doc",
    ".docx",
    ".dmg",
    ".exe",
    ".gif",
    ".gz",
    ".hwp",
    ".hwpx",
    ".iso",
    ".jpeg",
    ".jpg",
    ".json",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".msi",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".rar",
    ".tar",
    ".tgz",
    ".torrent",
    ".wav",
    ".webp",
    ".xls",
    ".xlsx",
    ".xml",
    ".xz",
    ".zip",
}

USER_AGENT = (
    "PersonalInfoIllicitPostCrawler/0.1 (public-web; no-login; contact: research-team)"
)
MAX_HTML_BYTES = 1_000_000
MAX_TEXT_CHARS = 20_000
DEFAULT_MIN_TEXT_CHARS = 80
CONNECT_TIMEOUT_SECONDS = 4
READ_TIMEOUT_SECONDS = 10


@dataclass
class Candidate:
    url: str
    query_group: str
    detection_type: str
    source_type: str = "search"
    discovery_text: str = ""
    search_provider: str = ""


@dataclass(frozen=True)
class QuerySpec:
    group: str
    detection_type: str
    query: str


@dataclass(frozen=True)
class KeywordExpansion:
    round_number: int
    query_group: str
    detection_type: str
    query: str
    document_frequency: int
    domain_frequency: int


@dataclass
class CollectionLog:
    url_hmac: str
    query_group: str
    outcome: str
    http_status: str = ""
    reason: str = ""
    text_chars: int = 0
    extraction_method: str = ""
    attempted_at: str = field(
        default_factory=lambda: dt.datetime.now(
            dt.timezone(dt.timedelta(hours=9))
        ).isoformat(timespec="seconds")
    )


@dataclass
class DetectionEntry:
    detected_on: dt.date
    url: str
    detection_type: str
    registrant: str
    note: str = "자동 수집 후보·사람 검토 필요"


class RateLimiter:
    def __init__(self, delay_seconds: float) -> None:
        self.delay = delay_seconds
        self.last_request: dict[str, float] = defaultdict(lambda: 0.0)

    def wait(self, host: str) -> None:
        elapsed = time.monotonic() - self.last_request[host]
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request[host] = time.monotonic()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=int, default=200)
    parser.add_argument("--cdp", default="127.0.0.1:9222")
    parser.add_argument("--out", type=Path, default=Path("output"))
    parser.add_argument("--template", type=Path, default=Path("(양식) 탐지내역.xlsx"))
    parser.add_argument("--registrant", default="", help="탐지내역 양식의 등록자 이름")
    parser.add_argument(
        "--skip-detection-workbook",
        action="store_true",
        help="원 URL 제출용 Excel은 만들지 않고 마스킹된 연구용 CSV만 저장",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--queries",
        type=Path,
        help="비공개 검색어 YAML 파일(예: config/queries.local.yaml)",
    )
    source.add_argument(
        "--seed-file",
        type=Path,
        help="비공개 URL 시드 CSV 또는 줄 단위 텍스트 파일",
    )
    parser.add_argument("--search-delay", type=float, default=3.0)
    parser.add_argument("--domain-delay", type=float, default=2.0)
    parser.add_argument("--search-pages", type=int, default=2)
    parser.add_argument(
        "--search-provider",
        action="append",
        choices=(
            "naver",
            "naver_blog",
            "naver_cafe",
            "naver_kin",
            "naver_news",
            "bing",
            "duckduckgo",
            "google",
            "google_api",
        ),
        help="사용할 검색 공급자(반복 지정 가능, 기본은 전체)",
    )
    parser.add_argument(
        "--google-api-key-env",
        default="GOOGLE_CSE_API_KEY",
        help="Google 검색 API 키를 읽을 환경변수 이름",
    )
    parser.add_argument(
        "--google-cse-id-env",
        default="GOOGLE_CSE_ID",
        help="Google Programmable Search Engine ID를 읽을 환경변수 이름",
    )
    parser.add_argument(
        "--query-variants",
        type=int,
        default=1,
        help="검색어별 자동 변형 개수(1은 원본만 사용)",
    )
    parser.add_argument(
        "--strict-search",
        action="store_true",
        help="검색어에 구문 일치와 일반 문서 제외 조건을 적용",
    )
    parser.add_argument(
        "--relevance-gate",
        choices=("off", "labeling", "review", "strict"),
        default="off",
        help="AI 없이 개인정보 대상·거래·연락 문맥으로 후보를 선별",
    )
    parser.add_argument(
        "--provider-stale-pages",
        type=int,
        default=12,
        help="새 후보가 없을 때 검색 공급자를 바꿀 연속 페이지 수(0은 비활성화)",
    )
    parser.add_argument(
        "--keyword-expansion-rounds",
        type=int,
        default=0,
        help="고관련 검색 요약에서 새 2어절 검색어를 만들어 반복할 횟수",
    )
    parser.add_argument(
        "--keyword-expansion-per-round",
        type=int,
        default=20,
        help="키워드 확장 라운드마다 추가할 최대 검색어 수",
    )
    parser.add_argument(
        "--keyword-expansion-min-domains",
        type=int,
        default=2,
        help="확장 검색어를 채택하는 데 필요한 서로 다른 출처 도메인 수",
    )
    parser.add_argument(
        "--keyword-expansion-require-contact",
        action="store_true",
        help="연락 수단이 함께 나온 대상어 조합만 확장 검색어로 채택",
    )
    parser.add_argument("--min-text-chars", type=int, default=DEFAULT_MIN_TEXT_CHARS)
    parser.add_argument(
        "--min-korean-chars",
        type=int,
        default=0,
        help="제목·본문에 필요한 최소 한글 음절 수(0은 비활성화)",
    )
    parser.add_argument("--checkpoint-every", type=int, default=25)
    parser.add_argument(
        "--follow-links-per-page",
        type=int,
        default=0,
        help="본문 수집에 성공한 페이지에서 추가할 관련 공개 내부 링크 수",
    )
    parser.add_argument(
        "--candidate-pool-limit",
        type=int,
        default=0,
        help="추가 발견을 포함한 최대 후보 수(0은 목표의 4배)",
    )
    parser.add_argument(
        "--max-candidates-per-domain",
        type=int,
        default=100,
        help="내부 링크 확장 시 도메인당 최대 후보 수(0은 제한 없음)",
    )
    parser.add_argument(
        "--max-records-per-domain",
        type=int,
        default=0,
        help="최종 표본에 보존할 도메인별 최대 건수(0은 제한 없음)",
    )
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.target < 1:
        raise ValueError("--target must be at least 1")
    if args.search_pages < 1 or args.search_pages > 20:
        raise ValueError("--search-pages must be between 1 and 20")
    if args.query_variants < 1 or args.query_variants > 10:
        raise ValueError("--query-variants must be between 1 and 10")
    if args.search_delay < 0 or args.domain_delay < 0:
        raise ValueError("Request delays cannot be negative")
    if args.min_text_chars < 40 or args.min_text_chars > MAX_TEXT_CHARS:
        raise ValueError(f"--min-text-chars must be between 40 and {MAX_TEXT_CHARS}")
    if args.min_korean_chars < 0 or args.min_korean_chars > MAX_TEXT_CHARS:
        raise ValueError(f"--min-korean-chars must be between 0 and {MAX_TEXT_CHARS}")
    if args.checkpoint_every < 1 or args.checkpoint_every > 500:
        raise ValueError("--checkpoint-every must be between 1 and 500")
    if args.follow_links_per_page < 0 or args.follow_links_per_page > 20:
        raise ValueError("--follow-links-per-page must be between 0 and 20")
    if args.candidate_pool_limit < 0:
        raise ValueError("--candidate-pool-limit cannot be negative")
    if args.max_candidates_per_domain < 0:
        raise ValueError("--max-candidates-per-domain cannot be negative")
    if args.max_records_per_domain < 0:
        raise ValueError("--max-records-per-domain cannot be negative")
    if args.provider_stale_pages < 0 or args.provider_stale_pages > 1000:
        raise ValueError("--provider-stale-pages must be between 0 and 1000")
    if args.keyword_expansion_rounds < 0 or args.keyword_expansion_rounds > 5:
        raise ValueError("--keyword-expansion-rounds must be between 0 and 5")
    if (
        args.keyword_expansion_per_round < 1
        or args.keyword_expansion_per_round > 100
    ):
        raise ValueError("--keyword-expansion-per-round must be between 1 and 100")
    if (
        args.keyword_expansion_min_domains < 1
        or args.keyword_expansion_min_domains > 20
    ):
        raise ValueError("--keyword-expansion-min-domains must be between 1 and 20")
    if args.seed_file and args.keyword_expansion_rounds:
        raise ValueError("Keyword expansion requires --queries, not --seed-file")
    if args.search_provider and "google_api" in args.search_provider:
        if not os.environ.get(args.google_api_key_env, "").strip():
            raise ValueError(
                f"Google API key environment variable is empty: "
                f"{args.google_api_key_env}"
            )
        if not os.environ.get(args.google_cse_id_env, "").strip():
            raise ValueError(
                f"Google CSE ID environment variable is empty: "
                f"{args.google_cse_id_env}"
            )
    if not args.skip_detection_workbook and not args.registrant.strip():
        raise ValueError("--registrant cannot be empty")


def get_or_create_hmac_key(private_dir: Path) -> bytes:
    private_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(private_dir, 0o700)
    key_path = private_dir / "url_hmac_key"
    if key_path.exists():
        key = key_path.read_bytes().strip()
        if len(key) < 32:
            raise RuntimeError("Existing HMAC key is unexpectedly short")
        return key
    key = secrets.token_hex(32).encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(key_path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key + b"\n")
    return key


def canonicalize_url(raw: str) -> str | None:
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None
    if parts.username or parts.password:
        return None
    path_lower = parts.path.lower()
    if any(path_lower.endswith(ext) for ext in BLOCKED_EXTENSIONS):
        return None
    # Fragments and common analytics parameters do not identify a separate document.
    tracking_names = {"fbclid", "gclid", "dclid", "msclkid", "ref_src"}
    kept = [
        (name, value)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
        if not name.lower().startswith("utm_") and name.lower() not in tracking_names
    ]
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path or "/",
            urlencode(kept),
            "",
        )
    )


def public_content_fallback_url(url: str) -> str | None:
    """Return an equivalent public content URL for known frame-only pages."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    segments = [segment for segment in parts.path.split("/") if segment]
    if host == "blog.naver.com" and len(segments) == 2 and segments[1].isdigit():
        return urlunsplit(
            ("https", "m.blog.naver.com", f"/{segments[0]}/{segments[1]}", "", "")
        )
    return None


def unwrap_search_result_url(raw: str) -> str:
    """Resolve only transparent search redirect encodings, without requesting them."""
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        query = parse_qs(parts.query)
        if host.endswith("bing.com") and parts.path == "/ck/a":
            encoded = query.get("u", [""])[0]
            if encoded.startswith("a1"):
                payload = encoded[2:]
                payload += "=" * (-len(payload) % 4)
                decoded = base64.urlsafe_b64decode(payload).decode("utf-8")
                if decoded.startswith(("http://", "https://")):
                    return decoded
        if host.endswith("google.com") and parts.path == "/url":
            target = query.get("q", [""])[0]
            if target.startswith(("http://", "https://")):
                return target
        if host.endswith("duckduckgo.com") and parts.path.startswith("/l/"):
            target = query.get("uddg", [""])[0]
            if target.startswith(("http://", "https://")):
                return target
    except (ValueError, UnicodeDecodeError):
        pass
    return raw


def registrable_domain(host: str) -> str:
    host = host.lower().strip(".")
    labels = host.split(".")
    common_second_level = {
        "co.kr",
        "or.kr",
        "go.kr",
        "ac.kr",
        "ne.kr",
        "com.au",
        "co.jp",
        "co.uk",
    }
    if len(labels) >= 3 and ".".join(labels[-2:]) in common_second_level:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def url_digest(key: bytes, url: str) -> str:
    return hmac.new(key, url.encode("utf-8", "ignore"), hashlib.sha256).hexdigest()


def is_public_http_url(url: str) -> tuple[bool, str]:
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return False, "unsupported_url"
        port = parts.port or (443 if parts.scheme == "https" else 80)
        infos = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
        if not infos:
            return False, "dns_empty"
        for info in infos:
            address = ipaddress.ip_address(info[4][0])
            if not address.is_global:
                return False, "non_public_address"
        return True, ""
    except (OSError, ValueError):
        return False, "dns_or_url_error"


def connect_browser(cdp_address: str) -> webdriver.Chrome:
    options = Options()
    options.add_experimental_option("debuggerAddress", cdp_address)
    driver = webdriver.Chrome(options=options)
    driver.set_page_load_timeout(25)
    driver.set_script_timeout(10)
    return driver


def disconnect_browser(driver: webdriver.Chrome) -> None:
    """Detach ChromeDriver without closing the externally managed CDP browser."""
    try:
        driver.service.stop()
    except (AttributeError, OSError):
        pass


def load_query_specs(path: Path) -> list[QuerySpec]:
    if not path.exists():
        raise FileNotFoundError(f"Private query file not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    groups = raw.get("groups")
    if not isinstance(groups, list) or not groups:
        raise ValueError("Query YAML must contain a non-empty 'groups' list")
    specs: list[QuerySpec] = []
    names: set[str] = set()
    for item in groups:
        if not isinstance(item, dict):
            raise TypeError("Each query group must be a mapping")
        name = str(item.get("name", "")).strip()
        detection_type = str(item.get("detection_type", "")).strip()
        queries = item.get("queries")
        if not name or not re.fullmatch(r"[a-z0-9_-]+", name):
            raise ValueError(
                "Query group names may contain only lowercase letters, digits, '_' and '-'"
            )
        if name in names:
            raise ValueError(f"Duplicate query group: {name}")
        if detection_type not in DETECTION_TYPES:
            raise ValueError(
                f"Unsupported detection type in group {name}: {detection_type}"
            )
        if not isinstance(queries, list) or not queries:
            raise ValueError(f"Query group {name} must contain at least one query")
        names.add(name)
        for query in queries:
            query = str(query).strip()
            if not query:
                raise ValueError(f"Query group {name} contains an empty query")
            if len(query) > 200:
                raise ValueError(f"Query in group {name} exceeds 200 characters")
            specs.append(QuerySpec(name, detection_type, query))
    return specs


def expand_query_specs(specs: Iterable[QuerySpec], variants: int) -> list[QuerySpec]:
    suffixes = (
        "",
        " 텔레그램",
        " 오픈채팅",
        " 문의",
        " 게시판",
        " 블로그",
        " 연락처",
        " 판매",
        " 구매",
        " 실시간",
    )
    expanded: list[QuerySpec] = []
    seen: set[tuple[str, str]] = set()
    for spec in specs:
        for suffix in suffixes[:variants]:
            query = (spec.query + suffix).strip()
            key = (spec.group, query)
            if key in seen or len(query) > 200:
                continue
            seen.add(key)
            expanded.append(QuerySpec(spec.group, spec.detection_type, query))
    return expanded


SEARCH_NEGATIVE_FILTERS = (
    "-개인정보처리방침 -이용약관 -위키 -로그인 -회원가입 -고객센터 "
    "-뉴스 -기사 -보도 -사건 -판결 -처벌 -법률상담 -예방 -주의 -경고"
)


def constrain_query_specs(specs: Iterable[QuerySpec]) -> list[QuerySpec]:
    """Favor exact illicit-trade phrases and suppress known generic documents."""
    constrained: list[QuerySpec] = []
    seen: set[tuple[str, str]] = set()
    for spec in specs:
        words = spec.query.split()
        candidates = [
            f"{spec.query} {SEARCH_NEGATIVE_FILTERS}",
            f'"{spec.query}" {SEARCH_NEGATIVE_FILTERS}',
        ]
        if len(words) >= 3:
            candidates.extend(
                (
                    f'"{" ".join(words[:2])}" {" ".join(words[2:])} '
                    f"{SEARCH_NEGATIVE_FILTERS}",
                    f'{" ".join(words[:-2])} "{" ".join(words[-2:])}" '
                    f"{SEARCH_NEGATIVE_FILTERS}",
                )
            )
        for query in candidates:
            key = (spec.group, query)
            if key in seen or len(query) > 400:
                continue
            seen.add(key)
            constrained.append(QuerySpec(spec.group, spec.detection_type, query))
    return constrained


def strip_negative_search_terms(query: str) -> str:
    """Remove web-search minus filters for vertical search surfaces."""
    return re.sub(r"\s+-\S+", "", query).strip()


def load_seed_candidates(path: Path) -> list[Candidate]:
    if not path.exists():
        raise FileNotFoundError(f"Private seed file not found: {path}")
    if path.suffix.lower() == ".jsonl":
        return load_candidate_queue(path)
    candidates: dict[str, Candidate] = {}
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or "url" not in reader.fieldnames:
                raise ValueError("Seed CSV requires a 'url' column")
            for row in reader:
                url = canonicalize_url(str(row.get("url", "")).strip())
                detection_type = str(row.get("detection_type") or "기타").strip()
                group = str(row.get("query_group") or "private_seed").strip()
                if not url:
                    continue
                if detection_type not in DETECTION_TYPES:
                    raise ValueError(
                        f"Unsupported seed detection type: {detection_type}"
                    )
                candidates.setdefault(
                    url, Candidate(url, group, detection_type, source_type="seed")
                )
    else:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            url = canonicalize_url(stripped)
            if url:
                candidates.setdefault(
                    url,
                    Candidate(url, "private_seed", "기타", source_type="seed"),
                )
    if not candidates:
        raise ValueError("Seed file did not contain any usable public HTTP(S) URLs")
    return list(candidates.values())


def save_candidate_queue(path: Path, candidates: Iterable[Candidate]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    with path.open("w", encoding="utf-8") as handle:
        for candidate in candidates:
            handle.write(json.dumps(asdict(candidate), ensure_ascii=False) + "\n")
    os.chmod(path, 0o600)


def load_candidate_queue(path: Path) -> list[Candidate]:
    candidates: dict[str, Candidate] = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                candidate = Candidate(
                    url=str(item["url"]),
                    query_group=str(item["query_group"]),
                    detection_type=str(item["detection_type"]),
                    source_type=str(item.get("source_type") or "search"),
                    discovery_text=str(item.get("discovery_text") or ""),
                    search_provider=str(item.get("search_provider") or ""),
                )
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"Invalid candidate queue row {line_number}: {path}"
                ) from exc
            url = canonicalize_url(candidate.url)
            if url:
                candidate.url = url
                candidates.setdefault(url, candidate)
    if not candidates:
        raise ValueError(f"Candidate queue is empty: {path}")
    return list(candidates.values())


def ordered_provider_names(
    available: Iterable[str], requested: Iterable[str] | None
) -> list[str]:
    """Keep CLI provider order while removing duplicates and unknown names."""
    available_names = list(available)
    if requested is None:
        return available_names
    allowed = set(available_names)
    ordered: list[str] = []
    for name in requested:
        if name in allowed and name not in ordered:
            ordered.append(name)
    return ordered


def discover_google_api_candidates(
    session: requests.Session,
    query_specs: list[QuerySpec],
    desired: int,
    pages: int,
    delay: float,
    prefilter_mode: str,
    api_key: str,
    cse_id: str,
    soft_target_multiplier: int = 3,
) -> list[Candidate]:
    """Discover candidates through Google's official JSON API without key logging."""
    found: dict[str, Candidate] = {}
    soft_target = max(desired * soft_target_multiplier, desired + 30)
    for spec in query_specs:
        for page in range(min(pages, 10)):
            try:
                response = session.get(
                    "https://customsearch.googleapis.com/customsearch/v1",
                    params={
                        "key": api_key,
                        "cx": cse_id,
                        "q": spec.query,
                        "start": page * 10 + 1,
                        "num": 10,
                        "hl": "ko",
                        "filter": "0",
                        "fields": "items(link,title,snippet)",
                    },
                    timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
                )
            except requests.RequestException:
                print(
                    "google_api: request failed; stopping without retry bypass",
                    flush=True,
                )
                return [
                    item
                    for item in found.values()
                    if discovery_candidate_passes(item, prefilter_mode)
                ]
            try:
                if response.status_code in {401, 403, 429}:
                    print(
                        f"google_api: HTTP {response.status_code}; "
                        "check credentials, quota, and engine scope",
                        flush=True,
                    )
                    return [
                        item
                        for item in found.values()
                        if discovery_candidate_passes(item, prefilter_mode)
                    ]
                if response.status_code != 200:
                    print(
                        f"google_api: HTTP {response.status_code}; "
                        "stopping provider",
                        flush=True,
                    )
                    return [
                        item
                        for item in found.values()
                        if discovery_candidate_passes(item, prefilter_mode)
                    ]
                try:
                    payload = response.json()
                except requests.exceptions.JSONDecodeError:
                    print("google_api: invalid JSON response", flush=True)
                    return [
                        item
                        for item in found.values()
                        if discovery_candidate_passes(item, prefilter_mode)
                    ]
            finally:
                response.close()

            before_page = len(found)
            for item in payload.get("items") or []:
                url = canonicalize_url(str(item.get("link") or ""))
                if not url:
                    continue
                host = (urlsplit(url).hostname or "").lower()
                if host in SEARCH_HOSTS or host.endswith((".google.com", ".bing.com")):
                    continue
                discovery_text = normalize_extracted_text(
                    str(item.get("title") or "")
                    + "\n"
                    + str(item.get("snippet") or "")
                )[:2_000]
                if not discovery_text:
                    continue
                if url not in found:
                    found[url] = Candidate(
                        url=url,
                        query_group=spec.group,
                        detection_type=spec.detection_type,
                        discovery_text=discovery_text,
                        search_provider="google_api",
                    )
                elif discovery_text not in found[url].discovery_text:
                    found[url].discovery_text = normalize_extracted_text(
                        found[url].discovery_text + "\n" + discovery_text
                    )[:2_000]
            qualified = [
                item
                for item in found.values()
                if discovery_candidate_passes(item, prefilter_mode)
            ]
            print(
                f"google_api {spec.group}: {len(found)} discovered, "
                f"{len(qualified)} qualified (+{len(found) - before_page})",
                flush=True,
            )
            if len(qualified) >= soft_target:
                return qualified
            if len(found) == before_page:
                break
            time.sleep(delay)
    return [
        item
        for item in found.values()
        if discovery_candidate_passes(item, prefilter_mode)
    ]


def discover_candidates(
    driver: webdriver.Chrome,
    query_specs: list[QuerySpec],
    desired: int,
    pages: int,
    delay: float,
    soft_target_multiplier: int = 3,
    prefilter_mode: str = "off",
    providers_enabled: list[str] | None = None,
    provider_stale_pages_limit: int = 12,
) -> list[Candidate]:
    found: dict[str, Candidate] = {}
    broad_queries = [item for item in query_specs if '"' not in item.query]
    phrase_queries = [item for item in query_specs if '"' in item.query]
    # Balance research groups without allowing narrow phrase variants to trigger
    # the provider's stale-result cutoff before broader queries are attempted.
    rng = random.Random(20260817)
    rng.shuffle(broad_queries)
    rng.shuffle(phrase_queries)
    soft_target = max(desired * soft_target_multiplier, desired + 30)

    providers = (
        (
            "naver",
            lambda query, page: (
                "https://search.naver.com/search.naver?where=web&start="
                f"{page * 15 + 1}&query={quote_plus(query)}"
            ),
            ".fds-web-doc-root a[href], "
            ".fds-ugc-single-intention-item-list-rra a[href]",
        ),
        (
            "naver_blog",
            lambda query, page: (
                "https://search.naver.com/search.naver?ssc=tab.blog.all&"
                "where=blog&sm=tab_jum&start="
                f"{page * 7 + 1}&query={quote_plus(strip_negative_search_terms(query))}"
            ),
            "a[href]",
        ),
        (
            "naver_cafe",
            lambda query, page: (
                "https://search.naver.com/search.naver?ssc=tab.cafe.all&"
                "where=cafe&sm=tab_jum&start="
                f"{page * 7 + 1}&query={quote_plus(strip_negative_search_terms(query))}"
            ),
            "a[href]",
        ),
        (
            "naver_kin",
            lambda query, page: (
                "https://search.naver.com/search.naver?ssc=tab.kin.all&"
                "where=kin&sm=tab_jum&start="
                f"{page * 10 + 1}&query={quote_plus(strip_negative_search_terms(query))}"
            ),
            "a[href]",
        ),
        (
            "naver_news",
            lambda query, page: (
                "https://search.naver.com/search.naver?ssc=tab.news.all&"
                "where=news&sm=tab_jum&start="
                f"{page * 10 + 1}&query={quote_plus(strip_negative_search_terms(query))}"
            ),
            ".fds-news-item-list-tab a[href]",
        ),
        (
            "bing",
            lambda query, page: (
                "https://www.bing.com/search?setlang=ko-kr&count=20&first="
                f"{page * 20 + 1}&q={quote_plus(query)}"
            ),
            "li.b_algo h2 a",
        ),
        (
            "duckduckgo",
            lambda query, page: (
                "https://html.duckduckgo.com/html/?kl=kr-kr&s="
                f"{page * 30}&q={quote_plus(query)}"
            ),
            "a.result__a",
        ),
        (
            "google",
            lambda query, page: (
                "https://www.google.com/search?filter=0&num=20&hl=ko&start="
                f"{page * 20}&q={quote_plus(query)}"
            ),
            "a:has(h3)",
        ),
    )
    provider_by_name = {item[0]: item for item in providers}
    selected_provider_names = ordered_provider_names(
        provider_by_name, providers_enabled
    )
    selected_providers = tuple(
        provider_by_name[name] for name in selected_provider_names
    )

    def rotate(items: list[QuerySpec], provider_index: int) -> list[QuerySpec]:
        if not items:
            return []
        provider_count = max(1, len(selected_providers))
        offset = (provider_index * max(1, len(items) // provider_count)) % len(items)
        return items[offset:] + items[:offset]

    for provider_index, (provider_name, make_url, selector) in enumerate(
        selected_providers
    ):
        provider_query_items = rotate(broad_queries, provider_index) + rotate(
            phrase_queries, provider_index
        )
        provider_blocked = False
        provider_stale_pages = 0
        for spec in provider_query_items:
            stale_pages = 0
            for page in range(pages):
                before_page = len(found)
                before_qualified = sum(
                    discovery_candidate_passes(item, prefilter_mode)
                    for item in found.values()
                )
                try:
                    driver.get(make_url(spec.query, page))
                except TimeoutException:
                    try:
                        driver.execute_cdp_cmd("Page.stopLoading", {})
                    except WebDriverException:
                        pass
                except WebDriverException:
                    time.sleep(delay)
                    continue
                try:
                    page_lower = driver.execute_script(
                        "return document.body ? "
                        "document.body.innerText.toLowerCase() : '';"
                    )
                except (TimeoutException, WebDriverException):
                    print(
                        f"{provider_name}: result page unavailable; "
                        "switching provider without retry bypass",
                        flush=True,
                    )
                    provider_blocked = True
                    break
                challenge_markers = (
                    "captcha",
                    "unusual traffic",
                    "verify you are human",
                    "our systems have detected unusual traffic",
                )
                if "sorry" in driver.current_url or any(
                    marker in page_lower for marker in challenge_markers
                ):
                    print(
                        f"{provider_name}: challenge detected; switching provider without bypass",
                        flush=True,
                    )
                    provider_blocked = True
                    break
                try:
                    anchors = driver.execute_script(
                        "return Array.from(document.querySelectorAll(arguments[0]))"
                        ".map(a => ({href:a.href, "
                        "text:(a.innerText || a.textContent || '').trim(), "
                        "ignored:Boolean(a.closest('.sds-comps-profile-source, "
                        ".api_ly_save'))}));",
                        selector,
                    )
                except (TimeoutException, WebDriverException):
                    print(
                        f"{provider_name}: result links unavailable; "
                        "switching provider without retry bypass",
                        flush=True,
                    )
                    provider_blocked = True
                    break
                for anchor in anchors or []:
                    if anchor.get("ignored"):
                        continue
                    raw = str(anchor.get("href") or "")
                    discovery_text = normalize_extracted_text(
                        str(anchor.get("text") or "")
                    )[:1_000]
                    if not discovery_text or discovery_text in {
                        "새 창 열림",
                        "Keep에 저장",
                        "Keep에 바로가기새 창 열림",
                    }:
                        continue
                    raw = unwrap_search_result_url(raw)
                    url = canonicalize_url(raw)
                    if not url:
                        continue
                    host = (urlsplit(url).hostname or "").lower()
                    if host in SEARCH_HOSTS or host.endswith(
                        (".google.com", ".bing.com")
                    ):
                        continue
                    if url not in found:
                        found[url] = Candidate(
                            url=url,
                            query_group=spec.group,
                            detection_type=spec.detection_type,
                            discovery_text=discovery_text,
                            search_provider=provider_name,
                        )
                    elif discovery_text and discovery_text not in found[url].discovery_text:
                        found[url].discovery_text = normalize_extracted_text(
                            found[url].discovery_text + "\n" + discovery_text
                        )[:2_000]
                qualified = (
                    [
                        item
                        for item in found.values()
                        if discovery_candidate_passes(item, prefilter_mode)
                    ]
                    if prefilter_mode != "off"
                    else list(found.values())
                )
                print(
                    f"{provider_name} {spec.group}: {len(found)} discovered, "
                    f"{len(qualified)} qualified "
                    f"(+{len(found) - before_page})",
                    flush=True,
                )
                if len(qualified) >= soft_target:
                    return qualified
                progress_count = (
                    len(qualified) if prefilter_mode != "off" else len(found)
                )
                previous_progress_count = (
                    before_qualified if prefilter_mode != "off" else before_page
                )
                if progress_count == previous_progress_count:
                    provider_stale_pages += 1
                    if (
                        provider_stale_pages_limit
                        and provider_stale_pages >= provider_stale_pages_limit
                    ):
                        print(
                            f"{provider_name}: {provider_stale_pages_limit} pages "
                            "without a new "
                            "candidate; switching provider",
                            flush=True,
                        )
                        provider_blocked = True
                        break
                else:
                    provider_stale_pages = 0
                if len(found) == before_page:
                    stale_pages += 1
                    if stale_pages >= 2:
                        break
                else:
                    stale_pages = 0
                time.sleep(delay)
            if provider_blocked:
                break
    if prefilter_mode != "off":
        return [
            item
            for item in found.values()
            if discovery_candidate_passes(item, prefilter_mode)
        ]
    return list(found.values())


def request_once(
    session: requests.Session,
    url: str,
    limiter: RateLimiter,
    max_redirects: int = 5,
) -> tuple[requests.Response | None, str, str]:
    current = url
    for _ in range(max_redirects + 1):
        safe, reason = is_public_http_url(current)
        if not safe:
            return None, current, reason
        host = urlsplit(current).hostname or ""
        limiter.wait(host)
        try:
            response = session.get(
                current,
                allow_redirects=False,
                timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
                stream=True,
                headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"},
            )
        except requests.RequestException as exc:
            return None, current, type(exc).__name__
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                return None, current, "redirect_without_location"
            next_url = canonicalize_url(urljoin(current, location))
            if not next_url:
                return None, current, "unsafe_redirect"
            current = next_url
            continue
        return response, current, ""
    return None, current, "too_many_redirects"


def robots_allowed(
    session: requests.Session,
    url: str,
    limiter: RateLimiter,
    cache: dict[str, tuple[bool, str]],
) -> tuple[bool, str]:
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    if origin in cache:
        return cache[origin]
    robots_url = origin + "/robots.txt"
    response, _, reason = request_once(session, robots_url, limiter, max_redirects=2)
    if response is None:
        # A network failure is not interpreted as an explicit robots denial.
        result = (True, "robots_unavailable:" + reason)
    elif response.status_code in {401, 403}:
        response.close()
        result = (False, "robots_forbidden")
    elif response.status_code >= 400:
        response.close()
        result = (True, "robots_absent")
    else:
        raw = response.raw.read(256_000, decode_content=True).decode("utf-8", "replace")
        response.close()
        from urllib.robotparser import RobotFileParser

        parser = RobotFileParser()
        parser.set_url(robots_url)
        parser.parse(raw.splitlines())
        allowed = parser.can_fetch(USER_AGENT, url)
        result = (allowed, "robots_allowed" if allowed else "robots_disallowed")
    cache[origin] = result
    return result


def read_html(response: requests.Response) -> tuple[str | None, str]:
    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
        return None, "non_html_content"
    declared = response.headers.get("Content-Length")
    if declared and declared.isdigit() and int(declared) > MAX_HTML_BYTES:
        return None, "content_too_large"
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(64 * 1024):
        total += len(chunk)
        if total > MAX_HTML_BYTES:
            return None, "content_too_large"
        chunks.append(chunk)
    response.encoding = response.encoding or response.apparent_encoding or "utf-8"
    try:
        return b"".join(chunks).decode(response.encoding, "replace"), ""
    except LookupError:
        return b"".join(chunks).decode("utf-8", "replace"), ""


def normalize_extracted_text(value: str | None) -> str:
    text = re.sub(r"[ \t]+", " ", value or "")
    text = re.sub(r"\n[ \t]+", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()[:MAX_TEXT_CHARS]


def extract_title_text(html: str, url: str) -> tuple[str, str, str]:
    soup = BeautifulSoup(html, "lxml")
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()

    # Korean legacy boards often keep the post in a table cell while generic
    # article extraction selects a longer footer. Prefer only selectors that
    # strongly identify an individual post before trying trafilatura.
    strong_post_candidates = [
        normalize_extracted_text(node.get_text("\n", strip=True))
        for selector in (
            ".post-content",
            ".article-content",
            ".article_view",
            ".board_view",
            ".view_content",
            ".view_text",
            ".view_cont",
            ".board_contents",
            ".board-content",
            ".bo_v_con",
            "#bo_v_con",
            "td.con_f",
        )
        for node in soup.select(selector)
    ]
    strong_post_text = max(strong_post_candidates, key=len, default="")
    if len(strong_post_text) >= DEFAULT_MIN_TEXT_CHARS:
        return title[:2_000], strong_post_text, "strong_post_container"

    complex_dom = len(html) > 600_000 or len(soup.find_all(True, limit=5_001)) > 5_000
    precision_text = None
    if not complex_dom:
        precision_text = trafilatura.extract(
            html,
            url=url,
            include_comments=False,
            include_tables=False,
            include_links=False,
            favor_precision=True,
            output_format="txt",
        )
    precision_text = normalize_extracted_text(precision_text)
    if len(precision_text) >= DEFAULT_MIN_TEXT_CHARS:
        return title[:2_000], precision_text, "trafilatura_precision"

    # Short forum posts are often missed by article-focused extraction. Prefer a
    # visible main/article container before falling back to a broader recall pass.
    for node in soup(["script", "style", "noscript", "svg", "nav", "footer", "header"]):
        node.decompose()
    main_candidates = [
        normalize_extracted_text(node.get_text("\n", strip=True))
        for selector in (
            "article",
            "main",
            "[role='main']",
            ".post-content",
            ".post_view",
            ".article-content",
            ".article_view",
            ".board_view",
            "#content",
        )
        for node in soup.select(selector)
    ]
    main_text = max(main_candidates, key=len, default="")
    if len(main_text) >= DEFAULT_MIN_TEXT_CHARS:
        return title[:2_000], main_text, "main_container"

    recall_text = None
    if not complex_dom:
        recall_text = trafilatura.extract(
            html,
            url=url,
            include_comments=False,
            include_tables=False,
            include_links=False,
            favor_recall=True,
            output_format="txt",
        )
    recall_text = normalize_extracted_text(recall_text)
    if len(recall_text) >= DEFAULT_MIN_TEXT_CHARS:
        return title[:2_000], recall_text, "trafilatura_recall"

    body_text = normalize_extracted_text(soup.get_text("\n", strip=True))
    candidates = (
        (precision_text, "trafilatura_precision_short"),
        (main_text, "main_container_short"),
        (recall_text, "trafilatura_recall_short"),
        (body_text, "visible_body_fallback"),
    )
    text, method = max(candidates, key=lambda item: len(item[0]))
    return title[:2_000], text, method


def text_quality_reason(
    text: str, minimum_chars: int, minimum_korean_chars: int = 0, title: str = ""
) -> str:
    if len(text) < minimum_chars:
        return "insufficient_text"
    lowered = text.lower()
    challenge_markers = (
        "verify you are human",
        "checking your browser",
        "enable javascript and cookies to continue",
        "access denied",
        "비정상적인 접근",
        "자동입력 방지",
    )
    if any(marker in lowered for marker in challenge_markers):
        return "challenge_or_access_page"
    tokens = re.findall(r"[가-힣A-Za-z0-9_]{2,}", text)
    if len(tokens) < max(6, minimum_chars // 20):
        return "insufficient_meaningful_tokens"
    if minimum_korean_chars:
        korean_chars = len(re.findall(r"[가-힣]", title + "\n" + text))
        if korean_chars < minimum_korean_chars:
            return "insufficient_korean_text"
    return ""


RELEVANCE_TARGET = re.compile(
    r"(?:고객|회원|보험|대출|주식|부동산|업체|사업자|마케팅|쇼핑몰|성인|토토)\s*"
    r"(?:DB|디비|명단|리스트|정보)|"
    r"(?:개인정보|연락처|전화번호|휴대폰번호|주민등록번호|주민번호|여권|통장|계좌|"
    r"신분증|주민등록증|운전면허증|면허증|외국인등록증)"
    r"(?:\s*(?:DB|디비|명단|리스트))?|"
    r"(?:네이버|다음|카카오|구글|쿠팡|배민|밴드|인스타|페이스북|포털)\s*"
    r"(?:계정|아이디|ID)|"
    r"(?:계정|아이디)\s*(?:판매|팝니다|매입|삽니다|거래)",
    re.IGNORECASE,
)
LABELING_TARGET = re.compile(
    RELEVANCE_TARGET.pattern
    + r"|(?<![A-Za-z0-9])DB(?![A-Za-z0-9])|디비|계정|아이디|"
    r"본인\s*인증|실명\s*인증|비실명|명의|대포\s*통장|리딩방",
    re.IGNORECASE,
)
RELEVANCE_SHORT_TARGET = re.compile(
    r"(?<![가-힣A-Za-z0-9])(?:"
    r"[가-힣]{0,10}(?:디비|아이디|계정)|"
    r"[가-힣]{0,10}(?:DB|ID)|"
    r"[가-힣]{0,10}(?:여권|통장|계좌|신분증|주민등록증|운전면허증|면허증|외국인등록증)"
    r")(?![가-힣A-Za-z0-9])",
    re.IGNORECASE,
)
RELEVANCE_STRICT_TARGET = re.compile(
    r"(?:고객|회원|보험|대출|주식|부동산|업체|사업자|마케팅|쇼핑몰|성인|토토)\s*"
    r"(?:DB|디비|명단|리스트|정보)|"
    r"(?:개인정보|연락처|전화번호|휴대폰번호|주민등록번호|주민번호)\s*"
    r"(?:DB|디비|명단|리스트|판매|팝니다|매입|삽니다|거래|제공)|"
    r"(?:여권|통장|계좌|신분증|주민등록증|운전면허증|면허증|외국인등록증)|"
    r"(?:네이버|다음|카카오|구글|쿠팡|배민|밴드|인스타|인스타그램|페이스북|"
    r"트위터|엑스|틱톡|포털)\s*(?:계정|아이디|ID)|"
    r"(?:대량|다중|실명|비실명|가입|본인|마케팅|광고|디엠|육성|신규)\s*"
    r"(?:계정|아이디|ID)|"
    r"(?:계정|아이디|ID).{0,15}"
    r"(?:대량|다중|실명|비실명|인증|여러|개당|명의|마케팅|광고|디엠)|"
    r"(?:본인|실명|가입)\s*인증(?:\s*(?:계정|아이디|자료))?\s*"
    r"(?:판매|팝니다|매입|삽니다|거래)|"
    r"명의\s*(?:판매|팝니다|매입|삽니다|대여|거래)",
    re.IGNORECASE,
)
RELEVANCE_STRICT_SHORT_TARGET = re.compile(
    r"(?<![가-힣A-Za-z0-9])(?:"
    r"[가-힣]{1,12}(?:디비|DB)|"
    r"(?:여권|통장|계좌|신분증|주민등록증|운전면허증|면허증|외국인등록증)"
    r")(?![가-힣A-Za-z0-9])",
    re.IGNORECASE,
)
RELEVANCE_TRADE = re.compile(
    r"판매|팝니다|매입|삽니다|구매|대량|건당|단가|거래|공급|보유|"
    r"위조|복제|제작|도용|"
    r"최신\s*(?:DB|디비|명단)",
    re.IGNORECASE,
)
RELEVANCE_TITLE_TRADE = re.compile(
    r"판매|팝니다|매입|삽니다|구매|대량|건당|단가|공급|보유|"
    r"위조|복제|제작|도용|"
    r"최신\s*(?:DB|디비|명단)",
    re.IGNORECASE,
)
EXPANSION_CONTACT_TERM = re.compile(
    r"(?<![가-힣A-Za-z0-9])(?:텔레그램|텔그|텔레|telegram|TG|"
    r"오픈채팅|오픈톡|카카오톡|카톡)(?![가-힣A-Za-z0-9])",
    re.IGNORECASE,
)
RELEVANCE_CONTACT = re.compile(
    r"\[(?:EMAIL|PHONE|MESSENGER_ID|ACCOUNT|URL|CONTACT_URL)\]|"
    r"https?://|www\.|(?<!\w)@[A-Za-z0-9_]{3,}|"
    + EXPANSION_CONTACT_TERM.pattern
    + r"|문의\s*[:：]?",
    re.IGNORECASE,
)
RELEVANCE_STRONG_CONTACT = re.compile(
    r"\[(?:EMAIL|PHONE|MESSENGER_ID|ACCOUNT)\]|"
    r"(?<!\w)@[A-Za-z0-9_]{3,}|"
    r"(?:텔레그램|telegram|텔그|텔레|카카오톡|카톡|오픈채팅|라인|line)\s*"
    r"(?:아이디|id|주소|문의|연락|[:：])\s*[@:]?\s*[A-Za-z0-9_.-]{2,}",
    re.IGNORECASE,
)
RELEVANCE_DIRECT_OFFER = re.compile(
    r"판매\s*(?:합니다|해요|중|가능)|팝니다|매입\s*(?:합니다|해요|중|가능)|"
    r"삽니다|구매\s*(?:합니다|해요|원합니다|중|가능)|구합니다|"
    r"제공\s*(?:합니다|해드립니다|드립니다|가능)|공급\s*(?:합니다|가능)|"
    r"납품\s*(?:합니다|가능|시)|취급\s*(?:합니다|중)|보유\s*(?:중|하고|합니다)|"
    r"대량\s*보유|건당|단가|가격\s*[:：]|"
    r"(?:DB|디비|계좌|통장|계정|아이디|여권|신분증|민증)\s*(?:판매|매입)|"
    r"판매\s*(?:업체|전문)|(?:주문|구매|판매|상담)\s*문의|"
    r"문의\s*(?:주세요|주시면|주시기|주십쇼|바랍니다|가능|부탁)|"
    r"(?:위조|제작)\s*(?:가능|전문|의뢰|문의)|"
    r"의뢰\s*(?:받습니다|받아요|주세요|문의)",
    re.IGNORECASE,
)
RELEVANCE_NEGATED_OFFER = re.compile(
    r"(?:판매|매입|구매|거래|대여|제휴)(?:은|는|를)?\s*"
    r"(?:하지|받지)\s*않",
    re.IGNORECASE,
)
RELEVANCE_REPORTING_CONTEXT = re.compile(
    r"뉴스|기사(?:본문)?|보도(?:자료|입니다)?|적발|검거|체포|기소|송치|"
    r"경찰|검찰|법원|판결|선고|혐의|피고인|사건\s*(?:요약|개요)|"
    r"상담사례|법률\s*상담|처벌|대응\s*방법|예방|주의(?:하세요|해야)|경고|"
    r"피해\s*(?:사례|경험담)|사기\s*(?:입니다|당했|피해)|(?:경찰|수사대)에?\s*신고|"
    r"확인\s*방법|궁금(?:합니다|할)|"
    r"(?:할까요|인가요|되나요|있나요|없나요)\s*[?？]?",
    re.IGNORECASE,
)
RELEVANCE_SINGLE_ACCOUNT_CONTEXT = re.compile(
    r"게임\s*계정|FC\s*모바일|로드\s*모바일|피파(?:온라인)?|한게임|순비피|"
    r"구글\s*연동|계정\s*하나|실사용(?:하던)?\s*계정|계정\s*급처|계정\s*스펙",
    re.IGNORECASE,
)
RELEVANCE_EXCLUDED_TITLE = re.compile(
    r"개인정보\s*처리방침|개인정보\s*보호정책|이용약관|서비스\s*약관|"
    r"고객센터|고객지원|도움말|자주\s*묻는\s*질문|FAQ|로그인|회원가입|"
    r"계정\s*만들기|바로가기|사용법|동기화|다운로드|설치|위키|사전|매뉴얼|"
    r"documentation|codelab|고객\s*권리\s*안내|신용정보\s*권리",
    re.IGNORECASE,
)
RELEVANCE_EXCLUDED_DOMAINS = {
    "claude.com",
    "enuri.com",
    "google.com",
    "google.co.kr",
    "kakaocorp.com",
    "messenger.com",
    "minecraft.wiki",
    "privacy.go.kr",
    "snuh.org",
    "thewiki.kr",
    "wikimedia.org",
    "wikipedia.org",
    "wiktionary.org",
}


def nearby_matches(
    left: re.Match[str] | None,
    right: re.Match[str] | None,
    maximum_gap: int = 120,
) -> bool:
    """Return whether two signals occur in the same compact phrase context."""
    if left is None or right is None:
        return False
    gap = max(left.start() - right.end(), right.start() - left.end(), 0)
    return gap <= maximum_gap


def discovery_candidate_relevant(candidate: Candidate) -> bool:
    text = candidate.discovery_text
    if not text:
        return False
    if RELEVANCE_EXCLUDED_TITLE.search(text[:1_000]):
        return False
    target = RELEVANCE_TARGET.search(text) or RELEVANCE_SHORT_TARGET.search(text)
    support = RELEVANCE_TRADE.search(text) or RELEVANCE_CONTACT.search(text)
    return bool(target and support)


def discovery_candidate_passes(candidate: Candidate, mode: str) -> bool:
    """Apply the requested search-snippet prefilter without final labeling."""
    if mode == "off":
        return True
    text = candidate.discovery_text
    if not text or RELEVANCE_EXCLUDED_TITLE.search(text[:1_000]):
        return False
    host = (urlsplit(candidate.url).hostname or "").lower()
    domain = registrable_domain(host)
    if domain in RELEVANCE_EXCLUDED_DOMAINS or domain.endswith(".wiki"):
        return False
    if mode == "labeling":
        # Search snippets can omit the traded object even when the destination
        # title or body contains it. Keep trade-word candidates for annotation,
        # then apply the stricter document-level gate after extraction.
        return bool(LABELING_TARGET.search(text) or RELEVANCE_TRADE.search(text))
    if mode == "strict":
        masked = mask_text(text[:2_000])
        # Search cards may concatenate unrelated result fragments. Require the
        # traded object and a direct offer in one local window, but defer the
        # concrete-contact requirement until the destination page is fetched.
        for start in range(0, len(masked), 180):
            window = masked[start : start + 360]
            if RELEVANCE_REPORTING_CONTEXT.search(window):
                continue
            target = RELEVANCE_STRICT_TARGET.search(
                window
            ) or RELEVANCE_STRICT_SHORT_TARGET.search(window)
            direct_offer = RELEVANCE_DIRECT_OFFER.search(window)
            negated_offer = RELEVANCE_NEGATED_OFFER.search(window)
            if (
                nearby_matches(target, direct_offer)
                and not nearby_matches(direct_offer, negated_offer)
            ):
                return True
            if (
                target
                and RELEVANCE_TRADE.search(window)
                and RELEVANCE_STRONG_CONTACT.search(window)
            ):
                return True
        return False
    return discovery_candidate_relevant(candidate)


def prefilter_seed_candidates(
    candidates: Iterable[Candidate], mode: str
) -> list[Candidate]:
    """Reuse discovery evidence when a prior candidate queue becomes a seed.

    Manually supplied URLs have no discovery text and must still be fetched.
    Prior search queues retain their snippets, so applying the requested gate
    avoids downloading every broad-review candidate again.
    """
    return [
        candidate
        for candidate in candidates
        if not candidate.discovery_text
        or mode == "off"
        or discovery_candidate_passes(candidate, mode)
    ]


def normalized_expansion_query(query: str) -> str:
    """Normalize a query for deduplication without retaining search operators."""
    terms = [
        term.strip('"').lower()
        for term in query.split()
        if term and not term.startswith("-")
    ]
    return " ".join(terms)


def mine_keyword_expansions(
    candidates: Iterable[Candidate],
    known_specs: Iterable[QuerySpec],
    round_number: int,
    limit: int,
    minimum_domains: int,
    require_contact: bool = False,
) -> list[KeywordExpansion]:
    """Mine target/support pairs repeated across high-relevance search snippets."""
    known = {normalized_expansion_query(spec.query) for spec in known_specs}
    documents: defaultdict[str, set[str]] = defaultdict(set)
    domains: defaultdict[str, set[str]] = defaultdict(set)
    metadata: defaultdict[str, Counter[tuple[str, str]]] = defaultdict(Counter)
    display_queries: dict[str, str] = {}
    contact_queries: set[str] = set()

    for candidate in candidates:
        if not discovery_candidate_relevant(candidate):
            continue
        text = mask_text(candidate.discovery_text[:2_000])
        domain = registrable_domain(urlsplit(candidate.url).hostname or "")
        for start in range(0, len(text), 120):
            window = text[start : start + 240]
            targets = {
                normalize_extracted_text(match.group(0))
                for match in RELEVANCE_SHORT_TARGET.finditer(window)
            }
            contact_terms = {
                normalize_extracted_text(match.group(0))
                for match in EXPANSION_CONTACT_TERM.finditer(window)
            }
            trade_terms = {
                normalize_extracted_text(match.group(0))
                for match in RELEVANCE_TRADE.finditer(window)
            }
            support_terms = (
                contact_terms if require_contact else contact_terms | trade_terms
            )
            if not targets or not support_terms:
                continue
            for target in targets:
                for support in support_terms:
                    query = f"{target} {support}".strip()
                    key = normalized_expansion_query(query)
                    if not key or key in known or len(query) > 80:
                        continue
                    documents[key].add(candidate.url)
                    if domain:
                        domains[key].add(domain)
                    metadata[key][
                        (candidate.query_group, candidate.detection_type)
                    ] += 1
                    display_queries.setdefault(key, query)
                    if support in contact_terms:
                        contact_queries.add(key)

    eligible = [
        key for key in documents if len(domains[key]) >= minimum_domains
    ]
    eligible.sort(
        key=lambda key: (
            key in contact_queries,
            len(domains[key]),
            len(documents[key]),
            -len(display_queries[key]),
            display_queries[key],
        ),
        reverse=True,
    )
    expansions: list[KeywordExpansion] = []
    for key in eligible[:limit]:
        query_group, detection_type = metadata[key].most_common(1)[0][0]
        expansions.append(
            KeywordExpansion(
                round_number=round_number,
                query_group=query_group,
                detection_type=detection_type,
                query=display_queries[key],
                document_frequency=len(documents[key]),
                domain_frequency=len(domains[key]),
            )
        )
    return expansions


def merge_candidates(
    current: Iterable[Candidate], additions: Iterable[Candidate]
) -> list[Candidate]:
    """Merge search candidates while preserving all available snippet evidence."""
    merged: dict[str, Candidate] = {}
    for candidate in [*current, *additions]:
        existing = merged.get(candidate.url)
        if existing is None:
            merged[candidate.url] = candidate
            continue
        if (
            candidate.discovery_text
            and candidate.discovery_text not in existing.discovery_text
        ):
            existing.discovery_text = normalize_extracted_text(
                existing.discovery_text + "\n" + candidate.discovery_text
            )[:2_000]
        existing_providers = {
            name for name in existing.search_provider.split(",") if name
        }
        additional_providers = {
            name for name in candidate.search_provider.split(",") if name
        }
        if additional_providers - existing_providers:
            existing.search_provider = ",".join(
                sorted(existing_providers | additional_providers)
            )
    return list(merged.values())


def discovery_relevance_score(candidate: Candidate) -> int:
    """Rank search-result documents without assigning a final label."""
    text = candidate.discovery_text[:2_000]
    if not text:
        return -100
    score = 0
    target_count = min(4, len(RELEVANCE_TARGET.findall(text)))
    trade_count = min(4, len(RELEVANCE_TRADE.findall(text)))
    contact_count = min(3, len(RELEVANCE_CONTACT.findall(text)))
    score += target_count * 5 + trade_count * 3 + contact_count * 2
    if target_count and (trade_count or contact_count):
        score += 10
    if RELEVANCE_EXCLUDED_TITLE.search(text):
        score -= 20
    host = (urlsplit(candidate.url).hostname or "").lower()
    domain = registrable_domain(host)
    if domain in RELEVANCE_EXCLUDED_DOMAINS or domain.endswith(".wiki"):
        score -= 20
    return score


def relevance_gate_reason(
    title: str,
    text: str,
    url: str,
    page_type: str,
    mode: str,
    discovery_text: str = "",
) -> str:
    """Return an exclusion reason, or an empty string for a retained candidate."""
    if page_type in {
        "search_result_list",
        "search_reflection",
        "deleted_or_inaccessible",
    }:
        return "excluded_page_type"
    # Structural exclusions are always active. ``off`` disables topical
    # filtering only; it must not turn search-result pages into samples.
    if mode == "off":
        return ""
    if mode == "strict" and page_type == "news_or_education":
        return "excluded_page_type"
    host = (urlsplit(url).hostname or "").lower()
    domain = registrable_domain(host)
    if domain in RELEVANCE_EXCLUDED_DOMAINS or domain.endswith(".wiki"):
        return "excluded_domain"
    if mode == "strict" and host.endswith((".ac.kr", ".go.kr")):
        return "excluded_institutional_domain"
    title_and_lead = title + "\n" + text[:800]
    # These are title indicators, not arbitrary body stop words. Genuine
    # channels commonly contain "바로가기" or "위키" in nearby link text.
    if RELEVANCE_EXCLUDED_TITLE.search(title):
        return "excluded_document_type"

    if mode == "strict" and RELEVANCE_REPORTING_CONTEXT.search(title_and_lead):
        return "excluded_reporting_context"
    if mode == "strict" and RELEVANCE_SINGLE_ACCOUNT_CONTEXT.search(title_and_lead):
        return "excluded_single_account_trade"

    if mode == "labeling":
        # Keep topical positives and hard negatives for human annotation. The
        # stronger review/strict modes remain available for precision-first runs.
        title_has_target = bool(LABELING_TARGET.search(title))
        title_has_trade = bool(RELEVANCE_TITLE_TRADE.search(title))
        title_has_contact = bool(RELEVANCE_CONTACT.search(title))
        lead_has_target = bool(LABELING_TARGET.search(text[:1_000]))
        if title_has_target or title_has_trade:
            return ""
        if title_has_contact and lead_has_target:
            return ""
        return "missing_relevant_target"

    title_has_target = bool(
        RELEVANCE_TARGET.search(title) or RELEVANCE_SHORT_TARGET.search(title)
    )
    title_has_trade = bool(RELEVANCE_TITLE_TRADE.search(title))
    title_has_contact = bool(RELEVANCE_CONTACT.search(title))
    if mode != "strict" and (
        not title_has_target or not (title_has_trade or title_has_contact)
    ):
        return "missing_title_signal"

    combined = title + "\n" + text
    best_signals: set[str] = set()
    weak_complete_window = False
    # Signals must occur in the same local window. This prevents a long generic
    # privacy policy from passing because unrelated words occur far apart.
    for start in range(0, len(combined), 250):
        window = combined[start : start + 500]
        signals = set()
        target_pattern = (
            RELEVANCE_STRICT_TARGET if mode == "strict" else RELEVANCE_TARGET
        )
        short_target_pattern = (
            RELEVANCE_STRICT_SHORT_TARGET
            if mode == "strict"
            else RELEVANCE_SHORT_TARGET
        )
        target = target_pattern.search(window) or short_target_pattern.search(window)
        if target:
            signals.add("target")
        if RELEVANCE_TRADE.search(window):
            signals.add("trade")
        contact_pattern = (
            RELEVANCE_STRONG_CONTACT if mode == "strict" else RELEVANCE_CONTACT
        )
        if contact_pattern.search(window):
            signals.add("contact")
        if len(signals) > len(best_signals):
            best_signals = signals
        if mode == "strict" and signals == {"target", "trade", "contact"}:
            direct_offer = RELEVANCE_DIRECT_OFFER.search(window)
            negated_offer = RELEVANCE_NEGATED_OFFER.search(window)
            if (
                nearby_matches(target, direct_offer)
                and not nearby_matches(direct_offer, negated_offer)
            ):
                return ""
            weak_complete_window = True
        if (
            mode == "review"
            and "target" in signals
            and len(signals) >= 2
            and title_has_target
            and (title_has_trade or title_has_contact)
        ):
            return ""
    if "target" not in best_signals:
        return "missing_relevant_target"
    if mode == "strict":
        # The destination body must independently show the traded object and
        # a direct offer. Search-result text may supply a contact omitted by
        # extraction, but must never make an unrelated landing page pass.
        body_has_offer = False
        for start in range(0, len(combined), 250):
            window = combined[start : start + 500]
            target = RELEVANCE_STRICT_TARGET.search(
                window
            ) or RELEVANCE_STRICT_SHORT_TARGET.search(window)
            direct_offer = RELEVANCE_DIRECT_OFFER.search(window)
            negated_offer = RELEVANCE_NEGATED_OFFER.search(window)
            if (
                target
                and RELEVANCE_TRADE.search(window)
                and nearby_matches(target, direct_offer)
                and not nearby_matches(direct_offer, negated_offer)
            ):
                body_has_offer = True
                break
        if not body_has_offer:
            return "missing_body_offer"
        if discovery_text:
            discovery = mask_text(discovery_text[:2_000])
            for start in range(0, len(discovery), 180):
                window = discovery[start : start + 360]
                target = RELEVANCE_STRICT_TARGET.search(
                    window
                ) or RELEVANCE_STRICT_SHORT_TARGET.search(window)
                if target and RELEVANCE_STRONG_CONTACT.search(window):
                    return ""
        if "contact" not in best_signals:
            return "missing_concrete_contact"
        if weak_complete_window:
            return "missing_direct_offer"
        return "missing_trade_or_contact_signal"
    return "missing_supporting_signal"


def discover_related_internal_links(
    html: str, base_url: str, limit: int
) -> list[str]:
    if limit <= 0:
        return []
    base = urlsplit(base_url)
    base_host = base.hostname or ""
    base_domain = registrable_domain(base_host)
    base_parent = base.path.rsplit("/", 1)[0]
    topic_terms = re.compile(
        r"개인정보|고객|DB|디비|계정|ID|아이디|판매|구매|"
        r"텔레그램|텔그|오픈채팅|문의|회원|여권|통장|실명",
        re.IGNORECASE,
    )
    content_path = re.compile(
        r"/(?:board|boards|bbs|post|posts|article|articles|view|read|detail|entry|blog)/|"
        r"(?:^|[/_-])(?:board|bbs|post|article|view|read|detail|idx)(?:[/_.?=&-]|$)",
        re.IGNORECASE,
    )
    blocked_path = re.compile(
        r"/(?:login|logout|signup|register|account|admin|download|attachment|file)/?",
        re.IGNORECASE,
    )
    scored: dict[str, int] = {}
    soup = BeautifulSoup(html, "lxml")
    for anchor in soup.select("a[href]"):
        raw = str(anchor.get("href") or "").strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        url = canonicalize_url(urljoin(base_url, raw))
        if not url or url == base_url:
            continue
        parts = urlsplit(url)
        if registrable_domain(parts.hostname or "") != base_domain:
            continue
        if blocked_path.search(parts.path):
            continue
        params = {name.lower() for name, _ in parse_qsl(parts.query)}
        if params & {"q", "query", "keyword", "search", "searchword"}:
            continue
        anchor_text = anchor.get_text(" ", strip=True)
        score = 0
        if topic_terms.search(anchor_text):
            score += 3
        if topic_terms.search(parts.path):
            score += 2
        if content_path.search(parts.path):
            score += 2
        if base_parent and base_parent != "/" and parts.path.startswith(base_parent):
            score += 1
        # Same-directory and generic content-path matches alone are not topical.
        # Require an explicit topic term in the anchor text or target path.
        if score > 0 and (
            topic_terms.search(anchor_text) or topic_terms.search(parts.path)
        ):
            scored[url] = max(scored.get(url, 0), score)
    return [
        url
        for url, _ in sorted(scored.items(), key=lambda item: (-item[1], item[0]))[
            :limit
        ]
    ]


def mask_text(value: str) -> str:
    if not value:
        return ""
    text = value
    # Preserve the existence and channel of direct messenger contacts while
    # removing the handle itself. Generic URLs are masked separately below.
    text = re.sub(
        r"(?i)(?:https?://)?(?:t\.me|telegram\.me)/[A-Za-z0-9_.+-]{2,}",
        "텔레그램 [MESSENGER_ID]",
        text,
    )
    text = re.sub(
        r"(?i)(?:https?://)?(?:open\.kakao\.com|pf\.kakao\.com)/[A-Za-z0-9_./?=&+-]+",
        "카카오톡 [MESSENGER_ID]",
        text,
    )
    text = re.sub(
        r"(?i)(?:https?://)?line\.me/[A-Za-z0-9_./?=&+-]+",
        "라인 [MESSENGER_ID]",
        text,
    )
    # Order matters: remaining URLs and emails must be removed before generic IDs.
    text = re.sub(
        r"(?i)(?:https?://|www\.)[^\s<>\"']+",
        "[CONTACT_URL]",
        text,
    )
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL]", text)
    text = re.sub(r"(?<!\d)(?:\d{6}\s*[-–]?\s*[1-4]\d{6})(?!\d)", "[NATIONAL_ID]", text)
    text = re.sub(
        r"(?<!\d)(?:01[016789]|02|0[3-6][1-5])[- .]?\d{3,4}[- .]?\d{4}(?!\d)",
        "[PHONE]",
        text,
    )
    text = re.sub(
        r"(?<!\d)(?:\+?82[- .]?)?1[016789][- .]?\d{3,4}[- .]?\d{4}(?!\d)",
        "[PHONE]",
        text,
    )
    text = re.sub(
        r"(?i)(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", "[IP_ADDRESS]", text
    )
    text = re.sub(
        r"(?i)(텔레그램|telegram|텔그|텔레|카카오톡|카톡|오픈채팅|라인|line)\s*(?:아이디|id|주소|문의|[:：])?\s*[@:]?\s*[A-Za-z0-9_.-]{3,}",
        lambda m: m.group(1) + " [MESSENGER_ID]",
        text,
    )
    text = re.sub(r"(?<!\w)@[A-Za-z0-9_]{3,}(?!\w)", "[ACCOUNT]", text)
    text = re.sub(
        r"(?i)(아이디|ID|계정명|닉네임|사용자명)\s*[:：=]\s*[A-Za-z0-9_.-]{2,}",
        lambda m: m.group(1) + ": [ACCOUNT]",
        text,
    )
    text = re.sub(
        r"(이름|성명|예금주)\s*[:：=]\s*[가-힣]{2,4}",
        lambda m: m.group(1) + ": [NAME]",
        text,
    )
    text = re.sub(
        r"(계좌(?:번호)?|입금계좌)\s*[:：=]?\s*(?:\d[- ]?){9,16}\d",
        lambda m: m.group(1) + ": [BANK_ACCOUNT]",
        text,
    )
    # Any remaining long digit sequence is not useful research content.
    text = re.sub(r"(?<!\d)\d{10,16}(?!\d)", "[NUMERIC_IDENTIFIER]", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = text.strip()
    # CSV quoting alone does not stop spreadsheet applications from evaluating cells.
    if text.startswith(("=", "+", "-", "@")):
        text = "'" + text
    return text


def language_mix(text: str) -> str:
    has_ko = bool(re.search(r"[가-힣]", text))
    has_en = bool(re.search(r"[A-Za-z]", text))
    if has_ko and has_en:
        return "ko_en_mixed"
    if has_ko:
        return "ko"
    if has_en:
        return "en"
    return "other"


def obfuscation_type(text: str) -> str:
    flags = []
    if re.search(r"[ㅏ-ㅣㄱ-ㅎ]{2,}", text):
        flags.append("jamo")
    if re.search(r"\w[._*·-]\w[._*·-]\w", text):
        flags.append("symbol_separated")
    if re.search(r"[A-Za-z].*[가-힣]|[가-힣].*[A-Za-z]", text):
        flags.append("mixed_script")
    return "+".join(flags) if flags else "none"


def classify_page_type(url: str, title: str, text: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path_query = (parts.path + "?" + parts.query).lower()
    combined = (title + "\n" + text[:2_000]).lower()
    if re.search(
        r"(?:^|[/_?&=-])(search|query|keyword|find|input|results?)"
        r"(?:[/_?&=-]|$)",
        path_query,
    ):
        params = parse_qs(parts.query)
        reflected_values = [
            value.lower().strip()
            for key, values in params.items()
            if key.lower()
            in {
                "q",
                "query",
                "keyword",
                "search",
                "searchword",
                "search_query",
                "s",
                "i",
                "text",
                "term",
                "wd",
            }
            for value in values
            if len(value.strip()) >= 4
        ]
        if any(value in combined for value in reflected_values):
            return "search_reflection"
        return "search_result_list"
    if re.search(
        r"번호\s*제목\s*작성자\s*작성일(?:\s*(?:추천|조회))*",
        text[:1_500],
        re.IGNORECASE,
    ):
        return "search_result_list"
    if any(
        term in combined
        for term in (
            "삭제된 게시물",
            "존재하지 않는 게시물",
            "페이지를 찾을 수 없습니다",
        )
    ):
        return "deleted_or_inaccessible"
    if any(
        term in combined
        for term in ("뉴스", "보도자료", "교육자료", "예방 수칙", "피해 사례")
    ):
        return "news_or_education"
    if host in {"t.me", "telegram.me", "www.telegram.me"}:
        return "public_messenger_page"
    return "unknown"


def near_duplicate_id(masked_title: str, masked_text: str) -> str:
    tokens = re.findall(
        r"[가-힣A-Za-z0-9_]{2,}", (masked_title + " " + masked_text).lower()
    )[:2_000]
    if not tokens:
        return ""
    weights = [0] * 64
    # Repeated sales phrases are common in these pages. Hash each distinct token
    # once and apply its frequency as a weight; this is equivalent to the former
    # per-occurrence loop and materially reduces CPU work on long copied posts.
    for token, count in Counter(tokens).items():
        value = int.from_bytes(
            hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big"
        )
        for bit in range(64):
            weights[bit] += count if value & (1 << bit) else -count
    fingerprint = sum((1 << bit) for bit, weight in enumerate(weights) if weight >= 0)
    return f"simhash64:{fingerprint:016x}"


def contact_campaign_id(key: bytes, raw_text: str) -> str:
    patterns = (
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        r"(?<!\d)(?:01[016789]|02|0[3-6][1-5])[- .]?\d{3,4}[- .]?\d{4}(?!\d)",
        r"(?i)(?:https?://|www\.)[^\s<>\"']+",
        r"(?<!\w)@[A-Za-z0-9_]{3,}(?!\w)",
        r"(?i)(?:텔레그램|telegram|텔그|텔레|카카오톡|카톡|오픈채팅|라인|line)\s*(?:아이디|id|주소|문의|[:：])?\s*[@:]?\s*[A-Za-z0-9_.-]{3,}",
    )
    contacts = {
        re.sub(r"\s+", "", match.group(0)).lower().rstrip(".,;)")
        for pattern in patterns
        for match in re.finditer(pattern, raw_text)
    }
    if not contacts:
        return ""
    payload = "\n".join(sorted(contacts))
    return (
        "contact-hmac:"
        + hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    )


def make_record(
    index: int,
    candidate: Candidate,
    final_url: str,
    http_status: int,
    title: str,
    text: str,
    key: bytes,
) -> dict[str, object]:
    masked_title = mask_text(title)
    masked_text = mask_text(text)
    fingerprint = near_duplicate_id(masked_title, masked_text)
    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).isoformat(
        timespec="seconds"
    )
    record: dict[str, object] = {name: "" for name in SCHEMA}
    record.update(
        {
            "sample_id": f"EG-{index:06d}",
            "collected_at": now,
            "source_type": candidate.source_type,
            "registrable_domain": registrable_domain(
                urlsplit(final_url).hostname or ""
            ),
            "url_hmac": url_digest(key, candidate.url),
            "http_status": http_status,
            "final_url_hmac": url_digest(key, final_url),
            "page_type": classify_page_type(final_url, masked_title, masked_text),
            "live_status": "accessible",
            "extraction_status": "success",
            "masked_title": masked_title,
            "masked_text": masked_text,
            "language_mix": language_mix(masked_title + "\n" + masked_text),
            "obfuscation_type": obfuscation_type(masked_title + "\n" + masked_text),
            "intent_label": "",
            "target_label": "",
            "contact_label": "",
            "final_label": "uncertain",
            "evidence_spans": "{}",
            # Keep the old field during the handoff transition. Both values are
            # fingerprints, not precomputed duplicate cluster identifiers.
            "near_duplicate_cluster": fingerprint,
            "near_duplicate_fingerprint": fingerprint,
            "campaign_group": contact_campaign_id(key, title + "\n" + text),
        }
    )
    return record


def existing_hashes(csv_path: Path) -> set[str]:
    if not csv_path.exists():
        return set()
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        return {
            row["url_hmac"] for row in csv.DictReader(handle) if row.get("url_hmac")
        }


def existing_fingerprints(csv_path: Path) -> set[str]:
    """Load fingerprints already retained, including older handoff files."""
    if not csv_path.exists():
        return set()
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        return {
            fingerprint
            for row in csv.DictReader(handle)
            if (
                fingerprint := (
                    row.get("near_duplicate_fingerprint")
                    or row.get("near_duplicate_cluster")
                    or ""
                )
            )
        }


def next_sample_index(csv_path: Path) -> int:
    """Return an unused numeric suffix, including after interrupted resumes."""
    if not csv_path.exists():
        return 1
    maximum = 0
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            match = re.fullmatch(r"EG-(\d+)", row.get("sample_id", ""))
            if match:
                maximum = max(maximum, int(match.group(1)))
    return maximum + 1


def existing_success_domains(csv_path: Path) -> set[str]:
    if not csv_path.exists():
        return set()
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        return {
            row["registrable_domain"]
            for row in csv.DictReader(handle)
            if row.get("registrable_domain")
        }


def existing_success_domain_counts(csv_path: Path) -> Counter[str]:
    if not csv_path.exists():
        return Counter()
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        return Counter(
            row["registrable_domain"]
            for row in csv.DictReader(handle)
            if row.get("registrable_domain")
        )


def terminal_attempt_hashes(log_path: Path) -> set[str]:
    if not log_path.exists():
        return set()
    terminal: set[str] = set()
    with log_path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            digest = row.get("url_hmac", "")
            outcome = row.get("outcome", "")
            reason = row.get("reason", "")
            status = row.get("http_status", "")
            if not digest or outcome == "success":
                continue
            if outcome == "skipped":
                terminal.add(digest)
                continue
            if reason in {
                "insufficient_text",
                "insufficient_meaningful_tokens",
                "insufficient_korean_text",
                "challenge_or_access_page",
            }:
                terminal.add(digest)
                continue
            if reason == "http_status" and status.isdigit():
                code = int(status)
                if 400 <= code < 500 and code not in {408, 429}:
                    terminal.add(digest)
    return terminal


def append_csv(
    path: Path, records: Iterable[dict[str, object]], fieldnames: list[str]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        if not exists:
            writer.writeheader()
        writer.writerows(records)
    os.chmod(path, 0o600)


def upgrade_existing_csv_schema(path: Path) -> None:
    """Add newly standardized columns before appending to an older run."""
    if not path.exists():
        return
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        old_fields = reader.fieldnames or []
    if old_fields == SCHEMA:
        return
    if not old_fields or not set(old_fields).issubset(SCHEMA):
        raise RuntimeError("Existing output schema is incompatible with this collector")
    temp_path = path.with_suffix(path.suffix + ".upgrade.tmp")
    with temp_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SCHEMA)
        writer.writeheader()
        for row in rows:
            row.setdefault("extraction_status", "success")
            if row.get("live_status") == "true":
                row["live_status"] = "accessible"
            row["source_type"] = {
                "public_web_search": "search",
                "private_seed": "seed",
            }.get(row.get("source_type", ""), row.get("source_type", "") or "search")
            row["page_type"] = {
                "reflected_search_page": "search_reflection",
                "cached_or_deleted": "deleted_or_inaccessible",
            }.get(row.get("page_type", ""), row.get("page_type", ""))
            row.setdefault(
                "near_duplicate_fingerprint", row.get("near_duplicate_cluster", "")
            )
            writer.writerow(row)
    os.chmod(temp_path, 0o600)
    temp_path.replace(path)


def upgrade_collection_log_schema(path: Path) -> None:
    if not path.exists():
        return
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        old_fields = reader.fieldnames or []
    if old_fields == LOG_SCHEMA:
        return
    if not old_fields or not set(old_fields).issubset(LOG_SCHEMA):
        raise RuntimeError("Existing collection log schema is incompatible")
    temp_path = path.with_suffix(path.suffix + ".upgrade.tmp")
    with temp_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LOG_SCHEMA)
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(temp_path, 0o600)
    temp_path.replace(path)


def extraction_status_for_failure(reason: str, text_chars: int) -> str:
    if reason == "non_html_content":
        return "non_html"
    if reason in {"challenge_or_access_page", "dynamic_render_failure"}:
        return "dynamic_render_failure"
    if reason == "insufficient_meaningful_tokens":
        return "boilerplate_only"
    if reason == "insufficient_text":
        return "partial" if text_chars else "empty"
    if reason == "encoding_failure":
        return "encoding_failure"
    return "other_failure"


def extraction_failure_record(log: CollectionLog) -> dict[str, object] | None:
    extraction_reasons = {
        "non_html_content",
        "content_too_large",
        "insufficient_text",
        "insufficient_meaningful_tokens",
        "insufficient_korean_text",
        "challenge_or_access_page",
        "dynamic_render_failure",
        "encoding_failure",
    }
    if log.outcome == "success" or log.reason not in extraction_reasons:
        return None
    return {
        "url_hmac": log.url_hmac,
        "query_group": log.query_group,
        "attempted_at": log.attempted_at,
        "http_status": log.http_status,
        "reason": log.reason,
        "extraction_status": extraction_status_for_failure(
            log.reason, log.text_chars
        ),
        "text_chars": log.text_chars,
        "extraction_method": log.extraction_method,
    }


RESIDUAL_PATTERNS = {
    "email": r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    "phone": r"(?<!\d)(?:01[016789]|02|0[3-6][1-5])[- .]?\d{3,4}[- .]?\d{4}(?!\d)",
    "national_id": r"(?<!\d)\d{6}\s*[-–]?\s*[1-4]\d{6}(?!\d)",
    "http_url": r"(?i)https?://\S+",
}


def masking_validation(csv_path: Path, dataset_version: str) -> dict[str, object]:
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    joined = "\n".join(
        row.get("masked_title", "") + "\n" + row.get("masked_text", "")
        for row in rows
    )
    hits = {
        name: len(re.findall(pattern, joined))
        for name, pattern in RESIDUAL_PATTERNS.items()
    }
    return {
        "dataset_version": dataset_version,
        "checked_rows": len(rows),
        **{f"residual_{name}_hits": count for name, count in hits.items()},
        "manual_reviewed_rows": 0,
        "manual_review_failures": 0,
        "passed": not any(hits.values()),
        "generated_at": dt.datetime.now(
            dt.timezone(dt.timedelta(hours=9))
        ).isoformat(timespec="seconds"),
    }


def write_restricted_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(path, 0o600)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def csv_row_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def collection_log_metrics(path: Path) -> dict[str, object]:
    if not path.exists():
        return {
            "attempted_candidates": 0,
            "outcome_counts": {},
            "attempt_reconciliation_passed": True,
        }
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    outcomes = Counter(row.get("outcome", "") for row in rows)
    expected = sum(outcomes.get(name, 0) for name in ("success", "failed", "skipped"))
    return {
        "attempted_candidates": len(rows),
        "outcome_counts": dict(outcomes),
        "attempt_reconciliation_passed": expected == len(rows),
    }


def collector_code_version() -> dict[str, str]:
    script_path = Path(__file__).resolve()
    result = {"collector_sha256": sha256_file(script_path)}
    try:
        root = script_path.parents[1]
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", str(script_path)],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        result["git_commit"] = commit + ("+dirty" if dirty else "")
    except (OSError, subprocess.SubprocessError):
        result["git_commit"] = "unknown"
    return result


def data_manifest(
    out_dir: Path,
    dataset_version: str,
    paths: Iterable[Path],
    settings: dict[str, object],
) -> dict[str, object]:
    files = []
    for path in paths:
        if not path.exists():
            continue
        item: dict[str, object] = {
            "path": str(path.relative_to(out_dir)),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        if path.suffix.lower() == ".csv":
            item["rows"] = csv_row_count(path)
        files.append(item)
    return {
        "dataset_version": dataset_version,
        "generated_at": dt.datetime.now(
            dt.timezone(dt.timedelta(hours=9))
        ).isoformat(timespec="seconds"),
        "code_version": collector_code_version(),
        "settings": settings,
        "field_compatibility": {
            "near_duplicate_cluster": (
                "legacy alias of near_duplicate_fingerprint; "
                "value is a SimHash fingerprint"
            ),
        },
        "files": files,
    }


DETECTION_TYPES = {"개인정보DB", "여권 및 통장", "포털ID", "해킹대행", "기타"}


def infer_detection_type(configured_type: str, title: str, text: str) -> str:
    combined = (title + "\n" + text[:4_000]).lower()
    if configured_type != "기타":
        return configured_type
    if re.search(r"여권|통장|계좌|passport|bank", combined):
        return "여권 및 통장"
    if re.search(r"포털|네이버|다음|구글|portal", combined):
        return "포털ID"
    if re.search(r"해킹\s*(?:대행|의뢰)|hack(?:ing)?\s*(?:service|for hire)", combined):
        return "해킹대행"
    return configured_type


def copy_row_style(sheet, source_row: int, target_row: int) -> None:
    sheet.row_dimensions[target_row].height = sheet.row_dimensions[source_row].height
    for column in range(1, 7):
        source = sheet.cell(source_row, column)
        target = sheet.cell(target_row, column)
        if source.has_style:
            target._style = copy.copy(source._style)
        target.font = copy.copy(source.font)
        target.fill = copy.copy(source.fill)
        target.border = copy.copy(source.border)
        target.alignment = copy.copy(source.alignment)
        target.number_format = source.number_format
        target.protection = copy.copy(source.protection)


def prepare_detection_workbook(template_path: Path, output_path: Path, resume: bool):
    if resume and output_path.exists():
        workbook = load_workbook(output_path)
    else:
        if not template_path.exists():
            raise FileNotFoundError(f"Detection template not found: {template_path}")
        workbook = load_workbook(template_path)
        sheet = workbook[workbook.sheetnames[0]]
        # Delete only the example values. Formatting and the H4:N5 notice stay intact.
        for column in range(1, 7):
            sheet.cell(4, column).value = None
    sheet = workbook[workbook.sheetnames[0]]
    return workbook, sheet


def existing_detection_urls(sheet) -> set[str]:
    return {
        str(sheet.cell(row, 3).value).strip()
        for row in range(4, sheet.max_row + 1)
        if sheet.cell(row, 3).value
    }


def append_detection_entries(sheet, entries: Iterable[DetectionEntry]) -> None:
    occupied_rows = [
        row for row in range(4, sheet.max_row + 1) if sheet.cell(row, 3).value
    ]
    row = max(occupied_rows, default=3) + 1
    for entry in entries:
        if entry.detection_type not in DETECTION_TYPES:
            raise ValueError(f"Unsupported detection type: {entry.detection_type}")
        if row > 31:
            copy_row_style(sheet, 31, row)
        sheet.cell(row, 1).value = row - 3
        sheet.cell(row, 2).value = entry.detected_on
        sheet.cell(row, 2).number_format = "yyyy-mm-dd"
        sheet.cell(row, 3).value = entry.url
        sheet.cell(row, 3).hyperlink = entry.url
        sheet.cell(row, 3).alignment = Alignment(vertical="center", wrap_text=True)
        sheet.cell(row, 4).value = entry.detection_type
        sheet.cell(row, 5).value = safe_spreadsheet_text(entry.registrant)
        sheet.cell(row, 6).value = entry.note
        row += 1


def safe_spreadsheet_text(value: str) -> str:
    value = value.strip()
    return "'" + value if value.startswith(("=", "+", "-", "@")) else value


def save_restricted_workbook(workbook, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    workbook.save(path)
    os.chmod(path, 0o600)


def validate_output(csv_path: Path, target: int) -> None:
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) < target:
        raise RuntimeError(f"Only {len(rows)} successful records; target is {target}")
    if list(rows[0].keys()) != SCHEMA:
        raise RuntimeError("Output schema does not match the research plan")
    joined = "\n".join(
        (row["masked_title"] + "\n" + row["masked_text"]) for row in rows
    )
    hits = [
        name
        for name, pattern in RESIDUAL_PATTERNS.items()
        if re.search(pattern, joined)
    ]
    if hits:
        raise RuntimeError("Residual sensitive patterns found: " + ", ".join(hits))
    if any(row["url_hmac"].startswith(("http:", "https:")) for row in rows):
        raise RuntimeError("Raw URL leaked into URL identifier field")
    sample_ids = [row["sample_id"] for row in rows]
    if any(not sample_id for sample_id in sample_ids) or len(sample_ids) != len(
        set(sample_ids)
    ):
        raise RuntimeError("sample_id values must be present and unique")
    allowed_sources = {"search", "seed", "manual"}
    if any(row["source_type"] not in allowed_sources for row in rows):
        raise RuntimeError("Unsupported source_type found")


def dataset_metrics(csv_path: Path) -> dict[str, object]:
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    lengths = sorted(len(row["masked_text"]) for row in rows)
    domains = Counter(row["registrable_domain"] for row in rows)
    languages = Counter(row["language_mix"] for row in rows)
    page_types = Counter(row["page_type"] for row in rows)
    fingerprints = Counter(
        row["near_duplicate_cluster"]
        for row in rows
        if row["near_duplicate_cluster"]
    )
    duplicate_groups = {key: count for key, count in fingerprints.items() if count > 1}
    middle = len(lengths) // 2
    median = (
        (lengths[middle - 1] + lengths[middle]) / 2
        if lengths and len(lengths) % 2 == 0
        else lengths[middle]
        if lengths
        else 0
    )
    return {
        "dataset_rows": len(rows),
        "unique_url_hmacs": len({row["url_hmac"] for row in rows}),
        "unique_domains": len(domains),
        "top_domains": domains.most_common(10),
        "language_mix_counts": dict(languages),
        "page_type_counts": dict(page_types),
        "text_chars_min": min(lengths, default=0),
        "text_chars_median": median,
        "text_chars_average": round(sum(lengths) / len(lengths), 1) if lengths else 0,
        "text_chars_max": max(lengths, default=0),
        "exact_simhash_duplicate_groups": len(duplicate_groups),
        "exact_simhash_duplicate_rows": sum(duplicate_groups.values()),
    }


def main() -> int:
    args = parse_args()
    validate_args(args)
    args.out.mkdir(parents=True, exist_ok=True)
    os.chmod(args.out, 0o700)
    csv_path = args.out / "candidates_masked.csv"
    detection_path = args.out / "restricted" / "탐지내역_자동수집.xlsx"
    log_path = args.out / "collection_log.csv"
    failure_path = args.out / "extraction_failures.csv"
    summary_path = args.out / "collection_summary.json"
    masking_report_path = args.out / "masking_validation_report.json"
    manifest_path = args.out / "data_manifest.json"
    private_dir = args.out / ".private"
    key = get_or_create_hmac_key(private_dir)
    queue_path = private_dir / "candidate_queue.jsonl"
    keyword_expansion_path = private_dir / "keyword_expansions.csv"

    workbook = None
    detection_sheet = None
    detection_urls: set[str] = set()
    if not args.skip_detection_workbook:
        workbook, detection_sheet = prepare_detection_workbook(
            args.template, detection_path, args.resume
        )
        detection_urls = existing_detection_urls(detection_sheet)

    if csv_path.exists() and not args.resume:
        raise RuntimeError(f"{csv_path} exists; use --resume or move it first")
    if args.resume:
        upgrade_existing_csv_schema(csv_path)
        upgrade_collection_log_schema(log_path)
    done_hashes = existing_hashes(csv_path)
    retained_fingerprints = existing_fingerprints(csv_path)
    retained_domain_counts = existing_success_domain_counts(csv_path)
    terminal_hashes = terminal_attempt_hashes(log_path) if args.resume else set()
    existing_count = len(done_hashes)
    next_record_index = next_sample_index(csv_path)

    session = requests.Session()
    session.headers.update(
        {"User-Agent": USER_AGENT, "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.5"}
    )
    limiter = RateLimiter(args.domain_delay)
    robots_cache: dict[str, tuple[bool, str]] = {}
    logs: list[CollectionLog] = []
    successes: list[dict[str, object]] = []
    detection_entries: list[DetectionEntry] = []
    successful_text_lengths: list[int] = []
    successful_provider_counts: Counter[str] = Counter()
    newly_discovered_links = 0
    flushed_successes = 0
    flushed_detection_entries = 0

    def flush_pending(force: bool = False) -> None:
        nonlocal flushed_successes, flushed_detection_entries
        if not force and len(logs) < args.checkpoint_every:
            return
        pending_successes = successes[flushed_successes:]
        if pending_successes:
            append_csv(csv_path, pending_successes, SCHEMA)
            flushed_successes = len(successes)
        if logs:
            append_csv(log_path, [asdict(item) for item in logs], LOG_SCHEMA)
            failures = [
                failure
                for item in logs
                if (failure := extraction_failure_record(item)) is not None
            ]
            if failures:
                append_csv(failure_path, failures, EXTRACTION_FAILURE_SCHEMA)
            logs.clear()
        pending_detection = detection_entries[flushed_detection_entries:]
        if (
            pending_detection
            and detection_sheet is not None
            and workbook is not None
        ):
            append_detection_entries(detection_sheet, pending_detection)
            save_restricted_workbook(workbook, detection_path)
            flushed_detection_entries = len(detection_entries)
        save_candidate_queue(queue_path, candidates)

        if pending_successes:
            print(
                f"collected {existing_count + len(successes)}/{args.target}; "
                f"attempted {candidate_index}/{len(candidates)}",
                flush=True,
            )

    if args.seed_file:
        candidates = prefilter_seed_candidates(
            load_seed_candidates(args.seed_file), args.relevance_gate
        )
        save_candidate_queue(queue_path, candidates)
    elif args.resume and queue_path.exists():
        candidates = load_candidate_queue(queue_path)
        print(f"loaded {len(candidates)} candidates from private resume queue", flush=True)
    else:
        known_query_specs = expand_query_specs(
            load_query_specs(args.queries), args.query_variants
        )
        query_specs = list(known_query_specs)
        if args.strict_search:
            query_specs = constrain_query_specs(query_specs)
        print(f"prepared {len(query_specs)} search queries", flush=True)
        requested_providers = args.search_provider
        google_api_enabled = bool(
            requested_providers and "google_api" in requested_providers
        )
        browser_providers = (
            [name for name in requested_providers if name != "google_api"]
            if requested_providers is not None
            else None
        )
        driver = (
            connect_browser(args.cdp)
            if browser_providers is None or browser_providers
            else None
        )
        google_api_key = (
            os.environ.get(args.google_api_key_env, "").strip()
            if google_api_enabled
            else ""
        )
        google_cse_id = (
            os.environ.get(args.google_cse_id_env, "").strip()
            if google_api_enabled
            else ""
        )

        def run_search(
            specs: list[QuerySpec], desired: int, soft_target_multiplier: int
        ) -> list[Candidate]:
            discovered: list[Candidate] = []
            soft_target = max(
                desired * soft_target_multiplier,
                desired + 30,
            )
            if google_api_enabled:
                discovered = discover_google_api_candidates(
                    session,
                    query_specs=specs,
                    desired=desired,
                    pages=args.search_pages,
                    delay=args.search_delay,
                    prefilter_mode=args.relevance_gate,
                    api_key=google_api_key,
                    cse_id=google_cse_id,
                    soft_target_multiplier=soft_target_multiplier,
                )
            if driver is not None and len(discovered) < soft_target:
                browser_discovered = discover_candidates(
                    driver,
                    query_specs=specs,
                    desired=max(desired - len(discovered), 1),
                    pages=args.search_pages,
                    delay=args.search_delay,
                    soft_target_multiplier=soft_target_multiplier,
                    prefilter_mode=args.relevance_gate,
                    providers_enabled=browser_providers,
                    provider_stale_pages_limit=args.provider_stale_pages,
                )
                discovered = merge_candidates(discovered, browser_discovered)
            return discovered

        try:
            candidates = run_search(
                query_specs,
                desired=max(args.target - existing_count, 1),
                soft_target_multiplier=(
                    4 if args.relevance_gate == "labeling" else
                    15 if args.relevance_gate != "off" else 3
                ),
            )
            for round_number in range(1, args.keyword_expansion_rounds + 1):
                expansions = mine_keyword_expansions(
                    candidates,
                    known_query_specs,
                    round_number=round_number,
                    limit=args.keyword_expansion_per_round,
                    minimum_domains=args.keyword_expansion_min_domains,
                    require_contact=args.keyword_expansion_require_contact,
                )
                if not expansions:
                    print(
                        f"keyword expansion round {round_number}: no repeated "
                        "high-relevance pairs",
                        flush=True,
                    )
                    break
                append_csv(
                    keyword_expansion_path,
                    [asdict(item) for item in expansions],
                    KEYWORD_EXPANSION_SCHEMA,
                )
                expanded_specs = [
                    QuerySpec(
                        item.query_group,
                        item.detection_type,
                        item.query,
                    )
                    for item in expansions
                ]
                known_query_specs.extend(expanded_specs)
                search_specs = (
                    constrain_query_specs(expanded_specs)
                    if args.strict_search
                    else expanded_specs
                )
                print(
                    f"keyword expansion round {round_number}: searching "
                    f"{len(expanded_specs)} new pairs",
                    flush=True,
                )
                additions = run_search(
                    search_specs,
                    desired=max(args.target - len(candidates), 1),
                    soft_target_multiplier=3,
                )
                before_merge = len(candidates)
                candidates = merge_candidates(candidates, additions)
                print(
                    f"keyword expansion round {round_number}: "
                    f"{len(candidates) - before_merge} new candidates",
                    flush=True,
                )
        finally:
            if driver is not None:
                disconnect_browser(driver)
        save_candidate_queue(queue_path, candidates)

    if args.relevance_gate == "off":
        # A labeling pool still benefits from seeing likely positives first;
        # retain the remaining search-result documents as hard negatives.
        candidates.sort(key=discovery_relevance_score, reverse=True)
        save_candidate_queue(queue_path, candidates)

    if args.resume and args.follow_links_per_page:
        priority_domains = existing_success_domains(csv_path)
        if priority_domains:
            candidates.sort(
                key=lambda candidate: (
                    registrable_domain(urlsplit(candidate.url).hostname or "")
                    not in priority_domains
                )
            )
            save_candidate_queue(queue_path, candidates)
            print(
                f"prioritized candidates from {len(priority_domains)} successful domains",
                flush=True,
            )

    candidate_pool_limit = args.candidate_pool_limit or args.target * 4
    candidate_urls = {candidate.url for candidate in candidates}
    candidate_domain_counts = defaultdict(int)
    for queued_candidate in candidates:
        candidate_domain_counts[
            registrable_domain(urlsplit(queued_candidate.url).hostname or "")
        ] += 1
    print(f"discovered {len(candidates)} candidates; collecting pages", flush=True)
    candidate_index = 0
    while candidate_index < len(candidates):
        flush_pending()
        candidate = candidates[candidate_index]
        candidate_index += 1
        if existing_count + len(successes) >= args.target:
            break
        digest = url_digest(key, candidate.url)
        if digest in done_hashes:
            continue
        if digest in terminal_hashes:
            continue
        if candidate.url in detection_urls:
            continue
        allowed, robots_reason = robots_allowed(
            session, candidate.url, limiter, robots_cache
        )
        if not allowed:
            logs.append(
                CollectionLog(
                    digest, candidate.query_group, "skipped", reason=robots_reason
                )
            )
            continue
        response, final_url, reason = request_once(session, candidate.url, limiter)
        if response is None:
            logs.append(
                CollectionLog(digest, candidate.query_group, "failed", reason=reason)
            )
            continue
        status = response.status_code
        if status != 200:
            response.close()
            logs.append(
                CollectionLog(
                    digest, candidate.query_group, "failed", str(status), "http_status"
                )
            )
            continue
        html, reason = read_html(response)
        if html is None:
            response.close()
            logs.append(
                CollectionLog(
                    digest, candidate.query_group, "skipped", str(status), reason
                )
            )
            continue
        title, text, extraction_method = extract_title_text(html, final_url)
        quality_reason = text_quality_reason(
            text,
            args.min_text_chars,
            minimum_korean_chars=args.min_korean_chars,
            title=title,
        )
        fallback_url = public_content_fallback_url(final_url)
        if quality_reason and fallback_url:
            response.close()
            fallback_allowed, fallback_robots_reason = robots_allowed(
                session, fallback_url, limiter, robots_cache
            )
            if fallback_allowed:
                fallback_response, fallback_final_url, _ = request_once(
                    session, fallback_url, limiter
                )
                if fallback_response is not None and fallback_response.status_code == 200:
                    fallback_html, _ = read_html(fallback_response)
                    if fallback_html is not None:
                        fallback_title, fallback_text, fallback_method = (
                            extract_title_text(fallback_html, fallback_final_url)
                        )
                        fallback_quality_reason = text_quality_reason(
                            fallback_text,
                            args.min_text_chars,
                            minimum_korean_chars=args.min_korean_chars,
                            title=fallback_title,
                        )
                        if not fallback_quality_reason:
                            response = fallback_response
                            final_url = fallback_final_url
                            status = fallback_response.status_code
                            html = fallback_html
                            title = fallback_title
                            text = fallback_text
                            extraction_method = (
                                "public_mobile_fallback:" + fallback_method
                            )
                            quality_reason = ""
                        else:
                            fallback_response.close()
                    else:
                        fallback_response.close()
            elif fallback_robots_reason:
                quality_reason = fallback_robots_reason
        if quality_reason:
            response.close()
            logs.append(
                CollectionLog(
                    digest,
                    candidate.query_group,
                    "failed",
                    str(status),
                    quality_reason,
                    len(text),
                    extraction_method,
                )
            )
            continue
        masked_title = mask_text(title)
        masked_text = mask_text(text)
        collector_page_type = classify_page_type(
            final_url, masked_title, masked_text
        )
        relevance_reason = relevance_gate_reason(
            masked_title,
            masked_text,
            final_url,
            collector_page_type,
            args.relevance_gate,
            candidate.discovery_text,
        )
        if relevance_reason:
            response.close()
            logs.append(
                CollectionLog(
                    digest,
                    candidate.query_group,
                    "skipped",
                    str(status),
                    relevance_reason,
                    len(text),
                    extraction_method,
                )
            )
            continue
        record_domain = registrable_domain(urlsplit(final_url).hostname or "")
        if (
            args.max_records_per_domain
            and retained_domain_counts[record_domain]
            >= args.max_records_per_domain
        ):
            response.close()
            logs.append(
                CollectionLog(
                    digest,
                    candidate.query_group,
                    "skipped",
                    str(status),
                    "domain_record_limit",
                    len(text),
                    extraction_method,
                )
            )
            continue
        if args.follow_links_per_page and len(candidates) < candidate_pool_limit:
            remaining_pool = candidate_pool_limit - len(candidates)
            related_links = discover_related_internal_links(
                html,
                final_url,
                min(args.follow_links_per_page, remaining_pool),
            )
            priority_candidates: list[Candidate] = []
            for related_url in related_links:
                if related_url in candidate_urls:
                    continue
                related_domain = registrable_domain(
                    urlsplit(related_url).hostname or ""
                )
                if (
                    args.max_candidates_per_domain
                    and candidate_domain_counts[related_domain]
                    >= args.max_candidates_per_domain
                ):
                    continue
                candidate_urls.add(related_url)
                candidate_domain_counts[related_domain] += 1
                priority_candidates.append(
                    Candidate(
                        url=related_url,
                        query_group=candidate.query_group,
                        detection_type=candidate.detection_type,
                        source_type=candidate.source_type,
                        search_provider=candidate.search_provider,
                    )
                )
                newly_discovered_links += 1
            if priority_candidates:
                candidates[candidate_index:candidate_index] = priority_candidates
        record = make_record(
            next_record_index + len(successes),
            candidate,
            final_url,
            status,
            title,
            text,
            key,
        )
        fingerprint = str(record["near_duplicate_fingerprint"])
        if fingerprint and fingerprint in retained_fingerprints:
            response.close()
            logs.append(
                CollectionLog(
                    digest,
                    candidate.query_group,
                    "skipped",
                    str(status),
                    "exact_simhash_duplicate",
                    len(text),
                    extraction_method,
                )
            )
            continue
        response.close()
        if fingerprint:
            retained_fingerprints.add(fingerprint)
        retained_domain_counts[record_domain] += 1
        successes.append(record)
        for provider_name in candidate.search_provider.split(","):
            if provider_name:
                successful_provider_counts[provider_name] += 1
        successful_text_lengths.append(len(text))
        if detection_sheet is not None:
            detection_entries.append(
                DetectionEntry(
                    detected_on=dt.datetime.now(
                        dt.timezone(dt.timedelta(hours=9))
                    ).date(),
                    url=final_url,
                    detection_type=infer_detection_type(
                        candidate.detection_type, title, text
                    ),
                    registrant=args.registrant,
                )
            )
        logs.append(
            CollectionLog(
                digest,
                candidate.query_group,
                "success",
                str(status),
                robots_reason,
                len(text),
                extraction_method,
            )
        )
    flush_pending(force=True)
    # Required handoff files retain a header even when this run has no rows.
    append_csv(csv_path, [], SCHEMA)
    append_csv(failure_path, [], EXTRACTION_FAILURE_SCHEMA)

    total = existing_count + len(successes)
    dataset_version = (
        dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).date().isoformat()
        + "-"
        + args.out.name
    )
    summary = {
        "generated_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).isoformat(
            timespec="seconds"
        ),
        "target": args.target,
        "successful_records": total,
        "new_records": len(successes),
        "discovered_candidates": len(candidates),
        "processed_queue_positions": candidate_index,
        "remaining_queue_positions": max(len(candidates) - candidate_index, 0),
        "same_site_links_added": newly_discovered_links,
        "candidate_provider_counts": dict(
            Counter(
                provider_name
                for candidate in candidates
                for provider_name in candidate.search_provider.split(",")
                if provider_name
            )
        ),
        "new_successful_provider_counts": dict(successful_provider_counts),
        "minimum_text_chars": args.min_text_chars,
        "minimum_korean_chars": args.min_korean_chars,
        "new_text_chars_min": min(successful_text_lengths, default=0),
        "new_text_chars_max": max(successful_text_lengths, default=0),
        "new_text_chars_average": (
            round(sum(successful_text_lengths) / len(successful_text_lengths), 1)
            if successful_text_lengths
            else 0
        ),
        "raw_urls_in_dataset": False,
        "raw_urls_in_restricted_detection_workbook": not args.skip_detection_workbook,
        "attachments_downloaded": False,
        "login_or_bypass_used": False,
        "ai_judgement_used": False,
        "schema_source": "CISC-W26 research plan section 5.2 and upstream handoff guide",
    }
    summary.update(dataset_metrics(csv_path))
    summary.update(collection_log_metrics(log_path))
    write_restricted_json(summary_path, summary)

    masking_report = masking_validation(csv_path, dataset_version)
    write_restricted_json(masking_report_path, masking_report)

    manifest = data_manifest(
        args.out,
        dataset_version,
        (
            csv_path,
            log_path,
            failure_path,
            summary_path,
            masking_report_path,
        ),
        {
            "target": args.target,
            "source_mode": "seed" if args.seed_file else "search",
            "search_pages": args.search_pages,
            "search_providers": args.search_provider or ["all"],
            "provider_stale_pages": args.provider_stale_pages,
            "query_variants": args.query_variants,
            "keyword_expansion_rounds": args.keyword_expansion_rounds,
            "keyword_expansion_per_round": args.keyword_expansion_per_round,
            "keyword_expansion_min_domains": args.keyword_expansion_min_domains,
            "keyword_expansion_require_contact": (
                args.keyword_expansion_require_contact
            ),
            "strict_search": args.strict_search,
            "relevance_gate": args.relevance_gate,
            "search_delay_seconds": args.search_delay,
            "domain_delay_seconds": args.domain_delay,
            "minimum_text_chars": args.min_text_chars,
            "minimum_korean_chars": args.min_korean_chars,
            "checkpoint_attempts": args.checkpoint_every,
            "follow_links_per_page": args.follow_links_per_page,
            "candidate_pool_limit": candidate_pool_limit,
            "max_candidates_per_domain": args.max_candidates_per_domain,
            "max_records_per_domain": args.max_records_per_domain,
            "ai_judgement_used": False,
        },
    )
    write_restricted_json(manifest_path, manifest)

    if total >= args.target:
        validate_output(csv_path, args.target)
        if not masking_report["passed"]:
            raise RuntimeError("Masking validation failed; do not hand off this dataset")
        print(f"complete: {total} masked records", flush=True)
        return 0
    print(f"incomplete: {total}/{args.target}; rerun with --resume", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
