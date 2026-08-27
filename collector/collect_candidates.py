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


@dataclass(frozen=True)
class QuerySpec:
    group: str
    detection_type: str
    query: str


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
        "--query-variants",
        type=int,
        default=1,
        help="검색어별 자동 변형 개수(1은 원본만 사용)",
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


def discover_candidates(
    driver: webdriver.Chrome,
    query_specs: list[QuerySpec],
    desired: int,
    pages: int,
    delay: float,
) -> list[Candidate]:
    found: dict[str, Candidate] = {}
    query_items = list(query_specs)
    # A stable shuffle prevents one category from dominating early termination.
    random.Random(20260817).shuffle(query_items)
    soft_target = max(desired * 3, desired + 30)

    providers = (
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
    for provider_name, make_url, selector in providers:
        provider_blocked = False
        for spec in query_items:
            stale_pages = 0
            for page in range(pages):
                before_page = len(found)
                try:
                    driver.get(make_url(spec.query, page))
                except TimeoutException:
                    pass
                except WebDriverException:
                    time.sleep(delay)
                    continue
                page_lower = driver.page_source.lower()
                challenge_markers = (
                    "captcha",
                    "unusual traffic",
                    "verify you are human",
                    "our systems have detected unusual traffic",
                    "anomaly-modal",
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
                anchors = driver.execute_script(
                    "return Array.from(document.querySelectorAll(arguments[0])).map(a => a.href);",
                    selector,
                )
                for raw in anchors or []:
                    raw = unwrap_search_result_url(raw)
                    url = canonicalize_url(raw)
                    if not url:
                        continue
                    host = (urlsplit(url).hostname or "").lower()
                    if host in SEARCH_HOSTS or host.endswith(
                        (".google.com", ".bing.com")
                    ):
                        continue
                    found.setdefault(
                        url,
                        Candidate(
                            url=url,
                            query_group=spec.group,
                            detection_type=spec.detection_type,
                        ),
                    )
                print(
                    f"{provider_name} {spec.group}: {len(found)} unique candidates "
                    f"(+{len(found) - before_page})",
                    flush=True,
                )
                if len(found) >= soft_target:
                    return list(found.values())
                if len(found) == before_page:
                    stale_pages += 1
                    if stale_pages >= 2:
                        break
                else:
                    stale_pages = 0
                time.sleep(delay)
            if provider_blocked:
                break
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
        r"텔레그램|오픈채팅|문의|회원|여권|통장|실명",
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
        if score > 0:
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
    # Order matters: contact URLs and emails must be removed before generic IDs.
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
        r"(?i)(텔레그램|telegram|텔레|카카오톡|카톡|오픈채팅|라인|line)\s*(?:아이디|id|주소|문의|[:：])?\s*[@:]?\s*[A-Za-z0-9_.-]{3,}",
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
    path_query = (parts.path + "?" + parts.query).lower()
    combined = (title + "\n" + text[:2_000]).lower()
    if re.search(
        r"(?:^|[/_?&=-])(search|query|keyword|find)(?:[/_?&=-]|$)", path_query
    ):
        params = parse_qs(parts.query)
        reflected_values = [
            value.lower().strip()
            for key, values in params.items()
            if key.lower() in {"q", "query", "keyword", "search", "searchword"}
            for value in values
            if len(value.strip()) >= 4
        ]
        if any(value in combined for value in reflected_values):
            return "search_reflection"
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
        r"(?i)(?:텔레그램|telegram|텔레|카카오톡|카톡|오픈채팅|라인|line)\s*(?:아이디|id|주소|문의|[:：])?\s*[@:]?\s*[A-Za-z0-9_.-]{3,}",
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
        candidates = load_seed_candidates(args.seed_file)
        save_candidate_queue(queue_path, candidates)
    elif args.resume and queue_path.exists():
        candidates = load_candidate_queue(queue_path)
        print(f"loaded {len(candidates)} candidates from private resume queue", flush=True)
    else:
        query_specs = expand_query_specs(
            load_query_specs(args.queries), args.query_variants
        )
        print(f"prepared {len(query_specs)} search queries", flush=True)
        driver = connect_browser(args.cdp)
        try:
            candidates = discover_candidates(
                driver,
                query_specs=query_specs,
                desired=max(args.target - existing_count, 1),
                pages=args.search_pages,
                delay=args.search_delay,
            )
        finally:
            disconnect_browser(driver)
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
        response.close()
        successes.append(record)
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
            "query_variants": args.query_variants,
            "search_delay_seconds": args.search_delay,
            "domain_delay_seconds": args.domain_delay,
            "minimum_text_chars": args.min_text_chars,
            "minimum_korean_chars": args.min_korean_chars,
            "checkpoint_attempts": args.checkpoint_every,
            "follow_links_per_page": args.follow_links_per_page,
            "candidate_pool_limit": candidate_pool_limit,
            "max_candidates_per_domain": args.max_candidates_per_domain,
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
