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
import sys
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass
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
    "campaign_group",
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


@dataclass
class Candidate:
    url: str
    query_group: str
    detection_type: str


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
    parser.add_argument(
        "--registrant", required=True, help="탐지내역 양식의 등록자 이름"
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
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.target < 1:
        raise ValueError("--target must be at least 1")
    if args.search_pages < 1 or args.search_pages > 10:
        raise ValueError("--search-pages must be between 1 and 10")
    if args.search_delay < 0 or args.domain_delay < 0:
        raise ValueError("Request delays cannot be negative")
    if not args.registrant.strip():
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


def load_seed_candidates(path: Path) -> list[Candidate]:
    if not path.exists():
        raise FileNotFoundError(f"Private seed file not found: {path}")
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
                candidates.setdefault(url, Candidate(url, group, detection_type))
    else:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            url = canonicalize_url(stripped)
            if url:
                candidates.setdefault(url, Candidate(url, "private_seed", "기타"))
    if not candidates:
        raise ValueError("Seed file did not contain any usable public HTTP(S) URLs")
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
            for page in range(pages):
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
                    f"{provider_name} {spec.group}: {len(found)} unique candidates",
                    flush=True,
                )
                if len(found) >= soft_target:
                    return list(found.values())
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
                timeout=(8, 15),
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


def extract_title_text(html: str, url: str) -> tuple[str, str]:
    soup = BeautifulSoup(html, "lxml")
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    extracted = trafilatura.extract(
        html,
        url=url,
        include_comments=False,
        include_tables=False,
        include_links=False,
        favor_precision=True,
        output_format="txt",
    )
    if not extracted:
        for node in soup(
            ["script", "style", "noscript", "svg", "nav", "footer", "header"]
        ):
            node.decompose()
        extracted = soup.get_text("\n", strip=True)
    text = re.sub(r"\n{3,}", "\n\n", extracted or "").strip()
    return title[:2_000], text[:MAX_TEXT_CHARS]


def mask_text(value: str) -> str:
    if not value:
        return ""
    text = value
    # Order matters: contact URLs and emails must be removed before generic IDs.
    text = re.sub(r"(?i)\b(?:https?://|www\.)\S+", "[URL]", text)
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
            return "reflected_search_page"
        return "search_result_list"
    if any(
        term in combined
        for term in (
            "삭제된 게시물",
            "존재하지 않는 게시물",
            "페이지를 찾을 수 없습니다",
        )
    ):
        return "cached_or_deleted"
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
    for token in tokens:
        value = int.from_bytes(
            hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big"
        )
        for bit in range(64):
            weights[bit] += 1 if value & (1 << bit) else -1
    fingerprint = sum((1 << bit) for bit, weight in enumerate(weights) if weight >= 0)
    return f"simhash64:{fingerprint:016x}"


def contact_campaign_id(key: bytes, raw_text: str) -> str:
    patterns = (
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        r"(?<!\d)(?:01[016789]|02|0[3-6][1-5])[- .]?\d{3,4}[- .]?\d{4}(?!\d)",
        r"(?i)\b(?:https?://|www\.)\S+",
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
    response: requests.Response,
    title: str,
    text: str,
    key: bytes,
) -> dict[str, object]:
    masked_title = mask_text(title)
    masked_text = mask_text(text)
    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).isoformat(
        timespec="seconds"
    )
    record: dict[str, object] = {name: "" for name in SCHEMA}
    record.update(
        {
            "sample_id": f"EG-{index:04d}",
            "collected_at": now,
            "source_type": "public_web_search",
            "registrable_domain": registrable_domain(
                urlsplit(final_url).hostname or ""
            ),
            "url_hmac": url_digest(key, candidate.url),
            "http_status": response.status_code,
            "final_url_hmac": url_digest(key, final_url),
            "page_type": classify_page_type(final_url, masked_title, masked_text),
            "live_status": "true",
            "masked_title": masked_title,
            "masked_text": masked_text,
            "language_mix": language_mix(masked_title + "\n" + masked_text),
            "obfuscation_type": obfuscation_type(masked_title + "\n" + masked_text),
            "intent_label": "",
            "target_label": "",
            "contact_label": "",
            "final_label": "uncertain",
            "evidence_spans": "{}",
            "near_duplicate_cluster": near_duplicate_id(masked_title, masked_text),
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
    residual_patterns = {
        "email": r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "phone": r"(?<!\d)(?:01[016789]|02|0[3-6][1-5])[- .]?\d{3,4}[- .]?\d{4}(?!\d)",
        "national_id": r"(?<!\d)\d{6}\s*[-–]?\s*[1-4]\d{6}(?!\d)",
        "http_url": r"(?i)https?://\S+",
    }
    hits = [
        name
        for name, pattern in residual_patterns.items()
        if re.search(pattern, joined)
    ]
    if hits:
        raise RuntimeError("Residual sensitive patterns found: " + ", ".join(hits))
    if any(row["url_hmac"].startswith(("http:", "https:")) for row in rows):
        raise RuntimeError("Raw URL leaked into URL identifier field")


def main() -> int:
    args = parse_args()
    validate_args(args)
    args.out.mkdir(parents=True, exist_ok=True)
    os.chmod(args.out, 0o700)
    csv_path = args.out / "candidates_masked.csv"
    detection_path = args.out / "restricted" / "탐지내역_자동수집.xlsx"
    log_path = args.out / "collection_log.csv"
    summary_path = args.out / "collection_summary.json"
    key = get_or_create_hmac_key(args.out / ".private")

    workbook, detection_sheet = prepare_detection_workbook(
        args.template, detection_path, args.resume
    )
    detection_urls = existing_detection_urls(detection_sheet)

    if csv_path.exists() and not args.resume:
        raise RuntimeError(f"{csv_path} exists; use --resume or move it first")
    done_hashes = existing_hashes(csv_path)
    existing_count = len(done_hashes)

    session = requests.Session()
    session.headers.update(
        {"User-Agent": USER_AGENT, "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.5"}
    )
    limiter = RateLimiter(args.domain_delay)
    robots_cache: dict[str, tuple[bool, str]] = {}
    logs: list[CollectionLog] = []
    successes: list[dict[str, object]] = []
    detection_entries: list[DetectionEntry] = []

    if args.seed_file:
        candidates = load_seed_candidates(args.seed_file)
    else:
        query_specs = load_query_specs(args.queries)
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
            driver.quit()

    print(f"discovered {len(candidates)} candidates; collecting pages", flush=True)
    for candidate in candidates:
        if existing_count + len(successes) >= args.target:
            break
        digest = url_digest(key, candidate.url)
        if digest in done_hashes:
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
        title, text = extract_title_text(html, final_url)
        if len(text) < 40:
            response.close()
            logs.append(
                CollectionLog(
                    digest,
                    candidate.query_group,
                    "failed",
                    str(status),
                    "insufficient_text",
                )
            )
            continue
        record = make_record(
            existing_count + len(successes) + 1,
            candidate,
            final_url,
            response,
            title,
            text,
            key,
        )
        response.close()
        successes.append(record)
        detection_entries.append(
            DetectionEntry(
                detected_on=dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).date(),
                url=final_url,
                detection_type=infer_detection_type(
                    candidate.detection_type, title, text
                ),
                registrant=args.registrant,
            )
        )
        logs.append(
            CollectionLog(
                digest, candidate.query_group, "success", str(status), robots_reason
            )
        )
        if len(successes) % 10 == 0:
            append_csv(csv_path, successes[-10:], SCHEMA)
            append_csv(
                log_path, [asdict(item) for item in logs], list(asdict(logs[0]).keys())
            )
            logs.clear()
            append_detection_entries(detection_sheet, detection_entries[-10:])
            save_restricted_workbook(workbook, detection_path)
            print(
                f"collected {existing_count + len(successes)}/{args.target}", flush=True
            )

    remainder = len(successes) % 10
    if remainder:
        append_csv(csv_path, successes[-remainder:], SCHEMA)
        append_detection_entries(detection_sheet, detection_entries[-remainder:])
        save_restricted_workbook(workbook, detection_path)
    if logs:
        append_csv(
            log_path, [asdict(item) for item in logs], list(asdict(logs[0]).keys())
        )

    total = existing_count + len(successes)
    summary = {
        "generated_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).isoformat(
            timespec="seconds"
        ),
        "target": args.target,
        "successful_records": total,
        "new_records": len(successes),
        "discovered_candidates": len(candidates),
        "raw_urls_in_dataset": False,
        "raw_urls_in_restricted_detection_workbook": True,
        "attachments_downloaded": False,
        "login_or_bypass_used": False,
        "schema_source": "CISC-W26 research plan section 5.2",
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(summary_path, 0o600)

    if total >= args.target:
        validate_output(csv_path, args.target)
        print(f"complete: {total} masked records", flush=True)
        return 0
    print(f"incomplete: {total}/{args.target}; rerun with --resume", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
