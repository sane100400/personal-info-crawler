#!/usr/bin/env python3
"""Build a masked labeling pilot from completed collector outputs.

The public handoff keeps labels blank and URLs HMAC-only. Raw URL provenance is
written only under ``.private`` with mode 0600 so cross-run deduplication can be
audited without exposing live destinations in the labeling CSV.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.collect_candidates import (
    Candidate,
    SCHEMA,
    load_candidate_queue,
    masking_validation,
    near_duplicate_id,
    relevance_gate_reason,
    sha256_file,
    url_digest,
)
from collector.labeling_workbook import (
    write_labeling_workbook as write_link_labeling_workbook,
)

LABELING_FIELDS = [
    "sample_id",
    "collected_at",
    "registrable_domain",
    "masked_title",
    "masked_text",
    "collector_page_type",
    "live_status",
    "intent_label",
    "trade_target_label",
    "contact_label",
    "page_type_label",
    "page_original_label",
    "accessible_label",
    "explicit_negative_label",
    "negative_type",
    "final_label",
    "evidence_spans",
    "annotation_notes",
]

BOUNDARY_REASONS = {
    "missing_body_offer",
    "missing_concrete_contact",
    "missing_direct_offer",
    "missing_supporting_signal",
    "missing_trade_or_contact_signal",
}


@dataclass(frozen=True)
class SourceRow:
    row: dict[str, str]
    candidate: Candidate
    source: Path
    source_tier: str
    gate_reason: str = ""
    selection_bucket: str = "ordered"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="append", type=Path, required=True)
    parser.add_argument("--fallback-source", action="append", type=Path, default=[])
    parser.add_argument("--target", type=int, default=30)
    parser.add_argument("--out", type=Path, required=True)
    priority = parser.add_mutually_exclusive_group()
    priority.add_argument(
        "--strict-priority",
        action="store_true",
        help=(
            "현재 strict 규칙 통과 후보를 먼저 뽑고, 경계 사례와 명시적 "
            "오탐 후보를 사유별로 번갈아 채움"
        ),
    )
    priority.add_argument(
        "--intent-priority",
        action="store_true",
        help=(
            "개인정보 거래 대상과 직접 거래 의사가 확인된 후보를 연락수단 "
            "유무와 관계없이 먼저 뽑음"
        ),
    )
    parser.add_argument(
        "--max-per-domain",
        type=int,
        default=0,
        help="라벨링 묶음의 도메인별 최대 행 수(0은 제한 없음)",
    )
    return parser.parse_args()


def normalized_document(row: dict[str, str]) -> str:
    return re.sub(
        r"\s+",
        " ",
        (row.get("masked_title", "") + "\n" + row.get("masked_text", "")).lower(),
    ).strip()


def load_rows(source: Path) -> list[tuple[dict[str, str], Candidate]]:
    csv_path = source / "candidates_masked.csv"
    queue_path = source / ".private" / "candidate_queue.jsonl"
    key_path = source / ".private" / "url_hmac_key"
    if not csv_path.exists() or not queue_path.exists() or not key_path.exists():
        raise FileNotFoundError(f"Incomplete collector output: {source}")
    key = key_path.read_bytes().strip()
    candidate_by_hmac = {
        url_digest(key, candidate.url): candidate
        for candidate in load_candidate_queue(queue_path)
    }
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    resolved = []
    for row in rows:
        candidate = candidate_by_hmac.get(row.get("url_hmac", ""))
        if not candidate:
            raise ValueError(
                f"Could not resolve URL provenance for {source}/{row.get('sample_id')}"
            )
        resolved.append((row, candidate))
    return resolved


def strict_bucket(reason: str) -> str:
    if not reason:
        return "strict_priority"
    if reason in BOUNDARY_REASONS:
        return "boundary_review"
    return "hard_negative"


def intent_bucket(reason: str) -> str:
    """Prioritize direct trade offers; contact details are supporting evidence."""
    if reason in {"", "missing_concrete_contact"}:
        return "intent_priority"
    if reason in BOUNDARY_REASONS:
        return "boundary_review"
    return "hard_negative"


def round_robin_reasons(rows: list[SourceRow]) -> list[SourceRow]:
    """Interleave gate reasons so one common negative class cannot dominate."""
    by_reason: dict[str, deque[SourceRow]] = defaultdict(deque)
    reason_order: list[str] = []
    for item in rows:
        if item.gate_reason not in by_reason:
            reason_order.append(item.gate_reason)
        by_reason[item.gate_reason].append(item)
    ordered: list[SourceRow] = []
    while reason_order:
        remaining: list[str] = []
        for reason in reason_order:
            queue = by_reason[reason]
            if queue:
                ordered.append(queue.popleft())
            if queue:
                remaining.append(reason)
        reason_order = remaining
    return ordered


def prioritize_rows(rows: list[SourceRow], priority_enabled: bool) -> list[SourceRow]:
    if not priority_enabled:
        return rows
    buckets: dict[str, list[SourceRow]] = defaultdict(list)
    for item in rows:
        buckets[item.selection_bucket].append(item)
    return [
        *buckets["strict_priority"],
        *buckets["intent_priority"],
        *round_robin_reasons(buckets["boundary_review"]),
        *round_robin_reasons(buckets["hard_negative"]),
    ]


def select_rows(
    rows: list[SourceRow], target: int, max_per_domain: int
) -> list[SourceRow]:
    selected: list[SourceRow] = []
    domain_counts: Counter[str] = Counter()
    for item in rows:
        domain = item.row.get("registrable_domain", "")
        if max_per_domain and domain_counts[domain] >= max_per_domain:
            continue
        selected.append(item)
        domain_counts[domain] += 1
        if len(selected) >= target:
            break
    return selected


def simhash_value(row: dict[str, str]) -> int:
    fingerprint = near_duplicate_id(
        row.get("masked_title", ""), row.get("masked_text", "")
    )
    return int(fingerprint.rsplit(":", 1)[1], 16)


def assign_near_duplicate_clusters(rows: list[dict[str, str]]) -> None:
    parents = list(range(len(rows)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    values = [simhash_value(row) for row in rows]
    for left in range(len(rows)):
        for right in range(left + 1, len(rows)):
            if (values[left] ^ values[right]).bit_count() <= 3:
                union(left, right)

    members: dict[int, list[int]] = {}
    for index in range(len(rows)):
        members.setdefault(find(index), []).append(index)
    ordered = sorted(members.values(), key=lambda group: min(group))
    for group_number, group in enumerate(ordered, start=1):
        cluster = f"pilot-dup-{group_number:03d}"
        for index in group:
            rows[index]["near_duplicate_cluster"] = cluster
            rows[index]["near_duplicate_fingerprint"] = (
                f"simhash64:{values[index]:016x}"
            )


def write_labeling_sheet(
    path: Path,
    rows: list[dict[str, str]],
    source_urls: dict[str, str] | None = None,
) -> None:
    fields = list(LABELING_FIELDS)
    if source_urls is not None:
        fields.insert(1, "source_url")
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            output = {
                "sample_id": row["sample_id"],
                "collected_at": row["collected_at"],
                "registrable_domain": row["registrable_domain"],
                "masked_title": row["masked_title"],
                "masked_text": row["masked_text"],
                "collector_page_type": row["page_type"],
                "live_status": row["live_status"],
                "intent_label": "",
                "trade_target_label": "",
                "contact_label": "",
                "page_type_label": "",
                "page_original_label": "",
                "accessible_label": "",
                "explicit_negative_label": "",
                "negative_type": "",
                "final_label": "",
                "evidence_spans": "{}",
                "annotation_notes": "",
            }
            if source_urls is not None:
                output["source_url"] = source_urls[row["sample_id"]]
            writer.writerow(output)


def main() -> int:
    args = parse_args()
    if args.target < 1:
        raise ValueError("--target must be at least 1")
    if args.max_per_domain < 0:
        raise ValueError("--max-per-domain cannot be negative")
    sources = [(path, "primary") for path in args.source] + [
        (path, "fallback") for path in args.fallback_source
    ]
    available: list[SourceRow] = []
    seen_urls: set[str] = set()
    seen_documents: set[str] = set()
    for source, tier in sources:
        for row, candidate in load_rows(source):
            document = normalized_document(row)
            if candidate.url in seen_urls or (
                document and document in seen_documents
            ):
                continue
            gate_reason = ""
            selection_bucket = "ordered"
            if args.strict_priority or args.intent_priority:
                gate_mode = "intent" if args.intent_priority else "strict"
                gate_reason = relevance_gate_reason(
                    row.get("masked_title", ""),
                    row.get("masked_text", ""),
                    candidate.url,
                    row.get("page_type", ""),
                    gate_mode,
                    candidate.discovery_text,
                )
                selection_bucket = (
                    intent_bucket(gate_reason)
                    if args.intent_priority
                    else strict_bucket(gate_reason)
                )
            available.append(
                SourceRow(
                    row=row,
                    candidate=candidate,
                    source=source,
                    source_tier=tier,
                    gate_reason=gate_reason,
                    selection_bucket=selection_bucket,
                )
            )
            seen_urls.add(candidate.url)
            if document:
                seen_documents.add(document)
    selected = select_rows(
        prioritize_rows(
            available, args.strict_priority or args.intent_priority
        ),
        args.target,
        args.max_per_domain,
    )
    if len(selected) < args.target:
        raise RuntimeError(
            f"Only {len(selected)} unique rows available for target {args.target} "
            f"with max_per_domain={args.max_per_domain}"
        )
    selected_bucket_counts = Counter(
        item.selection_bucket for item in selected
    )
    intent_priority_rows = selected_bucket_counts.get("intent_priority", 0)
    boundary_review_rows = selected_bucket_counts.get("boundary_review", 0)
    hard_negative_rows = selected_bucket_counts.get("hard_negative", 0)

    args.out.mkdir(parents=True, exist_ok=False)
    private_dir = args.out / ".private"
    private_dir.mkdir(mode=0o700)
    links_dir = args.out / "links"
    links_dir.mkdir(mode=0o700)
    rows: list[dict[str, str]] = []
    provenance: list[dict[str, str]] = []
    for index, item in enumerate(selected, start=1):
        row = {name: str(item.row.get(name, "")) for name in SCHEMA}
        source_sample_id = row["sample_id"]
        row["sample_id"] = f"LP-{index:06d}"
        for field in (
            "intent_label",
            "target_label",
            "contact_label",
            "annotator_1",
            "annotator_2",
            "adjudicated_label",
        ):
            row[field] = ""
        row["final_label"] = "uncertain"
        row["evidence_spans"] = "{}"
        rows.append(row)
        provenance.append(
            {
                "sample_id": row["sample_id"],
                "source_output": str(item.source),
                "source_sample_id": source_sample_id,
                "source_tier": item.source_tier,
                "selection_bucket": item.selection_bucket,
                "gate_exclusion_reason": item.gate_reason,
                "raw_url": item.candidate.url,
            }
        )
    assign_near_duplicate_clusters(rows)

    csv_path = args.out / "data.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SCHEMA)
        writer.writeheader()
        writer.writerows(rows)

    labeling_a_path = args.out / "label_A.csv"
    labeling_b_path = args.out / "label_B.csv"
    write_labeling_sheet(labeling_a_path, rows)
    write_labeling_sheet(labeling_b_path, rows)

    source_urls = {
        item["sample_id"]: item["raw_url"] for item in provenance
    }
    restricted_candidates_path = links_dir / "data.csv"
    restricted_fields = [SCHEMA[0], "source_url", *SCHEMA[1:]]
    with restricted_candidates_path.open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=restricted_fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    **row,
                    "source_url": source_urls[row["sample_id"]],
                }
            )
    restricted_labeling_a_path = links_dir / "label_A.csv"
    restricted_labeling_b_path = links_dir / "label_B.csv"
    write_labeling_sheet(restricted_labeling_a_path, rows, source_urls)
    write_labeling_sheet(restricted_labeling_b_path, rows, source_urls)
    labeling_workbook_path = links_dir / "label.xlsx"
    write_link_labeling_workbook(labeling_workbook_path, rows, source_urls)
    for path in (
        restricted_candidates_path,
        restricted_labeling_a_path,
        restricted_labeling_b_path,
        labeling_workbook_path,
    ):
        os.chmod(path, 0o600)

    instructions_path = args.out / "guide.md"
    instructions_path.write_text(
        f"""# {len(rows)}건 파일럿 라벨링 안내

이번 자료는 {len(rows)}건 전체가 정탐이라는 뜻이 아닙니다. 자동 선별 결과는
판매 의사 우선 후보 {intent_priority_rows}건, 경계 사례 {boundary_review_rows}건,
명시적 오탐 후보 {hard_negative_rows}건입니다. 경계 사례는 제목이나 검색요약에서
거래 대상이 확인됐지만, 수집된 본문만으로 작성자의 직접적인 판매·매입·제작
의사를 확정하지 못한 글입니다. 정탐으로 간주하지 말고 본문을 다시 확인합니다.

`label_A.csv`와 `label_B.csv`는 서로의 판정을 보지 않고 각각 작성합니다.
모든 행은 자동 정답이 아니라 후보이며, 수집기의 `collector_page_type`도 참고값일
뿐 최종 라벨이 아닙니다.

각 행은 다음 순서로 확인합니다.

1. 현재 내용을 확인할 수 있으면 `accessible_label=1`, 아니면 `0`으로 적습니다.
2. 작성자가 올린 원 게시물이면 `page_original_label=1`로 적습니다. 검색어 반사,
   검색결과, 뉴스·질문·교육, 전달·인용 글은 `0`입니다.
3. 작성자의 판매·매입·제작·중개 의사와 개인정보 불법유통 거래 대상을 각각
   `intent_label`, `trade_target_label`에 `0` 또는 `1`로 적습니다. 게시물에
   구체적인 연락 방법이 있으면 `contact_label=1`, 없으면 `0`으로 적되,
   연락 방법이 없다는 이유만으로 음성 처리하지 않습니다.
4. 명시적 오탐이면 `explicit_negative_label=1`로 적고 `negative_type`에
   `search_reflection`, `search_result_list`, `single_own_account`,
   `news_question_education`, `normal_db_context`, `missing_intent`,
   `missing_target`, `missing_contact`, `deleted_inaccessible`,
   `extraction_failure`, `slang_mixed_language`, `other` 중 하나 이상을 적습니다.
5. 양성은 거래 의사·거래 대상·원 게시물·접근 가능성이 모두 `1`이고 명시적
   오탐이 `0`일 때 선택합니다. 실제 개인정보가 본문에 노출되어 있거나 구체적인
   연락수단이 있어야 할 필요는 없습니다. 문맥이 부족하면 `uncertain`을 유지합니다.
6. 양성으로 본 근거 문구는 `evidence_spans`에, 판단 이유나 애매한 점은
   `annotation_notes`에 적습니다.

원문 확인이 필요한 내부 라벨러에게는 `links/label_A.csv`와
`links/label_B.csv`를 전달합니다. 링크 없는 일반 CSV는 외부
공유용입니다. 원문을 확인하더라도 연락하거나 구매·문의하지 말고, 첨부파일이나
유출 샘플도 내려받지 않습니다.
""",
        encoding="utf-8",
    )

    handoff_path = args.out / "handoff.md"
    handoff_path.write_text(
        f"""# 라벨링 데이터 인계 메모

라벨링할 자료 {len(rows)}건 전달드립니다. 다만 이 파일에 있는 글이 전부
개인정보 불법유통 정탐이라는 뜻은 아닙니다. 자동 선별 기준으로 보면 판매 의사가
확인된 우선 후보가 {intent_priority_rows}건, 사람이 다시 확인해야 하는 경계 사례가
{boundary_review_rows}건, 비교용 오탐 후보가 {hard_negative_rows}건 들어 있습니다.

경계 사례는 제목이나 검색 결과에서는 계정 판매, DB 매입 같은 표현이 보이지만
수집된 본문만으로 작성자의 직접적인 거래 의사를 확정하기 어려운 글입니다. 제목만
보고 정탐 처리하지 말고 본문에서 작성자가 직접 판매·매입·제작·중개하려는지 확인해
주세요. 뉴스, 피해 사례, 신고 안내, 정상 서비스 소개처럼 다른 사람의 거래를
언급한 글은 오탐입니다.

정탐 판단에서 가장 중요한 것은 실제 개인정보가 본문에 들어 있는지가 아니라
작성자의 거래 의사입니다. 개인정보 DB·계정·신분증·통장 등이 거래 대상이고,
작성자의 직접적인 거래 의사가 확인되면 양성으로 판단해 주세요. 연락처가 없거나
개인정보 원문이 노출되지 않았다는 이유만으로 음성 처리하지는 않습니다.

일반 라벨링에는 원문 링크와 판정 드롭다운이 포함된 `links/label.xlsx`를
사용해 주세요. 두 사람이 독립적으로 라벨링할 때만 `links/label_A.csv`와
`links/label_B.csv`를 각각 사용합니다. 링크가 포함된 파일은 연구팀 내부에서만
사용하고 외부로 전달하지 말아 주세요. 애매한 글은 `보류`로 남긴 뒤 최종 조정
때 같이 확인하겠습니다.
""",
        encoding="utf-8",
    )

    url_map_path = private_dir / "urls.csv"
    with url_map_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(provenance[0]))
        writer.writeheader()
        writer.writerows(provenance)
    os.chmod(url_map_path, 0o600)

    dataset_version = f"labeling-pilot-{dt.date.today().isoformat()}-v1"
    validation = masking_validation(csv_path, dataset_version)
    validation_path = args.out / "masking.json"
    validation_path.write_text(
        json.dumps(validation, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    source_counts: dict[str, int] = {}
    tier_counts: dict[str, int] = {}
    bucket_counts: dict[str, int] = {}
    gate_reason_counts: dict[str, int] = {}
    for item in provenance:
        source_counts[item["source_output"]] = (
            source_counts.get(item["source_output"], 0) + 1
        )
        tier_counts[item["source_tier"]] = (
            tier_counts.get(item["source_tier"], 0) + 1
        )
        bucket_counts[item["selection_bucket"]] = (
            bucket_counts.get(item["selection_bucket"], 0) + 1
        )
        reason = item["gate_exclusion_reason"] or "passed"
        gate_reason_counts[reason] = (
            gate_reason_counts.get(reason, 0) + 1
        )
    manifest = {
        "dataset_version": dataset_version,
        "generated_at": dt.datetime.now(
            dt.timezone(dt.timedelta(hours=9))
        ).isoformat(timespec="seconds"),
        "rows": len(rows),
        "selection": {
            "method": (
                "direct trade-intent priority regardless of contact availability, then "
                "reason-balanced boundary and hard-negative sampling; raw-URL and exact "
                "masked-text dedup"
                if args.intent_priority
                else "strict gate priority, then reason-balanced boundary and hard-negative "
                "sampling; raw-URL and exact masked-text dedup"
                if args.strict_priority
                else "ordered rule-gated outputs; raw-URL and exact masked-text dedup"
            ),
            "source_counts": source_counts,
            "tier_counts": tier_counts,
            "bucket_counts": bucket_counts,
            "selection_gate": (
                "intent" if args.intent_priority else "strict"
                if args.strict_priority else "ordered"
            ),
            "strict_priority_rows": bucket_counts.get("strict_priority", 0),
            "intent_priority_rows": bucket_counts.get("intent_priority", 0),
            "contact_required_for_intent_priority": (
                False if args.intent_priority else None
            ),
            "gate_exclusion_reason_counts": gate_reason_counts,
            "max_rows_per_domain": args.max_per_domain,
            "ai_final_labeling_used": False,
            "all_final_labels": "uncertain",
        },
        "near_duplicate_clustering": {
            "method": "SimHash64 Hamming distance <= 3",
            "clusters": len({row["near_duplicate_cluster"] for row in rows}),
        },
        "hmac_note": (
            "Rows retain source-run HMAC namespaces; use the restricted provenance "
            "map for cross-run audit. Do not use HMAC equality across source outputs."
        ),
        "files": [
            {
                "path": csv_path.name,
                "bytes": csv_path.stat().st_size,
                "sha256": sha256_file(csv_path),
                "rows": len(rows),
            },
            {
                "path": validation_path.name,
                "bytes": validation_path.stat().st_size,
                "sha256": sha256_file(validation_path),
            },
            *[
                {
                    "path": path.name,
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                    **({"rows": len(rows)} if path.suffix == ".csv" else {}),
                }
                for path in (
                    labeling_a_path,
                    labeling_b_path,
                    instructions_path,
                    handoff_path,
                )
            ],
        ],
        "restricted_files": [
            {
                "path": ".private/urls.csv",
                "rows": len(provenance),
                "mode": "0600",
                "included_in_public_manifest_hashes": False,
            },
            *[
                {
                    "path": str(path.relative_to(args.out)),
                    "rows": len(rows),
                    "mode": "0600",
                    "included_in_public_manifest_hashes": False,
                }
                for path in (
                    restricted_candidates_path,
                    restricted_labeling_a_path,
                    restricted_labeling_b_path,
                    labeling_workbook_path,
                )
            ],
        ],
        "masking_validation_passed": validation["passed"],
    }
    manifest_path = args.out / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"built {len(rows)}-row labeling pilot; "
        f"masking_passed={validation['passed']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
