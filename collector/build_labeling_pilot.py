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
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.collect_candidates import (
    SCHEMA,
    load_candidate_queue,
    masking_validation,
    near_duplicate_id,
    sha256_file,
    url_digest,
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="append", type=Path, required=True)
    parser.add_argument("--fallback-source", action="append", type=Path, default=[])
    parser.add_argument("--target", type=int, default=30)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def normalized_document(row: dict[str, str]) -> str:
    return re.sub(
        r"\s+",
        " ",
        (row.get("masked_title", "") + "\n" + row.get("masked_text", "")).lower(),
    ).strip()


def load_rows(source: Path) -> list[tuple[dict[str, str], str]]:
    csv_path = source / "candidates_masked.csv"
    queue_path = source / ".private" / "candidate_queue.jsonl"
    key_path = source / ".private" / "url_hmac_key"
    if not csv_path.exists() or not queue_path.exists() or not key_path.exists():
        raise FileNotFoundError(f"Incomplete collector output: {source}")
    key = key_path.read_bytes().strip()
    raw_by_hmac = {
        url_digest(key, candidate.url): candidate.url
        for candidate in load_candidate_queue(queue_path)
    }
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    resolved = []
    for row in rows:
        raw_url = raw_by_hmac.get(row.get("url_hmac", ""))
        if not raw_url:
            raise ValueError(
                f"Could not resolve URL provenance for {source}/{row.get('sample_id')}"
            )
        resolved.append((row, raw_url))
    return resolved


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


def write_labeling_sheet(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LABELING_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
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
            )


def main() -> int:
    args = parse_args()
    if args.target < 1:
        raise ValueError("--target must be at least 1")
    sources = [(path, "primary") for path in args.source] + [
        (path, "fallback") for path in args.fallback_source
    ]
    selected: list[tuple[dict[str, str], str, Path, str]] = []
    seen_urls: set[str] = set()
    seen_documents: set[str] = set()
    for source, tier in sources:
        for row, raw_url in load_rows(source):
            document = normalized_document(row)
            if raw_url in seen_urls or (document and document in seen_documents):
                continue
            selected.append((row, raw_url, source, tier))
            seen_urls.add(raw_url)
            if document:
                seen_documents.add(document)
            if len(selected) >= args.target:
                break
        if len(selected) >= args.target:
            break
    if len(selected) < args.target:
        raise RuntimeError(f"Only {len(selected)} unique rows available for target {args.target}")

    args.out.mkdir(parents=True, exist_ok=False)
    private_dir = args.out / ".private"
    private_dir.mkdir(mode=0o700)
    rows: list[dict[str, str]] = []
    provenance: list[dict[str, str]] = []
    for index, (source_row, raw_url, source, tier) in enumerate(selected, start=1):
        row = {name: str(source_row.get(name, "")) for name in SCHEMA}
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
                "source_output": str(source),
                "source_sample_id": source_sample_id,
                "selection_tier": tier,
                "raw_url": raw_url,
            }
        )
    assign_near_duplicate_clusters(rows)

    csv_path = args.out / "candidates_masked.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SCHEMA)
        writer.writeheader()
        writer.writerows(rows)

    labeling_a_path = args.out / "labeling_A.csv"
    labeling_b_path = args.out / "labeling_B.csv"
    write_labeling_sheet(labeling_a_path, rows)
    write_labeling_sheet(labeling_b_path, rows)

    instructions_path = args.out / "LABELING_INSTRUCTIONS.md"
    instructions_path.write_text(
        f"""# {len(rows)}건 파일럿 라벨링 안내

`labeling_A.csv`와 `labeling_B.csv`는 서로의 판정을 보지 않고 각각 작성합니다.
모든 행은 자동 정답이 아니라 후보이며, 수집기의 `collector_page_type`도 참고값일
뿐 최종 라벨이 아닙니다.

각 행은 다음 순서로 확인합니다.

1. 현재 내용을 확인할 수 있으면 `accessible_label=1`, 아니면 `0`으로 적습니다.
2. 작성자가 올린 원 게시물이면 `page_original_label=1`로 적습니다. 검색어 반사,
   검색결과, 뉴스·질문·교육, 전달·인용 글은 `0`입니다.
3. 거래 의사, 개인정보 불법유통 거래 대상, 구체적 연락 방법을 각각
   `intent_label`, `trade_target_label`, `contact_label`에 `0` 또는 `1`로 적습니다.
4. 명시적 오탐이면 `explicit_negative_label=1`로 적고 `negative_type`에
   `search_reflection`, `search_result_list`, `single_own_account`,
   `news_question_education`, `normal_db_context`, `missing_intent`,
   `missing_target`, `missing_contact`, `deleted_inaccessible`,
   `extraction_failure`, `slang_mixed_language`, `other` 중 하나 이상을 적습니다.
5. 양성은 거래 의사·대상·연락수단·원 게시물·접근 가능성이 모두 `1`이고
   명시적 오탐이 `0`일 때만 선택합니다. 문맥이 부족하면 `uncertain`을 유지합니다.
6. 양성으로 본 근거 문구는 `evidence_spans`에, 판단 이유나 애매한 점은
   `annotation_notes`에 적습니다.

원 URL은 일반 CSV에 없으며 책임자가 관리하는 `.private/url_provenance.csv`에서만
확인합니다. 연락하거나 구매·문의하지 말고, 첨부파일이나 유출 샘플도 내려받지
않습니다.
""",
        encoding="utf-8",
    )

    url_map_path = private_dir / "url_provenance.csv"
    with url_map_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(provenance[0]))
        writer.writeheader()
        writer.writerows(provenance)
    os.chmod(url_map_path, 0o600)

    dataset_version = f"labeling-pilot-{dt.date.today().isoformat()}-v1"
    validation = masking_validation(csv_path, dataset_version)
    validation_path = args.out / "masking_validation_report.json"
    validation_path.write_text(
        json.dumps(validation, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    source_counts: dict[str, int] = {}
    tier_counts: dict[str, int] = {}
    for item in provenance:
        source_counts[item["source_output"]] = (
            source_counts.get(item["source_output"], 0) + 1
        )
        tier_counts[item["selection_tier"]] = (
            tier_counts.get(item["selection_tier"], 0) + 1
        )
    manifest = {
        "dataset_version": dataset_version,
        "generated_at": dt.datetime.now(
            dt.timezone(dt.timedelta(hours=9))
        ).isoformat(timespec="seconds"),
        "rows": len(rows),
        "selection": {
            "method": "ordered rule-gated outputs; raw-URL and exact masked-text dedup",
            "source_counts": source_counts,
            "tier_counts": tier_counts,
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
                for path in (labeling_a_path, labeling_b_path, instructions_path)
            ],
        ],
        "restricted_files": [
            {
                "path": ".private/url_provenance.csv",
                "rows": len(provenance),
                "mode": "0600",
                "included_in_public_manifest_hashes": False,
            }
        ],
        "masking_validation_passed": validation["passed"],
    }
    manifest_path = args.out / "data_manifest.json"
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
