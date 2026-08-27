from __future__ import annotations

import base64
import csv
import datetime as dt
import tempfile
import unittest
from pathlib import Path

from openpyxl import load_workbook

from collector.collect_candidates import (
    Candidate,
    CollectionLog,
    DetectionEntry,
    QuerySpec,
    SCHEMA,
    append_detection_entries,
    canonicalize_url,
    constrain_query_specs,
    contact_campaign_id,
    data_manifest,
    discover_related_internal_links,
    discovery_candidate_relevant,
    discovery_relevance_score,
    expand_query_specs,
    extract_title_text,
    extraction_failure_record,
    existing_fingerprints,
    load_candidate_queue,
    load_query_specs,
    load_seed_candidates,
    mask_text,
    masking_validation,
    make_record,
    near_duplicate_id,
    prepare_detection_workbook,
    relevance_gate_reason,
    safe_spreadsheet_text,
    save_candidate_queue,
    save_restricted_workbook,
    text_quality_reason,
    terminal_attempt_hashes,
    unwrap_search_result_url,
    upgrade_collection_log_schema,
    upgrade_existing_csv_schema,
)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "(양식) 탐지내역.xlsx"


class CollectorTests(unittest.TestCase):
    def test_bing_redirect_is_unwrapped_without_request(self) -> None:
        target = "https://example.com/public/post/1"
        encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        wrapped = f"https://www.bing.com/ck/a?u=a1{encoded}&ntb=1"
        self.assertEqual(unwrap_search_result_url(wrapped), target)

    def test_duckduckgo_redirect_is_unwrapped_without_request(self) -> None:
        target = "https://example.com/public/post/2"
        wrapped = f"https://duckduckgo.com/l/?uddg={target}"
        self.assertEqual(unwrap_search_result_url(wrapped), target)

    def test_contact_data_is_masked(self) -> None:
        text = (
            "문의 test@example.com, 010-1234-5678, 텔레그램 sample_id "
            "홈페이지https://example.com/path"
        )
        masked = mask_text(text)
        self.assertIn("[EMAIL]", masked)
        self.assertIn("[PHONE]", masked)
        self.assertIn("[MESSENGER_ID]", masked)
        self.assertIn("홈페이지[CONTACT_URL]", masked)
        self.assertNotIn("sample_id", masked)
        self.assertNotIn("https://", masked)

    def test_spreadsheet_formula_prefix_is_neutralized(self) -> None:
        self.assertEqual(mask_text('=HYPERLINK("bad")'), '\'=HYPERLINK("bad")')
        self.assertEqual(safe_spreadsheet_text("+cmd"), "'+cmd")

    def test_tracking_parameters_and_fragment_are_removed(self) -> None:
        url = canonicalize_url("https://Example.com/post?id=7&utm_source=test#part")
        self.assertEqual(url, "https://example.com/post?id=7")

    def test_contact_campaign_uses_hmac_without_plaintext(self) -> None:
        campaign = contact_campaign_id(
            b"test-key", "문의 test@example.com 010-1234-5678"
        )
        self.assertTrue(campaign.startswith("contact-hmac:"))
        self.assertNotIn("example.com", campaign)
        self.assertEqual(
            campaign,
            contact_campaign_id(b"test-key", "010-1234-5678 / test@example.com"),
        )

    def test_simhash_is_stable_for_equivalent_token_order(self) -> None:
        first = near_duplicate_id("제목", "반복 문구 반복 문구")
        second = near_duplicate_id("제목", "반복 문구 반복 문구")
        self.assertEqual(first, second)
        self.assertRegex(first, r"^simhash64:[0-9a-f]{16}$")

    def test_existing_fingerprints_supports_current_and_legacy_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "candidates_masked.csv"
            with path.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "near_duplicate_fingerprint",
                        "near_duplicate_cluster",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "near_duplicate_fingerprint": "simhash64:current",
                        "near_duplicate_cluster": "simhash64:legacy-alias",
                    }
                )
                writer.writerow(
                    {
                        "near_duplicate_fingerprint": "",
                        "near_duplicate_cluster": "simhash64:legacy",
                    }
                )
            self.assertEqual(
                existing_fingerprints(path),
                {"simhash64:current", "simhash64:legacy"},
            )

    def test_private_query_yaml_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "queries.local.yaml"
            path.write_text(
                "groups:\n"
                "  - name: internal_example\n"
                "    detection_type: 개인정보DB\n"
                "    queries:\n"
                "      - private query\n",
                encoding="utf-8",
            )
            specs = load_query_specs(path)
            self.assertEqual(len(specs), 1)
            self.assertEqual(specs[0].group, "internal_example")
            self.assertEqual(specs[0].detection_type, "개인정보DB")

    def test_query_variants_are_created_in_stable_order(self) -> None:
        specs = [QuerySpec("group", "기타", "테스트 문의")]
        expanded = expand_query_specs(specs, 4)
        self.assertEqual(len(expanded), 4)
        self.assertEqual(expanded[0].query, "테스트 문의")
        self.assertEqual(expanded[-1].query, "테스트 문의 문의")

    def test_strict_queries_use_phrases_and_negative_filters(self) -> None:
        specs = [QuerySpec("group", "기타", "고객 DB 판매")]
        constrained = constrain_query_specs(specs)
        self.assertEqual(len(constrained), 4)
        self.assertTrue(constrained[0].query.startswith("고객 DB 판매"))
        self.assertTrue(constrained[1].query.startswith('"고객 DB 판매"'))
        self.assertTrue(all("-개인정보처리방침" in item.query for item in constrained))

    def test_search_snippet_prefilter_requires_target_and_trade_context(self) -> None:
        relevant = Candidate(
            "https://example.com/post",
            "group",
            "기타",
            discovery_text="고객 DB를 대량 판매한다는 게시물과 텔레그램 문의 안내",
        )
        generic = Candidate(
            "https://example.com/help",
            "group",
            "기타",
            discovery_text="고객센터에서 개인정보 처리방침을 확인하세요",
        )
        self.assertTrue(discovery_candidate_relevant(relevant))
        self.assertFalse(discovery_candidate_relevant(generic))
        self.assertGreater(
            discovery_relevance_score(relevant),
            discovery_relevance_score(generic),
        )

    def test_relevance_gate_keeps_local_trade_and_contact_signals(self) -> None:
        reason = relevance_gate_reason(
            "고객 DB 판매합니다",
            "최신 자료 대량 보유, 건당 단가 문의 텔레그램 [MESSENGER_ID]",
            "https://board.example/post/7",
            "unknown",
            "strict",
        )
        self.assertEqual(reason, "")

    def test_relevance_gate_rejects_policy_and_search_pages(self) -> None:
        policy_reason = relevance_gate_reason(
            "개인정보 처리방침",
            "고객정보를 보유하며 상품 구매 문의는 고객센터로 연락하세요.",
            "https://shop.example/privacy",
            "unknown",
            "review",
        )
        search_reason = relevance_gate_reason(
            "고객 DB 판매 검색",
            "검색 결과입니다. 텔레그램 문의",
            "https://board.example/search?q=test",
            "search_reflection",
            "review",
        )
        self.assertEqual(policy_reason, "excluded_document_type")
        self.assertEqual(search_reason, "excluded_page_type")
        self.assertEqual(
            relevance_gate_reason(
                "검색 결과",
                "공개 게시물 목록",
                "https://board.example/search?q=test",
                "search_result_list",
                "off",
            ),
            "excluded_page_type",
        )

    def test_review_gate_requires_title_signal_but_keeps_topical_news(self) -> None:
        generic = relevance_gate_reason(
            "전자계약 서비스 주요 기능",
            "고객 개인정보를 보유하며 계약 거래 문의는 [EMAIL]로 받습니다.",
            "https://service.example/features",
            "unknown",
            "review",
        )
        generic_account_trade = relevance_gate_reason(
            "거래중지 계좌 해지 방법",
            "오래 사용하지 않은 통장의 거래를 다시 시작하고 싶습니다.",
            "https://qna.example/question/2",
            "unknown",
            "review",
        )
        topical_news = relevance_gate_reason(
            "고객 DB 판매 게시물 적발",
            "개인정보 명단을 대량으로 거래한 사례가 확인됐다는 보도입니다.",
            "https://news.example/article/1",
            "news_or_education",
            "review",
        )
        self.assertEqual(generic, "missing_title_signal")
        self.assertEqual(generic_account_trade, "missing_title_signal")
        self.assertEqual(topical_news, "")

    def test_seed_csv_deduplicates_urls(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "seeds.local.csv"
            path.write_text(
                "url,detection_type,query_group\n"
                "https://example.com/post,기타,seed\n"
                "https://example.com/post#fragment,기타,seed\n",
                encoding="utf-8",
            )
            candidates = load_seed_candidates(path)
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].url, "https://example.com/post")

    def test_private_candidate_queue_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / ".private" / "candidate_queue.jsonl"
            expected = [Candidate("https://example.com/post", "group", "기타")]
            save_candidate_queue(path, expected)
            loaded = load_candidate_queue(path)
            self.assertEqual(loaded, expected)
            self.assertEqual(load_seed_candidates(path), expected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_terminal_failures_are_skipped_on_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "collection_log.csv"
            path.write_text(
                "url_hmac,query_group,outcome,http_status,reason,text_chars,extraction_method\n"
                "done,g,skipped,,robots_disallowed,0,\n"
                "short,g,failed,200,insufficient_text,20,visible_body_fallback\n"
                "retry,g,failed,,ReadTimeout,0,\n",
                encoding="utf-8",
            )
            self.assertEqual(terminal_attempt_hashes(path), {"done", "short"})

    def test_collection_log_upgrade_adds_attempt_time_column(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "collection_log.csv"
            path.write_text(
                "url_hmac,query_group,outcome,http_status,reason,text_chars,extraction_method\n"
                "abc,g,failed,200,insufficient_text,20,visible_body_fallback\n",
                encoding="utf-8",
            )
            upgrade_collection_log_schema(path)
            with path.open(encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                rows = list(reader)
            self.assertIn("attempted_at", reader.fieldnames)
            self.assertEqual(rows[0]["text_chars"], "20")

    def test_existing_dataset_upgrade_preserves_legacy_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "candidates_masked.csv"
            legacy_fields = [
                field
                for field in SCHEMA
                if field not in {"extraction_status", "near_duplicate_fingerprint"}
            ]
            row = {field: "" for field in legacy_fields}
            row.update(
                {
                    "sample_id": "EG-0001",
                    "source_type": "public_web_search",
                    "live_status": "true",
                    "page_type": "reflected_search_page",
                    "near_duplicate_cluster": "simhash64:1234567890abcdef",
                }
            )
            with path.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=legacy_fields)
                writer.writeheader()
                writer.writerow(row)
            upgrade_existing_csv_schema(path)
            with path.open(encoding="utf-8-sig", newline="") as handle:
                upgraded = next(csv.DictReader(handle))
            self.assertEqual(upgraded["sample_id"], "EG-0001")
            self.assertEqual(upgraded["source_type"], "search")
            self.assertEqual(upgraded["live_status"], "accessible")
            self.assertEqual(upgraded["page_type"], "search_reflection")
            self.assertEqual(
                upgraded["near_duplicate_fingerprint"],
                upgraded["near_duplicate_cluster"],
            )

    def test_extraction_failure_has_standard_status_and_no_raw_url(self) -> None:
        log = CollectionLog(
            "digest-only",
            "group",
            "failed",
            "200",
            "insufficient_text",
            25,
            "main_container_short",
        )
        failure = extraction_failure_record(log)
        self.assertIsNotNone(failure)
        self.assertEqual(failure["extraction_status"], "partial")
        self.assertRegex(failure["attempted_at"], r"^\d{4}-\d{2}-\d{2}T")

    def test_record_uses_standard_handoff_values(self) -> None:
        candidate = Candidate(
            "https://example.com/post/1", "seed-group", "기타", source_type="seed"
        )
        record = make_record(
            7,
            candidate,
            candidate.url,
            200,
            "테스트 제목",
            "충분한 공개 예시 본문입니다. " * 10,
            b"test-key",
        )
        self.assertEqual(record["sample_id"], "EG-000007")
        self.assertEqual(record["source_type"], "seed")
        self.assertEqual(record["live_status"], "accessible")
        self.assertEqual(record["extraction_status"], "success")
        self.assertEqual(
            record["near_duplicate_cluster"],
            record["near_duplicate_fingerprint"],
        )

    def test_masking_report_and_manifest_include_integrity_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir)
            csv_path = out / "candidates_masked.csv"
            csv_path.write_text(
                "masked_title,masked_text\n제목,연락처 [PHONE]\n",
                encoding="utf-8",
            )
            report = masking_validation(csv_path, "pilot-v1")
            self.assertTrue(report["passed"])
            manifest = data_manifest(out, "pilot-v1", [csv_path], {"target": 1})
            self.assertEqual(manifest["files"][0]["rows"], 1)
            self.assertRegex(manifest["files"][0]["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(manifest["settings"]["target"], 1)

    def test_extracts_short_post_from_main_container(self) -> None:
        html = """
        <html><head><title>테스트 게시물</title></head><body>
        <nav>메뉴 메뉴 메뉴</nav>
        <main><p>이것은 본문 추출 테스트를 위한 공개 예시 문장입니다.</p>
        <p>게시물의 핵심 내용이 메뉴보다 우선해서 저장되어야 합니다.</p></main>
        </body></html>
        """
        title, text, method = extract_title_text(html, "https://example.com/post")
        self.assertEqual(title, "테스트 게시물")
        self.assertIn("본문 추출 테스트", text)
        self.assertNotIn("메뉴 메뉴", text)
        self.assertIn(method, {"trafilatura_precision", "main_container"})

    def test_challenge_page_fails_text_quality_gate(self) -> None:
        text = "Checking your browser before accessing the requested public page."
        self.assertEqual(
            text_quality_reason(text, 40), "challenge_or_access_page"
        )

    def test_korean_text_gate_rejects_english_only_page(self) -> None:
        text = "This is a sufficiently long English page with meaningful words."
        self.assertEqual(
            text_quality_reason(text, 40, minimum_korean_chars=5),
            "insufficient_korean_text",
        )

    def test_related_internal_links_are_bounded_and_same_site(self) -> None:
        html = """
        <a href="/board/view?id=2">고객 DB 관련 게시물</a>
        <a href="/login">로그인</a>
        <a href="https://outside.example/post/3">개인정보</a>
        <a href="/search?q=개인정보">검색</a>
        """
        links = discover_related_internal_links(
            html, "https://example.com/board/view?id=1", 5
        )
        self.assertEqual(links, ["https://example.com/board/view?id=2"])

    def test_template_is_preserved_and_rows_expand(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "restricted" / "result.xlsx"
            workbook, sheet = prepare_detection_workbook(TEMPLATE, output, resume=False)
            entries = [
                DetectionEntry(
                    detected_on=dt.date(2026, 8, 17),
                    url=f"https://example.com/post/{index}",
                    detection_type="개인정보DB",
                    registrant="테스트",
                )
                for index in range(1, 35)
            ]
            append_detection_entries(sheet, entries)
            save_restricted_workbook(workbook, output)

            saved = load_workbook(output)["8월"]
            self.assertEqual(saved["A4"].value, 1)
            self.assertEqual(saved["A37"].value, 34)
            self.assertEqual(saved["D4"].value, "개인정보DB")
            self.assertEqual(saved["E4"].value, "테스트")
            self.assertEqual(saved["C4"].hyperlink.target, "https://example.com/post/1")
            self.assertIn("예시 내용", saved["H4"].value)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
