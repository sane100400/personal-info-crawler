from __future__ import annotations

import base64
import csv
import datetime as dt
import tempfile
import unittest
from pathlib import Path

from openpyxl import load_workbook

from collector.build_labeling_pilot import (
    SourceRow,
    assign_near_duplicate_clusters,
    intent_bucket,
    prioritize_rows,
    select_rows,
    strict_bucket,
)

from collector.collect_candidates import (
    Candidate,
    CollectionLog,
    DetectionEntry,
    QuerySpec,
    SCHEMA,
    append_detection_entries,
    canonicalize_url,
    classify_page_type,
    constrain_query_specs,
    contact_campaign_id,
    data_manifest,
    discover_google_api_candidates,
    discover_related_internal_links,
    discovery_candidate_relevant,
    discovery_candidate_passes,
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
    merge_candidates,
    mine_keyword_expansions,
    near_duplicate_id,
    ordered_provider_names,
    prefilter_seed_candidates,
    prepare_detection_workbook,
    public_content_fallback_url,
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
    def test_intent_priority_does_not_require_contact_details(self) -> None:
        self.assertEqual(intent_bucket(""), "intent_priority")
        self.assertEqual(
            intent_bucket("missing_concrete_contact"), "intent_priority"
        )
        self.assertEqual(
            intent_bucket("missing_body_offer"), "boundary_review"
        )
        self.assertEqual(
            intent_bucket("excluded_reporting_context"), "hard_negative"
        )

    def test_labeling_pilot_prioritizes_strict_and_balances_reasons(self) -> None:
        def item(index: int, reason: str) -> SourceRow:
            return SourceRow(
                row={"registrable_domain": f"d{index}.example"},
                candidate=Candidate(f"https://d{index}.example/post", "g", "기타"),
                source=Path("source"),
                source_tier="primary",
                gate_reason=reason,
                selection_bucket=strict_bucket(reason),
            )

        rows = [
            item(1, "excluded_reporting_context"),
            item(2, ""),
            item(3, "excluded_reporting_context"),
            item(4, "excluded_page_type"),
            item(5, "missing_concrete_contact"),
        ]
        ordered = prioritize_rows(rows, priority_enabled=True)
        self.assertEqual(
            [row.gate_reason for row in ordered],
            [
                "",
                "missing_concrete_contact",
                "excluded_reporting_context",
                "excluded_page_type",
                "excluded_reporting_context",
            ],
        )

    def test_labeling_pilot_honors_domain_cap(self) -> None:
        rows = [
            SourceRow(
                row={"registrable_domain": "same.example"},
                candidate=Candidate(f"https://same.example/{index}", "g", "기타"),
                source=Path("source"),
                source_tier="primary",
            )
            for index in range(3)
        ]
        rows.append(
            SourceRow(
                row={"registrable_domain": "other.example"},
                candidate=Candidate("https://other.example/1", "g", "기타"),
                source=Path("source"),
                source_tier="primary",
            )
        )
        selected = select_rows(rows, target=2, max_per_domain=1)
        self.assertEqual(
            [row.row["registrable_domain"] for row in selected],
            ["same.example", "other.example"],
        )

    def test_labeling_pilot_assigns_duplicate_clusters(self) -> None:
        rows = [
            {"masked_title": "계정 판매", "masked_text": "대량 계정 판매 문의"},
            {"masked_title": "계정 판매", "masked_text": "대량 계정 판매 문의"},
            {"masked_title": "다른 글", "masked_text": "전혀 다른 정상 문맥"},
        ]
        assign_near_duplicate_clusters(rows)
        self.assertEqual(
            rows[0]["near_duplicate_cluster"],
            rows[1]["near_duplicate_cluster"],
        )
        self.assertNotEqual(
            rows[0]["near_duplicate_cluster"],
            rows[2]["near_duplicate_cluster"],
        )

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

    def test_telegram_shorthand_contact_is_masked(self) -> None:
        masked = mask_text("디비 텔그 sample_id 문의")
        self.assertIn("텔그 [MESSENGER_ID]", masked)
        self.assertNotIn("sample_id", masked)

    def test_messenger_contact_url_keeps_channel_but_masks_handle(self) -> None:
        masked = mask_text(
            "상담 https://t.me/private_handle 또는 https://open.kakao.com/o/secret"
        )
        self.assertIn("텔레그램 [MESSENGER_ID]", masked)
        self.assertIn("카카오톡 [MESSENGER_ID]", masked)
        self.assertNotIn("private_handle", masked)
        self.assertNotIn("/secret", masked)

    def test_spreadsheet_formula_prefix_is_neutralized(self) -> None:
        self.assertEqual(mask_text('=HYPERLINK("bad")'), '\'=HYPERLINK("bad")')
        self.assertEqual(safe_spreadsheet_text("+cmd"), "'+cmd")

    def test_tracking_parameters_and_fragment_are_removed(self) -> None:
        url = canonicalize_url("https://Example.com/post?id=7&utm_source=test#part")
        self.assertEqual(url, "https://example.com/post?id=7")

    def test_public_naver_blog_frame_has_mobile_fallback(self) -> None:
        self.assertEqual(
            public_content_fallback_url(
                "https://blog.naver.com/public_writer/223456789012"
            ),
            "https://m.blog.naver.com/public_writer/223456789012",
        )
        self.assertIsNone(
            public_content_fallback_url("https://example.com/public/post/1")
        )

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

    def test_requested_search_provider_order_is_preserved(self) -> None:
        available = ["naver", "bing", "google"]
        self.assertEqual(
            ordered_provider_names(available, ["google", "naver", "google"]),
            ["google", "naver"],
        )
        self.assertEqual(ordered_provider_names(available, None), available)

    def test_google_api_discovery_uses_snippet_relevance_without_key_output(self) -> None:
        class FakeResponse:
            status_code = 200

            def json(self):
                return {
                    "items": [
                        {
                            "link": "https://example.com/public/post/1",
                            "title": "디비 텔그",
                            "snippet": "판매 관련 연락 안내",
                        }
                    ]
                }

            def close(self) -> None:
                pass

        class FakeSession:
            def __init__(self) -> None:
                self.params = {}

            def get(self, _url, **kwargs):
                self.params = kwargs["params"]
                return FakeResponse()

        session = FakeSession()
        candidates = discover_google_api_candidates(
            session,
            [QuerySpec("group", "개인정보DB", "디비 텔그")],
            desired=1,
            pages=1,
            delay=0,
            prefilter_mode="review",
            api_key="secret-key",
            cse_id="engine-id",
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].url, "https://example.com/public/post/1")
        self.assertEqual(session.params["key"], "secret-key")

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
        target_only = Candidate(
            "https://example.com/news",
            "group",
            "기타",
            discovery_text="개인정보 유출 사고를 다룬 국내 기사",
        )
        self.assertTrue(discovery_candidate_passes(target_only, "labeling"))
        self.assertFalse(discovery_candidate_passes(target_only, "review"))
        hard_negative = Candidate(
            "https://example.com/database-guide",
            "group",
            "기타",
            discovery_text="DB 계정 관리 방법을 설명하는 기술 문서",
        )
        self.assertTrue(discovery_candidate_passes(hard_negative, "labeling"))
        self.assertFalse(discovery_candidate_passes(hard_negative, "review"))
        trade_only = Candidate(
            "https://example.com/classified/7",
            "group",
            "기타",
            discovery_text="대량 판매합니다. 자세한 품목은 본문을 확인하세요.",
        )
        self.assertTrue(discovery_candidate_passes(trade_only, "labeling"))
        self.assertFalse(discovery_candidate_passes(trade_only, "review"))
        self.assertGreater(
            discovery_relevance_score(relevant),
            discovery_relevance_score(generic),
        )

    def test_strict_search_prefilter_requires_local_direct_offer(self) -> None:
        direct_offer = Candidate(
            "https://example.com/post/positive",
            "group",
            "개인정보DB",
            discovery_text=(
                "고객 DB 판매합니다. 건당 단가 문의 "
                "https://t.me/private_handle"
            ),
        )
        reporting = Candidate(
            "https://example.com/news/negative",
            "group",
            "개인정보DB",
            discovery_text="고객 DB 판매 사건을 경찰이 적발한 텔레그램 관련 기사",
        )
        destination_contact_deferred = Candidate(
            "https://example.com/post/weak",
            "group",
            "개인정보DB",
            discovery_text="고객 DB 판매합니다. 텔레그램에서 안내합니다.",
        )
        fused_card = Candidate(
            "https://example.com/post/fused",
            "group",
            "개인정보DB",
            discovery_text=(
                "고객 DB 관련 보안 안내 "
                + "일반 설명 " * 80
                + "중고 자동차 부품 판매합니다. 연락 [PHONE]"
            ),
        )
        self.assertTrue(discovery_candidate_passes(direct_offer, "strict"))
        self.assertFalse(discovery_candidate_passes(reporting, "strict"))
        self.assertTrue(
            discovery_candidate_passes(destination_contact_deferred, "strict")
        )
        self.assertFalse(discovery_candidate_passes(fused_card, "strict"))

    def test_shorthand_target_and_contact_pass_review_prefilter(self) -> None:
        shorthand = Candidate(
            "https://example.com/post/8",
            "group",
            "개인정보DB",
            discovery_text="디비 텔그 문의",
        )
        brand_noise = Candidate(
            "https://example.com/news/8",
            "group",
            "개인정보DB",
            discovery_text="DB손해보험 농구단 소식",
        )
        self.assertTrue(discovery_candidate_relevant(shorthand))
        self.assertFalse(discovery_candidate_relevant(brand_noise))
        self.assertTrue(discovery_candidate_passes(shorthand, "review"))
        self.assertEqual(
            relevance_gate_reason(
                "디비 텔그",
                "보유 자료 관련 연락 안내입니다.",
                "https://example.com/post/8",
                "unknown",
                "review",
            ),
            "",
        )

    def test_keyword_expansion_requires_repetition_across_domains(self) -> None:
        candidates = [
            Candidate(
                "https://one.example/post/1",
                "personal_info_db",
                "개인정보DB",
                discovery_text="고객디비 텔그 문의",
            ),
            Candidate(
                "https://two.example/post/2",
                "personal_info_db",
                "개인정보DB",
                discovery_text="고객디비 텔그 연락",
            ),
            Candidate(
                "https://one.example/post/3",
                "portal_accounts",
                "포털ID",
                discovery_text="희귀아이디 텔그 문의",
            ),
        ]
        expansions = mine_keyword_expansions(
            candidates,
            [QuerySpec("seed", "개인정보DB", "디비 텔그")],
            round_number=1,
            limit=10,
            minimum_domains=2,
        )
        self.assertEqual([item.query for item in expansions], ["고객디비 텔그"])
        self.assertEqual(expansions[0].domain_frequency, 2)

    def test_candidate_merge_combines_snippet_evidence(self) -> None:
        current = [
            Candidate(
                "https://example.com/post",
                "group",
                "기타",
                discovery_text="디비 판매",
                search_provider="bing",
            )
        ]
        additions = [
            Candidate(
                "https://example.com/post",
                "group",
                "기타",
                discovery_text="텔그 문의",
                search_provider="google_api",
            )
        ]
        merged = merge_candidates(current, additions)
        self.assertEqual(len(merged), 1)
        self.assertIn("디비 판매", merged[0].discovery_text)
        self.assertIn("텔그 문의", merged[0].discovery_text)
        self.assertEqual(merged[0].search_provider, "bing,google_api")

    def test_contact_required_expansion_rejects_trade_only_pair(self) -> None:
        candidates = [
            Candidate(
                "https://one.example/post/1",
                "portal_accounts",
                "포털ID",
                discovery_text="계정 거래 안내",
            ),
            Candidate(
                "https://two.example/post/2",
                "portal_accounts",
                "포털ID",
                discovery_text="계정 거래 게시물",
            ),
        ]
        expansions = mine_keyword_expansions(
            candidates,
            [],
            round_number=1,
            limit=10,
            minimum_domains=2,
            require_contact=True,
        )
        self.assertEqual(expansions, [])

    def test_identity_document_forgery_passes_review_gate(self) -> None:
        self.assertEqual(
            relevance_gate_reason(
                "신분증 위조 텔그",
                "제작 관련 연락 안내입니다.",
                "https://example.com/post/9",
                "unknown",
                "review",
            ),
            "",
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

    def test_intent_gate_prioritizes_direct_offer_without_contact(self) -> None:
        candidate = Candidate(
            "https://board.example/post/intent",
            "group",
            "개인정보DB",
            discovery_text="고객 DB를 대량 보유하고 판매합니다. 건당 단가 안내",
        )
        self.assertTrue(discovery_candidate_passes(candidate, "intent"))
        self.assertEqual(
            relevance_gate_reason(
                "고객 DB 판매합니다",
                "최신 고객 명단을 대량 보유하고 건당 판매합니다.",
                candidate.url,
                "unknown",
                "intent",
            ),
            "",
        )
        self.assertEqual(
            relevance_gate_reason(
                "고객 DB 판매합니다",
                "최신 고객 명단을 대량 보유하고 건당 판매합니다.",
                candidate.url,
                "unknown",
                "strict",
            ),
            "missing_concrete_contact",
        )

    def test_intent_gate_rejects_reporting_and_missing_offer(self) -> None:
        reporting = relevance_gate_reason(
            "고객 DB 판매 게시물 적발",
            "경찰이 개인정보 명단 거래 사건을 수사하고 있습니다.",
            "https://news.example/article/intent",
            "news_or_education",
            "intent",
        )
        no_offer = relevance_gate_reason(
            "고객 DB 안내",
            "고객정보 데이터베이스의 보관 방식을 설명합니다.",
            "https://board.example/post/no-offer",
            "unknown",
            "intent",
        )
        self.assertEqual(reporting, "excluded_page_type")
        self.assertEqual(no_offer, "missing_body_offer")

    def test_strict_gate_rejects_reporting_and_generic_links(self) -> None:
        reporting = relevance_gate_reason(
            "고객 DB 판매 게시물 적발",
            "경찰이 텔레그램을 통해 거래한 사건을 검거했다는 기사입니다.",
            "https://news.example/article/1",
            "news_or_education",
            "strict",
        )
        generic_link = relevance_gate_reason(
            "고객 DB 판매합니다",
            "대량 보유 중이며 주문 문의는 홈페이지 [CONTACT_URL]에서 받습니다.",
            "https://board.example/post/1",
            "unknown",
            "strict",
        )
        self.assertEqual(reporting, "excluded_page_type")
        self.assertEqual(generic_link, "missing_concrete_contact")

    def test_strict_gate_rejects_scam_warning_disguised_by_sales_title(self) -> None:
        reason = relevance_gate_reason(
            "SNS 계정 싸게 팝니다",
            "사기입니다. 돈을 보낸 뒤 피해를 입어 사이버수사대에 신고했습니다.",
            "https://community.example/post/2",
            "unknown",
            "strict",
            "SNS 계정 판매 연락 [PHONE]",
        )
        self.assertEqual(reason, "excluded_reporting_context")

    def test_strict_gate_rejects_bulk_messaging_service_context(self) -> None:
        reason = relevance_gate_reason(
            "대량문자 발송 서비스",
            (
                "연락처를 주소록에 저장해 대량문자를 발송합니다. "
                "회원 할인 단가를 제공하며 상담은 텔그 [MESSENGER_ID]"
            ),
            "https://blog.example/post/3",
            "unknown",
            "strict",
        )
        self.assertEqual(reason, "missing_relevant_target")

    def test_strict_gate_keeps_account_verification_buying_post(self) -> None:
        reason = relevance_gate_reason(
            "가입인증 삽니다",
            "성인 본인인증 자료를 매입합니다. 문의 텔레그램 [MESSENGER_ID]",
            "https://board.example/post/4",
            "unknown",
            "strict",
        )
        self.assertEqual(reason, "")

    def test_strict_gate_rejects_single_game_account_trade(self) -> None:
        reason = relevance_gate_reason(
            "게임 계정 하나 팝니다",
            "실사용하던 계정을 10만원에 판매합니다. 문의 [PHONE]",
            "https://market.example/post/5",
            "unknown",
            "strict",
        )
        self.assertEqual(reason, "excluded_single_account_trade")

        linked_platform_account = relevance_gate_reason(
            "구글 계정 팝니다",
            "로드 모바일에서 실사용하던 구글 연동 계정을 판매합니다. 문의 [PHONE]",
            "https://market.example/post/6",
            "unknown",
            "strict",
        )
        self.assertEqual(linked_platform_account, "excluded_single_account_trade")

    def test_strict_gate_keeps_forgery_service_offer(self) -> None:
        reason = relevance_gate_reason(
            "각종 신분증 위조 전문",
            "주민등록증과 운전면허증 제작 가능. 의뢰 문의 텔레그램 [MESSENGER_ID]",
            "https://board.example/post/7",
            "unknown",
            "strict",
        )
        self.assertEqual(reason, "")

    def test_strict_gate_does_not_treat_body_link_words_as_document_type(self) -> None:
        reason = relevance_gate_reason(
            "스토리 계좌매입 채널",
            (
                "계좌매입 후 즉시 정산합니다. 편하게 문의주십쇼 "
                "텔레그램 [MESSENGER_ID]. 채널 바로가기와 AV위키 제휴 안내."
            ),
            "https://t.me/public_channel",
            "unknown",
            "strict",
        )
        self.assertEqual(reason, "")

    def test_strict_gate_rejects_explicitly_negated_offer(self) -> None:
        reason = relevance_gate_reason(
            "종토방 제휴",
            (
                "유심, 통장대여, 코인이체, 계정매입 등 피싱과 관련된 "
                "제휴는 받지 않습니다. 텔레그램 [MESSENGER_ID]"
            ),
            "https://t.me/public_channel",
            "public_messenger_page",
            "strict",
        )
        self.assertNotEqual(reason, "")

    def test_strict_gate_can_use_strong_discovery_evidence(self) -> None:
        reason = relevance_gate_reason(
            "서비스 홍보",
            "주식 고객 DB를 대량 보유하고 판매합니다. 건당 단가 안내 가능합니다.",
            "https://community.example/service/1",
            "unknown",
            "strict",
            "주식 디비 판매합니다. 텔레그램 https://t.me/private_handle 문의",
        )
        self.assertEqual(reason, "")

    def test_strict_gate_rejects_unrelated_destination_despite_search_snippet(self) -> None:
        reason = relevance_gate_reason(
            "기업 홈페이지",
            "ICT 인프라 구축과 기술 컨설팅 서비스를 제공합니다.",
            "https://company.example/",
            "unknown",
            "strict",
            "고객 DB 판매합니다. 텔레그램 https://t.me/private_handle 문의",
        )
        self.assertEqual(reason, "missing_relevant_target")

    def test_input_parameter_reflection_is_classified_as_search_reflection(self) -> None:
        page_type = classify_page_type(
            "https://calculator.example/input?i=customer+db+sale",
            "customer db sale - calculator",
            "customer db sale natural language input",
        )
        self.assertEqual(page_type, "search_reflection")

    def test_forum_index_is_classified_as_search_result_list(self) -> None:
        page_type = classify_page_type(
            "https://board.example/pds",
            "자료실",
            "번호 제목 작성자 작성일 추천 조회 3010 개인통장 매입 문의",
        )
        self.assertEqual(page_type, "search_result_list")

    def test_public_telegram_page_has_distinct_page_type(self) -> None:
        page_type = classify_page_type(
            "https://t.me/public_channel",
            "계좌매입 채널",
            "계좌 매입 문의 텔레그램 [MESSENGER_ID]",
        )
        self.assertEqual(page_type, "public_messenger_page")

    def test_labeling_gate_keeps_topical_hard_negative(self) -> None:
        reason = relevance_gate_reason(
            "개인정보 유출 사고 안내",
            "피해 확인 방법을 설명하며 판매나 구매 의사는 없는 기사입니다.",
            "https://news.example/article/7",
            "news_or_education",
            "labeling",
        )
        self.assertEqual(reason, "")
        sidebar_noise = relevance_gate_reason(
            "여름맞이 경품 이벤트",
            "이벤트 안내입니다. 인기글: 고객 DB 판매 관련 문의",
            "https://community.example/event/9",
            "unknown",
            "labeling",
        )
        self.assertEqual(sidebar_noise, "missing_relevant_target")
        trade_title = relevance_gate_reason(
            "대량 판매합니다",
            "자세한 거래 대상은 게시물 본문을 확인하세요.",
            "https://community.example/post/10",
            "unknown",
            "labeling",
        )
        contact_with_target_lead = relevance_gate_reason(
            "텔레그램 문의",
            "고객 DB와 계정 관련 내용을 안내합니다.",
            "https://community.example/post/11",
            "unknown",
            "labeling",
        )
        generic_contact = relevance_gate_reason(
            "문의하기",
            "행사 참여 방법을 안내합니다.",
            "https://community.example/event/12",
            "unknown",
            "labeling",
        )
        self.assertEqual(trade_title, "")
        self.assertEqual(contact_with_target_lead, "")
        self.assertEqual(generic_contact, "missing_relevant_target")

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

    def test_prior_search_queue_is_prefiltered_but_manual_seed_is_retained(self) -> None:
        direct = Candidate(
            "https://example.com/direct",
            "group",
            "개인정보DB",
            discovery_text=(
                "고객 DB 판매합니다. 텔레그램 https://t.me/direct 문의"
            ),
        )
        reporting = Candidate(
            "https://example.com/report",
            "group",
            "개인정보DB",
            discovery_text="고객 DB 판매 사건을 경찰이 적발했다는 기사",
        )
        manual = Candidate("https://example.com/manual", "seed", "기타")
        filtered = prefilter_seed_candidates(
            [direct, reporting, manual], "strict"
        )
        self.assertEqual(filtered, [direct, manual])

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

    def test_legacy_board_post_beats_longer_footer(self) -> None:
        html = """
        <html><head><title>여권발급이나 새신분이 필요하신분</title></head>
        <body>
          <table><tr><td class="con_f">
            여권과 신분증 위조 제작 가능합니다. 판매 문의는
            텔레그램 sample_handle 또는 카톡 sample_chat으로 주세요.
            신청 대상과 제작 종류를 확인한 뒤 신속하게 안내한다는 게시물입니다.
          </td></tr></table>
          <footer>고객센터 문의와 저작권 안내입니다. """ + "일반 안내 " * 80 + """</footer>
        </body></html>
        """
        title, text, method = extract_title_text(
            html, "https://board.example/public/post/1"
        )
        self.assertIn("여권과 신분증 위조 제작", text)
        self.assertNotIn("저작권 안내", text)
        self.assertEqual(method, "strong_post_container")

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
