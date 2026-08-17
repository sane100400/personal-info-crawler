from __future__ import annotations

import base64
import datetime as dt
import tempfile
import unittest
from pathlib import Path

from openpyxl import load_workbook

from collector.collect_candidates import (
    DetectionEntry,
    append_detection_entries,
    canonicalize_url,
    contact_campaign_id,
    load_query_specs,
    load_seed_candidates,
    mask_text,
    near_duplicate_id,
    prepare_detection_workbook,
    safe_spreadsheet_text,
    save_restricted_workbook,
    unwrap_search_result_url,
)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "(양식) 탐지내역.xlsx"


class CollectorTests(unittest.TestCase):
    def test_bing_redirect_is_unwrapped_without_request(self) -> None:
        target = "https://example.com/public/post/1"
        encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        wrapped = f"https://www.bing.com/ck/a?u=a1{encoded}&ntb=1"
        self.assertEqual(unwrap_search_result_url(wrapped), target)

    def test_contact_data_is_masked(self) -> None:
        text = "문의 test@example.com, 010-1234-5678, 텔레그램 sample_id"
        masked = mask_text(text)
        self.assertIn("[EMAIL]", masked)
        self.assertIn("[PHONE]", masked)
        self.assertIn("[MESSENGER_ID]", masked)
        self.assertNotIn("sample_id", masked)

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
