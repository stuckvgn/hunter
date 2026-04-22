"""Unit tests for bounties.py — stdlib unittest, no external deps.

Run with: python3 -m unittest test_bounties -v
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import bounties as b


# ---------- fixtures ----------

HACKERONE_FIXTURE = [
    {
        "handle": "example_corp",
        "id": 1,
        "name": "Example Corp VDP",
        "url": "https://hackerone.com/example_corp",
        "website": "https://example.com",
        "offers_bounties": False,
        "targets": {
            "in_scope": [
                {
                    "asset_identifier": "*.example.com",
                    "asset_type": "URL",
                    "max_severity": "critical",
                    "eligible_for_bounty": False,
                    "instruction": "subdomains included",
                }
            ],
            "out_of_scope": [
                {"asset_identifier": "legacy.example.com", "asset_type": "URL"}
            ],
        },
    },
    {
        "handle": "paid_prog",
        "id": 2,
        "name": "Paid Program",
        "url": "https://hackerone.com/paid_prog",
        "website": None,
        "offers_bounties": True,
        "targets": {"in_scope": [], "out_of_scope": []},
    },
]

BUGCROWD_FIXTURE = [
    {
        "name": "  BC Program  ",
        "url": "https://bugcrowd.com/engagements/bc-prog",
        "allows_disclosure": True,
        "max_payout": 50000,
        "targets": {
            "in_scope": [
                {"type": "api", "target": "https://api.bc.com/", "uri": "https://api.bc.com/", "name": "main api"}
            ],
            "out_of_scope": [],
        },
    },
    {
        "name": "BC VDP",
        "url": "https://bugcrowd.com/engagements/bc-vdp",
        "max_payout": 0,
        "targets": {"in_scope": [], "out_of_scope": []},
    },
]

INTIGRITI_FIXTURE = [
    {
        "id": "abc-123",
        "name": "Intigriti Co",
        "company_handle": "int-co",
        "handle": "int-co",
        "url": "https://www.intigriti.com/programs/int-co/detail",
        "status": "open",
        "min_bounty": {"value": 100, "currency": "USD"},
        "max_bounty": {"value": 10000, "currency": "USD"},
        "targets": {
            "in_scope": [
                {"type": "other", "endpoint": "Hardware", "description": "Hw bugs", "impact": "Tier 1"}
            ],
            "out_of_scope": [],
        },
    },
]

YESWEHACK_FIXTURE = [
    {
        "id": "ywh-co",
        "name": "YWH Co",
        "public": True,
        "disabled": False,
        "min_bounty": 50,
        "max_bounty": 5000,
        "targets": {
            "in_scope": [{"target": "https://ywh.example.com", "type": "web-application"}],
            "out_of_scope": [],
        },
    },
]


class NormalizerTests(unittest.TestCase):
    """Each normalizer must produce the shared shape and handle upstream quirks."""

    def test_hackerone_paid_flag_from_offers_bounties(self):
        self.assertFalse(b._norm_hackerone(HACKERONE_FIXTURE[0])["offers_bounty"])
        self.assertTrue(b._norm_hackerone(HACKERONE_FIXTURE[1])["offers_bounty"])

    def test_hackerone_preserves_scope_metadata(self):
        n = b._norm_hackerone(HACKERONE_FIXTURE[0])
        scope = n["in_scope"][0]
        self.assertEqual(scope["type"], "url")
        self.assertEqual(scope["severity"], "critical")
        self.assertFalse(scope["eligible_for_bounty"])
        self.assertEqual(n["out_of_scope"][0]["target"], "legacy.example.com")

    def test_bugcrowd_handle_derived_from_url(self):
        self.assertEqual(b._norm_bugcrowd(BUGCROWD_FIXTURE[0])["handle"], "bc-prog")

    def test_bugcrowd_name_stripped(self):
        self.assertEqual(b._norm_bugcrowd(BUGCROWD_FIXTURE[0])["name"], "BC Program")

    def test_bugcrowd_vdp_when_max_payout_zero(self):
        self.assertFalse(b._norm_bugcrowd(BUGCROWD_FIXTURE[1])["offers_bounty"])
        self.assertIsNone(b._norm_bugcrowd(BUGCROWD_FIXTURE[1])["max_bounty"])

    def test_intigriti_extracts_bounty_values(self):
        n = b._norm_intigriti(INTIGRITI_FIXTURE[0])
        self.assertEqual(n["min_bounty"], 100)
        self.assertEqual(n["max_bounty"], 10000)
        self.assertTrue(n["offers_bounty"])

    def test_yeswehack_plain_int_bounties(self):
        n = b._norm_yeswehack(YESWEHACK_FIXTURE[0])
        self.assertEqual(n["min_bounty"], 50)
        self.assertEqual(n["max_bounty"], 5000)
        self.assertEqual(n["url"], "https://yeswehack.com/programs/ywh-co")

    def test_normalizer_registry_covers_all_platforms(self):
        self.assertEqual(set(b.NORMALIZERS.keys()), set(b.PLATFORMS))


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.programs = [
            b._norm_hackerone(rec) for rec in HACKERONE_FIXTURE
        ] + [
            b._norm_bugcrowd(rec) for rec in BUGCROWD_FIXTURE
        ] + [
            b._norm_intigriti(rec) for rec in INTIGRITI_FIXTURE
        ] + [
            b._norm_yeswehack(rec) for rec in YESWEHACK_FIXTURE
        ]

    def test_paid_only_excludes_vdp(self):
        out = b.apply_filters(self.programs, paid_only=True)
        self.assertTrue(all(p["offers_bounty"] for p in out))
        self.assertFalse(any(p["handle"] == "example_corp" for p in out))

    def test_vdp_only_excludes_paid(self):
        out = b.apply_filters(self.programs, vdp_only=True)
        self.assertTrue(all(not p["offers_bounty"] for p in out))

    def test_platform_filter(self):
        out = b.apply_filters(self.programs, platforms=["bugcrowd"])
        self.assertEqual({p["platform"] for p in out}, {"bugcrowd"})

    def test_min_bounty_drops_hackerone(self):
        # HackerOne records carry no max_bounty in the upstream dataset,
        # so --min-bounty must (correctly) exclude them.
        out = b.apply_filters(self.programs, min_max_bounty=1)
        self.assertFalse(any(p["platform"] == "hackerone" for p in out))

    def test_min_bounty_threshold(self):
        out = b.apply_filters(self.programs, min_max_bounty=20000)
        self.assertTrue(all((p.get("max_bounty") or 0) >= 20000 for p in out))

    def test_scope_type_filter(self):
        out = b.apply_filters(self.programs, scope_types=["api"])
        # Only the Bugcrowd program has an api scope in the fixture set.
        self.assertEqual([p["handle"] for p in out], ["bc-prog"])

    def test_keyword_matches_name_handle_and_scope_target(self):
        by_name = b.apply_filters(self.programs, keyword="example corp")
        self.assertEqual([p["handle"] for p in by_name], ["example_corp"])
        by_scope = b.apply_filters(self.programs, keyword="api.bc.com")
        self.assertEqual([p["handle"] for p in by_scope], ["bc-prog"])


class FormattingTests(unittest.TestCase):
    def test_fmt_bounty_vdp(self):
        self.assertEqual(b.fmt_bounty({"offers_bounty": False}), "VDP")

    def test_fmt_bounty_range(self):
        self.assertEqual(
            b.fmt_bounty({"offers_bounty": True, "min_bounty": 100, "max_bounty": 5000}),
            "$100-$5000",
        )

    def test_fmt_bounty_max_only(self):
        self.assertEqual(
            b.fmt_bounty({"offers_bounty": True, "min_bounty": None, "max_bounty": 5000}),
            "up to $5000",
        )

    def test_fmt_bounty_unknown_amount(self):
        # HackerOne paid programs have no amounts in the dataset.
        self.assertEqual(
            b.fmt_bounty({"offers_bounty": True, "min_bounty": None, "max_bounty": None}),
            "paid",
        )


class CacheTests(unittest.TestCase):
    """Cache path isolation — important since the real cache is user-global."""

    def test_cache_path_under_cache_dir(self):
        self.assertTrue(str(b.cache_path("hackerone")).endswith("hackerone_data.json"))
        self.assertEqual(b.cache_path("bugcrowd").parent, b.CACHE_DIR)

    def test_ensure_cache_respects_ttl(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = b.CACHE_DIR
            try:
                b.CACHE_DIR = Path(tmp)
                # Pre-populate fresh cache files so ensure_cache skips the network.
                for p in b.PLATFORMS:
                    (Path(tmp) / f"{p}_data.json").write_text("[]")
                with mock.patch.object(b, "fetch_platform") as fake_fetch:
                    b.ensure_cache(force=False)
                    fake_fetch.assert_not_called()
            finally:
                b.CACHE_DIR = original


class EndToEndTests(unittest.TestCase):
    """Drive load_all through cache_path so a single tmp dir covers the CLI flow."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.original_cache = b.CACHE_DIR
        b.CACHE_DIR = Path(self.tmp.name)
        fixtures = {
            "hackerone": HACKERONE_FIXTURE,
            "bugcrowd": BUGCROWD_FIXTURE,
            "intigriti": INTIGRITI_FIXTURE,
            "yeswehack": YESWEHACK_FIXTURE,
        }
        for platform, data in fixtures.items():
            (b.CACHE_DIR / f"{platform}_data.json").write_text(json.dumps(data))

    def tearDown(self):
        b.CACHE_DIR = self.original_cache

    def test_load_all_counts_exactly(self):
        out = b.load_all()
        by_plat = {}
        for p in out:
            by_plat[p["platform"]] = by_plat.get(p["platform"], 0) + 1
        self.assertEqual(by_plat, {"hackerone": 2, "bugcrowd": 2, "intigriti": 1, "yeswehack": 1})

    def test_load_all_platform_subset(self):
        out = b.load_all(["intigriti"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["platform"], "intigriti")

    def test_print_row_renders_expected_columns(self):
        out = b.load_all(["hackerone"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            b.print_row(out[0])
        line = buf.getvalue()
        self.assertIn("hackerone", line)
        self.assertIn("example_corp", line)
        self.assertIn("VDP", line)


if __name__ == "__main__":
    unittest.main()
