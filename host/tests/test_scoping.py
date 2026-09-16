"""Scoping guard — target allow-list, test-PAN policy, and masking."""
from __future__ import annotations

import pytest

from host.scoping import (
    WELL_KNOWN_TEST_BINS,
    Scope,
    ScopeError,
    mask_pan,
    mask_track2,
    parse_target,
)


class TestTargetAllowList:
    def test_no_allow_list_means_nowhere_is_reachable(self):
        """Fail closed: an unconfigured scope must not default to permissive."""
        with pytest.raises(ScopeError, match="No target has been allow-listed"):
            Scope().check_target("gateway.test", 5000)

    def test_allowed_target_passes(self):
        Scope(allowed_targets=("gateway.test:5000",)).check_target("gateway.test", 5000)

    def test_case_and_whitespace_do_not_defeat_the_list(self):
        scope = Scope(allowed_targets=("  Gateway.Test:5000 ",))
        scope.check_target("GATEWAY.test", 5000)

    def test_wrong_port_is_out_of_scope(self):
        scope = Scope(allowed_targets=("gateway.test:5000",))
        with pytest.raises(ScopeError, match="not in scope"):
            scope.check_target("gateway.test", 5001)

    def test_wrong_host_is_out_of_scope(self):
        scope = Scope(allowed_targets=("gateway.test:5000",))
        with pytest.raises(ScopeError, match="not in scope"):
            scope.check_target("prod-gateway.test", 5000)

    def test_error_names_what_is_allowed(self):
        scope = Scope(allowed_targets=("a.test:1", "b.test:2"))
        with pytest.raises(ScopeError) as ei:
            scope.check_target("c.test", 3)
        assert "a.test:1" in str(ei.value) and "b.test:2" in str(ei.value)


class TestPanPolicy:
    def test_well_known_test_cards_are_recognised(self):
        scope = Scope()
        for pan in ("4111111111111111", "5555555555554444", "378282246310005"):
            assert scope.is_test_pan(pan), pan
            assert scope.check_pan(pan) is None

    def test_unknown_pan_warns_by_default(self):
        warning = Scope().check_pan("4999888877776666")
        assert warning is not None
        assert "outside the configured test ranges" in warning

    def test_warning_does_not_leak_the_pan(self):
        warning = Scope().check_pan("4999888877776666")
        assert "4999888877776666" not in warning
        assert "499988******6666" in warning

    def test_abort_policy_raises(self):
        scope = Scope(on_live_pan="abort")
        with pytest.raises(ScopeError):
            scope.check_pan("4999888877776666")

    def test_custom_test_bins_replace_the_defaults(self):
        scope = Scope(test_bins=("999999",))
        assert scope.is_test_pan("9999991234567890")
        assert not scope.is_test_pan("4111111111111111")

    def test_empty_pan_is_not_a_finding(self):
        assert Scope().check_pan("") is None

    def test_invalid_policy_is_refused(self):
        with pytest.raises(ScopeError, match="on_live_pan"):
            Scope(on_live_pan="ignore")

    def test_default_bins_are_the_published_documentation_numbers(self):
        assert "411111" in WELL_KNOWN_TEST_BINS
        assert Scope().test_bins == WELL_KNOWN_TEST_BINS


class TestMasking:
    def test_keeps_first_six_and_last_four(self):
        assert mask_pan("4111111111111111") == "411111******1111"

    def test_short_values_are_masked_entirely(self):
        """A 12-digit value would otherwise show almost all of itself."""
        assert mask_pan("123456789012") == "*" * 12
        assert "1234" not in mask_pan("1234")

    def test_length_is_preserved(self):
        for pan in ("4111111111111111", "378282246310005", "6011111111111117"):
            assert len(mask_pan(pan)) == len(pan)

    def test_track2_masks_the_pan_and_drops_the_rest(self):
        masked = mask_track2("4111111111111111D25121011234567890")
        assert masked == "411111******1111D..."
        assert "2512" not in masked, "expiry and service code must not survive"

    def test_track2_with_equals_separator(self):
        assert mask_track2("4111111111111111=25121011") == "411111******1111=..."

    def test_track2_without_a_separator_still_masks(self):
        assert mask_track2("4111111111111111") == "411111******1111"


class TestParseTarget:
    @pytest.mark.parametrize("text,expected", [
        ("host.test:5000", ("host.test", 5000)),
        ("host.test", ("host.test", 8583)),
        ("127.0.0.1:9000", ("127.0.0.1", 9000)),
        ("[::1]:9000", ("::1", 9000)),
        ("[::1]", ("::1", 8583)),
    ])
    def test_parses_common_forms(self, text, expected):
        assert parse_target(text) == expected

    def test_rejects_empty_and_non_numeric_ports(self):
        with pytest.raises(ScopeError):
            parse_target("")
        with pytest.raises(ScopeError, match="not a number"):
            parse_target("host.test:https")
