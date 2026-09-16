"""
EMV cryptography — primitives, derivation, cryptograms.

On what these tests establish: the DES primitive is anchored against
pycryptodome, and everything above it is checked for self-consistency and
correct diversification. What they cannot establish is that any profile matches
a particular scheme's CVN — that data composition is confidential, and a test
asserting it would only be asserting my guess. `selftest` says the same thing
to the operator's face, which is the honest place for that caveat to live.
"""
from __future__ import annotations

import pytest

from host.crypto import (
    NONE,
    OPTION_B,
    CryptoError,
    CryptogramError,
    adjust_parity,
    arpc_method_1,
    arpc_method_2,
    available_profiles,
    build_data,
    compute_arqc,
    derive_session_key,
    derive_udk,
    des3_decrypt,
    des3_encrypt,
    has_odd_parity,
    load_profile,
    mac_iso9797_alg3,
    parse_key,
    resign,
    verify_cryptogram,
    xor,
)
from host.crypto.des import (
    des_encrypt,
    pad_method_1,
    pad_method_2,
)
from host.crypto.keys import KeyError_, load_imk
from host.iso8583 import Message, load_dialect
from host.iso8583 import de55 as de55_mod
from host.iso8583.tlv import TLVNode, serialize_tlv

IMK = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
PAN = "4111111111111111"


def _tlv(tag: str, hexval: str) -> TLVNode:
    v = bytes.fromhex(hexval)
    return TLVNode(tag=tag, length=len(v), value=v, constructed=False)


def _full_de55(**overrides) -> bytes:
    """DE55 carrying every tag the emv-book2 profile asks for."""
    values = {
        "9F02": "000000001000", "9F03": "000000000000", "9F1A": "0840",
        "95": "0000000000", "5F2A": "0840", "9A": "260819", "9C": "00",
        "9F37": "12345678", "82": "3900", "9F36": "00FF",
        "9F10": "06010A03900000", "9F26": "0000000000000000",
    }
    values.update(overrides)
    return serialize_tlv([_tlv(t, v) for t, v in values.items()])


@pytest.fixture
def iso():
    return load_dialect("iso8583-1987")


@pytest.fixture
def profile():
    return load_profile("emv-book2")


@pytest.fixture
def msg():
    return Message(mti="0100", fields={
        2: PAN, 4: "000000001000", 11: "000123", 49: "840", 55: _full_de55()})


# ── Primitives ────────────────────────────────────────────────────────────────

class TestDes:
    def test_3des_with_equal_halves_reduces_to_single_des(self):
        """
        The one independent anchor available without published vectors: with
        K1 == K2 the E-D-E collapses to a single DES, which pycryptodome
        computes separately.
        """
        k = bytes.fromhex("0123456789ABCDEF")
        pt = bytes.fromhex("4E6F772069732074")
        assert des3_encrypt(k + k, pt) == des_encrypt(k, pt)

    def test_3des_round_trip(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        pt = bytes.fromhex("4E6F772069732074" "0011223344556677")
        assert des3_decrypt(key, des3_encrypt(key, pt)) == pt

    def test_single_length_key_is_accepted_as_3des(self):
        k = bytes.fromhex("0123456789ABCDEF")
        pt = bytes.fromhex("4E6F772069732074")
        assert des3_encrypt(k, pt) == des3_encrypt(k + k, pt)

    def test_wrong_key_length_is_refused(self):
        with pytest.raises(CryptoError, match="8 or 16 bytes"):
            des3_encrypt(b"\x00" * 7, b"\x00" * 8)

    def test_partial_block_is_refused(self):
        with pytest.raises(CryptoError, match="whole 8-byte blocks"):
            des3_encrypt(b"\x00" * 16, b"\x00" * 7)

    def test_xor_length_mismatch(self):
        with pytest.raises(CryptoError, match="Cannot XOR"):
            xor(b"\x00", b"\x00\x00")


class TestPadding:
    @pytest.mark.parametrize("data,expected", [
        (b"", "0000000000000000"),
        (b"A", "4100000000000000"),
        (b"12345678", "3132333435363738"),
    ])
    def test_method_1(self, data, expected):
        assert pad_method_1(data).hex().upper() == expected.upper()

    @pytest.mark.parametrize("data,expected", [
        (b"", "8000000000000000"),
        (b"A", "4180000000000000"),
        (b"12345678", "31323334353637388000000000000000"),
    ])
    def test_method_2_always_adds_a_marker(self, data, expected):
        """Method 2 pads even a full block, which is what makes it unambiguous."""
        assert pad_method_2(data).hex().upper() == expected.upper()

    def test_both_produce_whole_blocks(self):
        for n in range(0, 20):
            assert len(pad_method_1(b"x" * n)) % 8 == 0
            assert len(pad_method_2(b"x" * n)) % 8 == 0


class TestMac:
    def test_length_and_determinism(self):
        key = IMK
        assert len(mac_iso9797_alg3(key, b"hello")) == 8
        assert mac_iso9797_alg3(key, b"hello") == mac_iso9797_alg3(key, b"hello")

    def test_sensitive_to_key_and_data(self):
        other = bytes.fromhex("FFEEDDCCBBAA99887766554433221100")
        base = mac_iso9797_alg3(IMK, b"hello")
        assert base != mac_iso9797_alg3(other, b"hello")
        assert base != mac_iso9797_alg3(IMK, b"hellp")

    def test_truncation(self):
        assert len(mac_iso9797_alg3(IMK, b"x", length=4)) == 4

    def test_unknown_padding_is_refused(self):
        with pytest.raises(CryptoError, match="Unknown padding"):
            mac_iso9797_alg3(IMK, b"x", padding="pkcs7")


class TestParity:
    def test_adjustment_makes_every_byte_odd(self):
        assert has_odd_parity(adjust_parity(bytes(range(16))))

    def test_idempotent(self):
        once = adjust_parity(b"\x00" * 8)
        assert adjust_parity(once) == once

    def test_only_the_low_bit_moves(self):
        for b in range(256):
            assert adjust_parity(bytes([b]))[0] >> 1 == b >> 1


# ── Derivation ────────────────────────────────────────────────────────────────

class TestUdk:
    def test_deterministic(self):
        assert derive_udk(IMK, PAN).udk == derive_udk(IMK, PAN).udk

    def test_diversified_by_pan_psn_and_imk(self):
        base = derive_udk(IMK, PAN).udk
        assert base != derive_udk(IMK, "4111111111111112").udk
        assert base != derive_udk(IMK, PAN, "01").udk
        assert base != derive_udk(bytes(16), PAN).udk

    def test_is_sixteen_bytes_and_parity_adjusted(self):
        udk = derive_udk(IMK, PAN).udk
        assert len(udk) == 16 and has_odd_parity(udk)

    def test_short_pan_pads_rather_than_failing(self):
        """A 13-digit PAN is legal and still has to derive."""
        assert len(derive_udk(IMK, "4111111111111").udk) == 16

    def test_repr_does_not_leak_the_key_or_the_pan(self):
        text = repr(derive_udk(IMK, PAN))
        assert "udk=<16 bytes>" in text
        assert PAN not in text
        assert derive_udk(IMK, PAN).udk.hex().upper() not in text.upper()

    def test_option_b_refuses_rather_than_approximating(self):
        """A half-right derivation produces keys that verify nothing."""
        with pytest.raises(KeyError_, match="Option B is not implemented"):
            derive_udk(IMK, PAN, method=OPTION_B)

    def test_empty_pan(self):
        with pytest.raises(KeyError_, match="PAN is empty"):
            derive_udk(IMK, "")

    def test_bad_imk_length(self):
        with pytest.raises(KeyError_, match="8 or 16 bytes"):
            derive_udk(b"\x00" * 7, PAN)


class TestSessionKey:
    def test_diversified_by_atc(self):
        udk = derive_udk(IMK, PAN).udk
        assert derive_session_key(udk, b"\x00\x01") != derive_session_key(udk, b"\x00\x02")

    def test_parity_adjusted_and_sixteen_bytes(self):
        sk = derive_session_key(derive_udk(IMK, PAN).udk, b"\x00\x01")
        assert len(sk) == 16 and has_odd_parity(sk)

    def test_none_method_returns_the_udk(self):
        udk = derive_udk(IMK, PAN).udk
        assert derive_session_key(udk, b"\x00\x01", method=NONE) == udk

    def test_atc_must_be_two_bytes(self):
        udk = derive_udk(IMK, PAN).udk
        with pytest.raises(KeyError_, match="ATC is 2 bytes"):
            derive_session_key(udk, b"\x01")

    def test_unknown_method(self):
        udk = derive_udk(IMK, PAN).udk
        with pytest.raises(KeyError_, match="Unknown session key method"):
            derive_session_key(udk, b"\x00\x01", method="magic")


class TestKeyLoading:
    def test_prefers_file_then_env_then_argv(self, tmp_path, monkeypatch):
        path = tmp_path / "imk.key"
        path.write_text(IMK.hex())
        monkeypatch.setenv("HOST_IMK", "00" * 16)

        key, source = load_imk("11" * 16, str(path))
        assert key == IMK and "file" in source

        key, source = load_imk("11" * 16, None)
        assert key == bytes(16) and "HOST_IMK" in source

        monkeypatch.delenv("HOST_IMK")
        key, source = load_imk("11" * 16, None)
        assert key == bytes.fromhex("11" * 16)
        assert "ps" in source, "an argv key must be reported as exposed"

    def test_nothing_supplied_explains_the_options(self, monkeypatch):
        monkeypatch.delenv("HOST_IMK", raising=False)
        with pytest.raises(KeyError_, match="HOST_IMK"):
            load_imk(None, None)

    def test_parse_rejects_non_hex_and_odd_lengths(self):
        with pytest.raises(KeyError_, match="not hex"):
            parse_key("zz")
        with pytest.raises(KeyError_, match="expected 8, 16 or 24"):
            parse_key("0011223344")

    def test_triple_length_key_is_truncated_to_two(self):
        assert len(parse_key("00" * 24)) == 16


# ── Profiles and data ─────────────────────────────────────────────────────────

class TestProfiles:
    def test_shipped_profiles_load(self):
        names = available_profiles()
        assert {"emv-book2", "emv-book2-iad", "udk-direct"} <= set(names)
        for name in names:
            p = load_profile(name)
            assert p.tags and p.description

    def test_iad_profile_appends_the_iad(self):
        assert load_profile("emv-book2-iad").tags[-1] == "9F10"

    def test_udk_direct_uses_no_session_key(self):
        assert load_profile("udk-direct").session_key == NONE

    def test_missing_profile_lists_what_exists(self):
        with pytest.raises(CryptogramError, match="Available:"):
            load_profile("visa-cvn10")

    def test_profile_without_tags_is_refused(self, tmp_path):
        (tmp_path / "bare.yaml").write_text("name: bare\n")
        with pytest.raises(CryptogramError, match="nothing to MAC"):
            load_profile("bare", tmp_path)


class TestBuildData:
    def test_concatenates_in_profile_order(self, profile, msg):
        built = build_data(profile, de55_mod.from_message(msg), msg)
        assert built.complete
        assert built.data.startswith(bytes.fromhex("000000001000"))
        assert built.data.endswith(bytes.fromhex("00FF"))

    def test_reports_missing_tags_rather_than_zero_filling(self, profile):
        """A cryptogram over wrong data fails exactly like a forged one."""
        nodes = de55_mod.parse(_full_de55())
        de55_mod.remove_tag(nodes, "9F37")
        built = build_data(profile, nodes, None)
        assert not built.complete and built.missing == ("9F37",)

    def test_falls_back_to_the_8583_layer_and_says_so(self, profile, iso):
        nodes = de55_mod.parse(_full_de55())
        de55_mod.remove_tag(nodes, "9F02")
        m = Message(mti="0100", fields={4: "000000001000"})
        built = build_data(profile, nodes, m)
        assert built.complete and built.substituted == ("9F02",)


# ── Cryptograms ───────────────────────────────────────────────────────────────

class TestVerify:
    def test_a_signed_message_verifies(self, profile, msg):
        keys = derive_udk(IMK, PAN)
        resign(msg, keys.udk, profile)
        result = verify_cryptogram(msg, keys.udk, profile)
        assert result.matched
        assert result.atc == "00FF"
        assert "verified" in str(result)

    def test_tampering_covered_data_breaks_it(self, profile, msg):
        keys = derive_udk(IMK, PAN)
        resign(msg, keys.udk, profile)
        nodes = de55_mod.from_message(msg)
        de55_mod.set_tag(nodes, "9F02", "000000009999")
        msg.fields[55] = de55_mod.serialize(nodes)

        result = verify_cryptogram(msg, keys.udk, profile)
        assert not result.matched and not result.reason
        assert "MISMATCH" in str(result)

    def test_the_wrong_key_does_not_verify(self, profile, msg):
        resign(msg, derive_udk(IMK, PAN).udk, profile)
        assert not verify_cryptogram(msg, derive_udk(bytes(16), PAN).udk,
                                     profile).matched

    def test_the_wrong_profile_does_not_verify(self, msg):
        keys = derive_udk(IMK, PAN)
        resign(msg, keys.udk, load_profile("emv-book2"))
        assert not verify_cryptogram(msg, keys.udk,
                                     load_profile("emv-book2-iad")).matched

    def test_refuses_to_judge_when_a_tag_is_missing(self, profile):
        """A verdict it cannot stand behind is worse than no verdict."""
        nodes = de55_mod.parse(_full_de55())
        de55_mod.remove_tag(nodes, "9F37")
        m = Message(mti="0100", fields={2: PAN, 55: de55_mod.serialize(nodes)})
        result = verify_cryptogram(m, derive_udk(IMK, PAN).udk, profile)
        assert not result.matched
        assert "missing 9F37" in result.reason
        assert "not checked" in str(result)

    def test_no_de55(self, profile):
        result = verify_cryptogram(Message(mti="0100", fields={2: PAN}),
                                   derive_udk(IMK, PAN).udk, profile)
        assert "no DE55" in result.reason

    def test_no_arqc_tag(self, profile):
        nodes = de55_mod.parse(_full_de55())
        de55_mod.remove_tag(nodes, "9F26")
        m = Message(mti="0100", fields={2: PAN, 55: de55_mod.serialize(nodes)})
        assert "no tag 9F26" in verify_cryptogram(
            m, derive_udk(IMK, PAN).udk, profile).reason

    def test_no_atc(self, profile):
        nodes = de55_mod.parse(_full_de55())
        de55_mod.remove_tag(nodes, "9F36")
        m = Message(mti="0100", fields={2: PAN, 55: de55_mod.serialize(nodes)})
        assert "ATC" in verify_cryptogram(
            m, derive_udk(IMK, PAN).udk, profile).reason


class TestResign:
    def test_writes_a_verifying_cryptogram(self, profile, msg):
        keys = derive_udk(IMK, PAN)
        _m, arqc = resign(msg, keys.udk, profile)
        assert de55_mod.tag_value(de55_mod.from_message(msg), "9F26") == arqc
        assert verify_cryptogram(msg, keys.udk, profile).matched

    def test_resigning_tampered_data_makes_it_valid_again(self, profile, msg):
        """The phase 5 payoff: valid crypto over changed content."""
        keys = derive_udk(IMK, PAN)
        nodes = de55_mod.from_message(msg)
        de55_mod.set_tag(nodes, "9F02", "000000009999")
        msg.fields[55] = de55_mod.serialize(nodes)
        assert not verify_cryptogram(msg, keys.udk, profile).matched

        resign(msg, keys.udk, profile)
        assert verify_cryptogram(msg, keys.udk, profile).matched

    def test_refuses_without_de55(self, profile):
        with pytest.raises(CryptogramError, match="no DE55"):
            resign(Message(mti="0100", fields={2: PAN}), derive_udk(IMK, PAN).udk,
                   profile)

    def test_refuses_when_data_is_incomplete(self, profile):
        nodes = de55_mod.parse(_full_de55())
        de55_mod.remove_tag(nodes, "9F37")
        m = Message(mti="0100", fields={2: PAN, 55: de55_mod.serialize(nodes)})
        with pytest.raises(CryptogramError, match="missing 9F37"):
            resign(m, derive_udk(IMK, PAN).udk, profile)


class TestArpc:
    def test_method_1_depends_on_the_response_code(self):
        sk = derive_session_key(derive_udk(IMK, PAN).udk, b"\x00\x01")
        arqc = compute_arqc(sk, b"\x00" * 16)
        approved = arpc_method_1(sk, arqc, b"\x30\x30")
        declined = arpc_method_1(sk, arqc, b"\x30\x35")
        assert approved != declined and len(approved) == 8

    def test_method_1_validates_input_sizes(self):
        sk = derive_session_key(derive_udk(IMK, PAN).udk, b"\x00\x01")
        with pytest.raises(CryptogramError, match="ARQC is 8 bytes"):
            arpc_method_1(sk, b"\x00", b"\x30\x30")
        with pytest.raises(CryptogramError, match="ARC is 2 bytes"):
            arpc_method_1(sk, b"\x00" * 8, b"\x30")

    def test_method_2_is_four_bytes_and_csu_sensitive(self):
        sk = derive_session_key(derive_udk(IMK, PAN).udk, b"\x00\x01")
        arqc = compute_arqc(sk, b"\x00" * 16)
        a = arpc_method_2(sk, arqc, b"\x00\x00\x00\x00")
        b = arpc_method_2(sk, arqc, b"\x00\x00\x00\x01")
        assert len(a) == 4 and a != b
