import pytest

from upload.handler import (
    safe_path,
    allowed_extension,
    sniff_type,
    within_size_limit,
    cleanup_temp,
    normalize_name,
)


def test_traversal_rejected():
    import pytest
    with pytest.raises(ValueError):
        safe_path("../etc/passwd", "/var/upload")


def test_absolute_path_rejected():
    import pytest
    with pytest.raises(ValueError):
        safe_path("/etc/passwd", "/var/upload")


def test_extension_whitelist():
    assert allowed_extension("a.png") is True


def test_double_extension_bypass():
    assert allowed_extension("a.php.png") is False


def test_case_variant_extension():
    assert allowed_extension("a.PHP") is False


def test_content_sniff_image():
    assert sniff_type(b"\x89PNG\r\n\x1a\n", "a.png") is True


def test_content_mismatch():
    assert sniff_type(b"<?php system($_GET[0]); ?>", "a.png") is False


def test_size_within_limit():
    assert within_size_limit(100, 1000) is True


def test_size_exceeded():
    assert within_size_limit(2000, 1000) is False


def test_zero_or_negative_size_rejected():
    assert within_size_limit(0, 1000) is False


def test_temp_cleanup_removes_file():
    import os, tempfile
    p = tempfile.mktemp()
    open(p, "w").close()
    cleanup_temp(p)
    assert not os.path.exists(p)


def test_normalize_lowercase():
    assert normalize_name("A.PNG").islower()


def test_normalize_strip():
    assert " " not in normalize_name("  a.png  ")


def test_path_escape_subdir_rejected():
    import pytest
    with pytest.raises(ValueError):
        safe_path("sub/../../etc/passwd", "/var/upload")


def test_valid_path_resolved():
    assert safe_path("a.png", "/var/upload").startswith("/var/upload")
