"""CPE 版本比较与区间判定。

这些用例固定的是**约定**：以后换实现可以，但结论不能变——否则已经发布的
"CVE 影响了哪些版本"会静默漂移。
"""
from core.kg.version import compare, is_any, is_na, is_unknown, matches

# --- 数值分段：字符串比较会在这里出错 ---------------------------------------


def test_fourth_segment_is_numeric_not_lexical():
    """'2.4.49' > '2.4.5'：按字符串比较会得出相反结论。"""
    assert compare("2.4.49", "2.4.5") == 1
    assert compare("2.4.5", "2.4.49") == -1


def test_numeric_segments_compare_as_numbers():
    assert compare("9.10", "9.8") == 1
    assert compare("2.4.50", "2.4.5") == 1
    assert compare("10.0.0", "9.9.9") == 1


def test_letter_suffix_compares_lexically():
    """OpenSSL 风格：1.0.2k < 1.0.2u。"""
    assert compare("1.0.2k", "1.0.2u") == -1
    assert compare("1.0.2u", "1.0.2k") == 1


def test_openssh_patch_suffix_is_ordered():
    assert compare("8.9p1", "8.9") == 1
    assert compare("8.9p1", "8.9p2") == -1


def test_missing_segments_pad_to_zero():
    assert compare("1.0", "1.0.0") == 0
    assert compare("1.0.0", "1.0") == 0


def test_identical_versions_are_equal():
    assert compare("2.4.49", "2.4.49") == 0


def test_leading_v_prefix_is_ignored():
    assert compare("v2.4.49", "2.4.49") == 0


# --- 不可比较：必须返回 None，不能被当成"相等" -------------------------------


def test_star_and_dash_are_not_comparable():
    assert is_any("*")
    assert is_any("")
    assert is_any(None)
    assert is_na("-")
    assert compare("*", "1.0") is None
    assert compare("1.0", "-") is None


def test_unsupported_forms_are_unknown_not_guessed():
    """~ 预发布与 epoch 明确不支持；猜一个答案比承认不知道更危险。"""
    assert compare("1.0.2~rc1", "1.0.2") is None
    assert compare("1:2.3", "2.3") is None
    assert is_unknown("1.0.2~rc1")


# --- 区间判定 ---------------------------------------------------------------


def test_inclusive_and_exclusive_bounds():
    assert matches("2.4.49", start_including="2.4.0", end_excluding="2.4.50") is True
    assert matches("2.4.50", start_including="2.4.0", end_excluding="2.4.50") is False
    assert matches("2.4.50", end_including="2.4.50") is True
    assert matches("2.4.49", start_excluding="2.4.49") is False
    assert matches("2.4.49", start_including="2.4.49") is True


def test_exact_criteria_version_requires_equality():
    assert matches("2.4.49", criteria_version="2.4.49") is True
    assert matches("2.4.50", criteria_version="2.4.49") is False


def test_any_criteria_version_matches_everything():
    assert matches("2.4.49", criteria_version="*") is True


def test_unknown_version_never_matches():
    """目标版本是 * 或 - 时不能匹配——否则会把"不知道"变成"命中"。"""
    assert matches("*", criteria_version="2.4.49") is False
    assert matches("-", criteria_version="2.4.49") is False
    assert matches("", criteria_version="*") is False
    assert matches(None, criteria_version="*") is False


def test_uncomparable_boundary_yields_no_match():
    """宁可漏报：边界无法判定时返回 False，而不是返回一个可能过报的 True。"""
    assert matches("1.0.2", start_including="1.0.2~rc1") is False
    assert matches("2.4.49", end_excluding="-") is False


def test_any_boundary_is_skipped():
    assert matches("2.4.49", start_including="*", end_excluding="2.4.50") is True
