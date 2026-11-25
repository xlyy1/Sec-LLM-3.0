"""CPE 版本比较与区间判定。

这些规则是**约定**，不是对 CPE 规范的反向工程：目的只有一个——同一份输入
永远得到同一个答案，并且这个答案被单测固定住，不会因为换了个库就漂移。

刻意不做的事：
- 不解析 epoch（``1:2.3``）
- 不实现 ``~`` 预发布语义
- 不实现 Debian/RPM 特有的排序

遇到上述形态或任何无法判定的输入，比较返回 ``None``（UNKNOWN）。调用方
必须把 UNKNOWN 当作**不命中**处理——宁可漏报，不可误报：漏报在报告里可见
（"该服务未匹配到已知 CVE"），误报会直接污染结论且用户看不出来。
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

#: CPE 的 ANY：任意版本，比较时没有意义，由调用方跳过边界判定。
ANY = "*"
#: CPE 的 NOT_APPLICABLE：该字段不适用，不可比较。
NA = "-"

# 数字段或字母段。分隔符（. - _ + 等）在匹配时自然被跳过。
_SEGMENT = re.compile(r"\d+|[a-z]+")
_UNSUPPORTED = ("~", ":")

Segment = Tuple[int, object]


def _text(value) -> str:
    return "" if value is None else str(value).strip()


def is_any(value) -> bool:
    """空值、``None``、``*`` 都表示"不限"。"""
    text = _text(value)
    return text in ("", ANY)


def is_na(value) -> bool:
    """CPE 的 NOT_APPLICABLE（``-``）。"""
    return _text(value) == NA


def _comparable(value) -> bool:
    text = _text(value).lower()
    if not text or text in (ANY, NA):
        return False
    # 明确不支持、却又长得像版本的输入：判定为不可比较，而不是硬算出一个答案。
    return not any(marker in text for marker in _UNSUPPORTED)


def _segments(value: str) -> list[Segment]:
    """切分版本：连续数字 → int 段，连续字母 → str 段。"""
    text = _text(value).lower()
    if len(text) > 1 and text[0] == "v" and text[1].isdigit():
        text = text[1:]
    return [
        (0, int(token)) if token.isdigit() else (1, token)
        for token in _SEGMENT.findall(text)
    ]


def _pad(kind: int) -> object:
    """补齐缺失段：数字补 0，字母补空串。"""
    return 0 if kind == 0 else ""


def compare(left, right) -> Optional[int]:
    """返回 -1 / 0 / 1；无法判定时返回 ``None``。

    ``None`` 不是"相等"，调用方必须显式处理。
    """
    if not _comparable(left) or not _comparable(right):
        return None

    a, b = _segments(left), _segments(right)
    if not a or not b:
        return None

    for index in range(max(len(a), len(b))):
        if index < len(a):
            kind_a, value_a = a[index]
        else:
            kind_b_missing = b[index][0]
            kind_a, value_a = kind_b_missing, _pad(kind_b_missing)
        if index < len(b):
            kind_b, value_b = b[index]
        else:
            kind_b, value_b = kind_a, _pad(kind_a)

        # 类型不同时数字段小于字母段。这是约定，不是真理；单测把顺序固定下来。
        if kind_a != kind_b:
            return -1 if kind_a < kind_b else 1
        if value_a != value_b:
            return -1 if value_a < value_b else 1
    return 0


def matches(
    version,
    criteria_version=None,
    *,
    start_including=None,
    start_excluding=None,
    end_including=None,
    end_excluding=None,
) -> bool:
    """判定 ``version`` 是否落入一条 ``cpeMatch`` 的适用区间。

    - 有区间边界时以区间为准，``criteria_version`` 不参与。
    - 没有区间边界时要求与 ``criteria_version`` 相等；``criteria_version``
      为 ``*`` 表示任意版本都满足。
    - 版本本身为 ``*`` / ``-`` / 空 → 不命中。
    - 任一比较返回 UNKNOWN → 不命中。
    """
    if not _comparable(version):
        return False

    bounds = (start_including, start_excluding, end_including, end_excluding)
    if all(bound is None for bound in bounds):
        if is_any(criteria_version):
            return True
        if is_na(criteria_version):
            return False
        return compare(version, criteria_version) == 0

    checks = (
        (start_including, lambda c: c >= 0),
        (start_excluding, lambda c: c > 0),
        (end_including, lambda c: c <= 0),
        (end_excluding, lambda c: c < 0),
    )
    for bound, ok in checks:
        if bound is None or is_any(bound):
            continue
        if is_na(bound):
            return False
        result = compare(version, bound)
        if result is None or not ok(result):
            return False
    return True


def is_unknown(*values) -> bool:
    """辅助：任一边界不可比较（用于调用方决定是否降级为"未匹配"）。"""
    return any(not _comparable(value) for value in values if value is not None)
