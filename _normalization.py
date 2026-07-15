from typing import Any, List


def normalize_unique_strings(value: Any, *, split_strings: bool = False) -> List[str]:
    """Return non-empty strings in input order with duplicates removed."""
    if value is None:
        values = []
    elif isinstance(value, str):
        values = value.split() if split_strings else [value]
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = [value]

    normalized = []
    seen = set()
    for item in values:
        text = str(item).strip()
        if text and text not in seen:
            normalized.append(text)
            seen.add(text)
    return normalized


def normalize_audience(value: Any) -> List[str]:
    """Normalize an audience claim into a unique string list."""
    return normalize_unique_strings(value)


def normalize_scopes(value: Any) -> List[str]:
    """Normalize scope-like values where strings are space-delimited."""
    return normalize_unique_strings(value, split_strings=True)
