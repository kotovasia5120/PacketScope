from __future__ import annotations

import json


def dumps_result(result: dict, pretty: bool = False) -> str:
    return json.dumps(
        result,
        ensure_ascii=False,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        allow_nan=False,
    )
