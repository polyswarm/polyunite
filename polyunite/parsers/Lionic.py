from ..vocab import (
    ARCHIVES,
    FAMILY_ID,
    HEURISTICS,
    LABELS,
    LANGS,
    MACROS,
    OBFUSCATIONS,
    OSES,
    PLATFORM,
    SUFFIXES,
    VARIANT_ID,
)
from ._base import Classification


class Lionic(Classification):
    pattern = rf"""^
    (
        (^|[.])
        (
            {PLATFORM}
            | Email
            | W
            | pcap
            | HTTP
            | Shell
            | {LABELS}(-?(?&LABELS))?
        )
    )*
    (?P<VEID>
        (
            ([.]|^)
            (
                {FAMILY_ID(
                    r"[0-9A-Z][a-zA-Z0-9]_[0-9]",
                    r'^[a-zA-Z0-9_]+$',
                    r'([0-9]{,3})[A-Z][A-Za-z][0-9]{4}',
                )}
                | [A-Z][a-z]{{1,2}}(?=[.])
            )
        )?
        {VARIANT_ID(r'[.][[:alnum:]][!][[:alnum:]]$')}*
    )
    $"""
