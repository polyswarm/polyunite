from ..vocab import pattern
from ..vocab import (
    VOCABDEF,
    FAMILY_ID,
    HEURISTICS,
    LABELS,
    OBFUSCATIONS,
    PLATFORM,
    VARIANT_ID,
)
from ._base import Classification


class Jiangmin(Classification):
    __av_name__ = 'Jiangmin'
    __patterns__ = (
        VOCABDEF,
        pattern.EICAR_MATCH_ANYWHERE,
        r"""
        (?(DEFINE)
            (?P<FAMILY>(?:PSW|AOL|MSN)[.][[:alnum:]]+|CVE-[0-9]+-[0-9]+|(?:Variant[.]\w+)|\w+)
            (?P<VARIANT>(?:-based)?(?:[.][0-9]{1,2}[a-z])?(?:[.][0-9]+)?(?:[.][a-z]+)?([.](?:[A-Z][a-z]+))?)
        )
        """,
        rf"""^
        (
            (?&TYPES)[./](?&TYPES)[.](?&FAMILY)
            | (?&TYPES)[./](?&FAMILY)
        )
        (?&VARIANT)
        $""",
    )
