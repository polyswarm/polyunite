from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID, pattern
from ._base import Classification


class DrWeb(Classification):
    __av_name__ = 'DrWeb'
    __patterns__ = (
        pattern.EICAR_MATCH_ANYWHERE,
        rf"""^
    (
        (^|[.-]|\s)
        (
            (?!PWS[.]){LABELS}(?&LABELS)?
            | {PLATFORM}
            | Nuke
            | STPAGE
        )
    )*
    (?P<VEID>
        (
            ([.]|^)
            (?!Based)
            (
                (?P<FAMILY>(?P<password_stealer>PWS[.][A-Z][[:alnum:]]+))
                | {
                    FAMILY_ID(
                        r"[A-Z]{2,3}",
                        r"[A-Z][A-Z0-9]{2,}",
                        r"(?<=^)[A-Z][a-z]+[.][A-Z][a-z]+(?=[.][0-9]+)"
                    )
                   }
            )
        )?
        {VARIANT_ID()}{{,2}}
    )
    $""",
    )
