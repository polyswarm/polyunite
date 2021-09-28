from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID, pattern
from ._base import Classification


class Virusdie(Classification):
    __av_name__ = 'VirusDie'
    __patterns__ = (
        pattern.EICAR_MATCH_ANYWHERE,
        rf"""^
        (
            (^|[.-])
            {PLATFORM}|{LABELS}
        )*
        (?P<VEID>
            (
                (^|[.])
                (
                    {FAMILY_ID()}
                    | .+
                )
            )?
            {VARIANT_ID()}*
        )
        $"""
    )
