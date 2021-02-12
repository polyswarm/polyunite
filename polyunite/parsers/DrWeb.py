from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class DrWeb(Classification):
    pattern = rf"""^
    ((probabl[ey]|modification(\ of)?|possibl[ey]))?
    (
        (^|[.-]|\ )
        (
          (?!PWS[.]){LABELS}(?&LABELS)?
          | {PLATFORM}
          | Sector
          | MGen
          | Ear
        )
    )*
    (?P<VEID>
        (
            ([.]|^)
            (
                (?P<FAMILY>(?P<password_stealer>PWS[.][A-Z][[:alnum:]]+))
                | {FAMILY_ID(r'[A-Z][[:alnum:]]{1,2}(?=[.]|$)')}
            )
        )?
        {VARIANT_ID(r'[.]Log')}*
    )
    $"""
