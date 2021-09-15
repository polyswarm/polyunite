from ..vocab import pattern, VOCABDEF
from ._base import Classification

# Matches:
#   Spyware
#   Riskware ( 0040eff71 )
#       K7KIND: 'Riskware', VARIANT='0040eff71'
#   Trojan-Downloader ( 0054e0831 ) => K7KIND:
base_pattern = r"^(?P<K7KIND>(?&TYPES)|([A-Z][A-Za-z0-9]+)(?:-([A-Z][A-Za-z0-9]+))?)\ \(\ (?P<VEID>(?P<VARIANT>[a-f0-9]{9}))\ \)$",
"""
>>> split('Riskware ( 0040eff71 )')
FAMILY='Riskware'
VARIANT='0040eff71'
LABELS={'riskware'}
"""

class K7(Classification):
    __av_name__ = 'K7'
    __patterns__ = (
        VOCABDEF,
        pattern.EICAR_MATCH_ANYWHERE,
        base_pattern,
    )

    @property
    def family(self):
        return None

    @property
    def taxon(self) -> str:
        # K7 does not work with family names
        if self.is_EICAR:
            return 'EICAR'

        return self['K7KIND']
