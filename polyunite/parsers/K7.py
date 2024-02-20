from ..vocab import pattern, VOCABDEF
from ._base import Classification

base_pattern = rf"^(?P<K7KIND>(?&TYPES)|[\w-]+)(?P<VEID>\s+\(\s*(?P<VARIANT>[a-f0-9]+)\s*\))?\s*$"

class K7(Classification):
    __av_name__ = 'K7'
    __patterns__ = (
        VOCABDEF,
        pattern.EICAR_MATCH_ANYWHERE,
        base_pattern
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
