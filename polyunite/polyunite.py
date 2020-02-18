# enum identifiers are sourced from https://maecproject.github.io/documentation/maec5-docs/#introduction
from typing import Optional, List, Type, Dict, Any
from enum import Enum
import re
import csv
import string

def seen(f):
    with open(f, newline='') as csvfile:
        yield from csv.reader(csvfile)

class MalwareLabel(Enum):
    @classmethod
    def construct(cls, **values):
        try:
            label = values.get('label', '').upper().replace('-', ' ').replace(' ', '')
            return getattr(cls, label) or cls(label)
        except (AttributeError, ValueError):
            return None

class OperatingSystem(Enum):
    @classmethod
    def construct(cls, **values):
        try:
            platform = values.get('platform', '').upper()
            return getattr(cls, platform) or cls(platform)
        except (AttributeError, ValueError):
            return None


class ObfuscationMethod(Enum):
    PACKER = 'packer'

    @classmethod
    def construct(cls, **values):
        if values.get('obfuscation', '').lower() == 'packed' or 'packed' in values.get(
                'label', {}) or 'packed' in values.get('platform', {}):
            return ObfuscationMethod.PACKER
        return None


class BaseClassification:
    engine: str
    values: Dict[str, Any]

    def __init__(self, engine=None, **values):
        self.engine = engine
        self.values = {k: v for k, v in values.items() if v}

    @property
    def name(self):
        return MalwareName.construct(**self.values)

    @property
    def operating_system(self):
        return OperatingSystem.construct(**self.values)

    def label(self):
        return MalwareLabel.construct(**self.values)

    @property
    def obfuscation_method(self):
        return ObfuscationMethod.construct(**self.values)

    def __repr__(self):
        return f'MalwareFamily(engine={self.engine}, name={self.name}, label={self.label}, os={self.operating_system})'

class Engine:
    regex: str

    def __init__(self, regex):
        self.regex = regex

    def parse(self, engine=None, **values):
        m = re.match(self.regex, family)
        if m:
            return MalwareFamily(engine=engine, **m.groupdict(default=''))
        else:
            print("%s didn't match the regex for %s" % (family, self.regex))

# class ParseField:
#     regex: str

#     def __init__(self, regex):
#         self.regex = regex

#     def transform(self, ss):
#         return ss.lower().translate({'-': '', ' ': '', '_': ''})

#     def extract(self, family: str):
#         m = re.match(self.regex, family)
#         if m:
#             return m.groupdict(default='')
#         return None

#     def parse(self, engine=None, family: str):
#         values = self.extract(family)
#         platform = values.get('platform', '')
#         if platform in platform_map:
#             for k, v in platform_map[platform].items():
#                 if type(v) == type(self):
#                     return v
#         return self.munge(engine, **values)


platform_map = {
    'AndroidOS': {'os': OperatingSystem.ANDROID, 'aliases': ['Andr', 'Android']},
    'DOS': 'MS-DOS',
    'UNIX': {
        '__desc__': 'general Unix platforms'
    },
    'Boot': { '__desc__': "Uses or resides in the Master Boot Record (MBR) or DOS Boot Sector of an operating system",
              '__alias__': ['Boot-DOS'] },
    'FreeBSD': "FreeBSD platform",
    'Linux': { '__desc__': "Linux platform", '__alias__': ['ELF', 'ELF.Linux'] },
    'MacOS': {
        '__alias__': ['Mac OSX', r'Mac[-\.\s]?(OSX?)?'],
        '__desc__': "MAC 9.x platform or earlier",
    },
    'Generic': {
        '__alias__': [r'I?Generic(PMF|RI|FC)?', 'Legacy', 'multios', 'Multi']
    },
    'EPOC': "Psion devices",
    'OS2': "OS2 platform",
    'Palm': "Palm operating system",
    'Solaris': "System V-based Unix platforms",
    'SunOS': "Unix platforms 4.1.3 or lower",
    'SymbOS': "Symbian operating system",
    'Script': 'Interpreted',
    'UKP': {},  # no idea what this is
    'WINDOWS': {
        '__desc__': 'Microsoft windows',
        '__alias__': ['Win32/64'],
        'Win16': "Win16 (3.1) platform",
        'Win2K': "Windows 2000 platform",
        'Win32': {
            '__desc__': "Windows 32-bit platform",
            '__alias__': ['W32']
        },
        'Win64': {
            '__desc__': "Windows 64-bit platform",
            '__alias__': ['W64']
        },
        'Win95': "Windows 95, 98 and ME platforms",
        'Win98': "Windows 98 platform only",
        'WinCE': "Windows CE platform",
        'WinNT': "WinNT",
    },
    'iPhoneOS': {
        '__desc__': 'IPhone',
        '__alias__': ['IOS']
    },
}

label_map = [
    (MalwareLabel.DOWNLOADER, ('downldr', '.*downloader.*'))
]

platform_re = '(?P<platform>' + '|'.join((k for k in platform_map)) + ')'
SCRIPT = r"(?P<script>ABAP|ALisp|AmiPro|ANSI|AppleScript|ASP|AutoIt|BAS|BAT|CorelScript|HTA|HTML|INF|IRC|Java|JS|LOGO|MPB|MSH|MSIL|Perl|PHP|Python|SAP|SH|VBA|VBS|WinBAT|WinHlp|WinREG)"
MACRO = r"(?P<macro>A97M|HE|O97M|PP97M|V5M|W1M|W2M|W97M|WM|X97M|XF|XM)"
PLATFORM = r"(?P<platform>Android|AndroidOS|Andr|Boot-DOS|CRX|DOS|FreeBSD|HTML|IMG-PNG|JS|Java|Android|Linux|Legacy|multios|MSExcel|ELF|MSIL|MSWord|Doc|Xls|Mac[-\.\s]?(OSX?)?|Multi|NSIS|OLE|PDF|PHP|PS|PowerShell|RTF|SWF|Script|SunOS|TIFF|UKP|VB|VBS|W32|W64|Win32|Win64|Win32/64|Win98|WinLNK|Unix|Win|W97M|file|iOS|iPhoneOS|W42)"
LABEL = r"(?P<label>[-\w]*?)"

def join_re(name, elts):
    def descend(kvs):
        collected = []
        for k, v in kvs.items():
            if isinstance(v, dict):
                collected.extend(descend(v))
            else:
                collected.append(k)
        return collected
    joined = '|'.join(descend(elts))
    return f'(?P<{name}>{joined})'

def combine(sources):
    inner = '|'.join([join_re(source) for source in sources])
    return f"(?P<combine>({inner}))"

class FamilyExtractor:
    @classmethod
    def parse(cls, engine, family: str) -> Optional[MalwareFamily]:
        extractor = getattr(cls, engine.lower().replace(' ', ''), None)
        if not extractor:
            return engine
        m = re.match(extractor.regex, family, re.IGNORECASE)
        if m:
            return MalwareFamily(engine=engine, **m.groupdict())
        return None

class style():
    BLACK = lambda x: '\033[30m' + str(x)
    RED = lambda x: '\033[31m' + str(x)
    GREEN = lambda x: '\033[32m' + str(x)
    YELLOW = lambda x: '\033[33m' + str(x)
    BLUE = lambda x: '\033[34m' + str(x)
    MAGENTA = lambda x: '\033[35m' + str(x)
    CYAN = lambda x: '\033[36m' + str(x)
    WHITE = lambda x: '\033[37m' + str(x)
    UNDERLINE = lambda x: '\033[4m' + str(x)
    RESET = lambda x: '\033[0m'


class EngineProcessor:
    _engines: Dict[str, Type['EngineProcessor']] = {}
    # Generic processing logic for CME
    clf: str = r"((?P<label>\w+):)((?P<platform>\w)/)?(?P<family>\w+)(\.(?P<variant>\w+))?(\!(?P<suffix>\w+))?"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        EngineProcessor._engines[engine] = cls

    @staticmethod
    def to_engine(ss: str) -> str:
        return ss.translate(str.maketrans('', '', string.punctuation + string.whitespace))

    @classmethod
    def parse_as(cls, engine: str, classification: str):
        name = cls.to_engine(engine)
        return cls._engines[name].parse(classification)

    @classmethod
    def parse(cls, classification: str) -> Optional[re.Match[str]]:
        return re.match(cls.clf, classification, re.IGNORECASE)
        # if m:
        #     return m # MalwareFamily(engine=engine, **m.groupdict())
        # return None

    Classification = BaseClassification


class alibaba(EngineProcessor):
    name = 'alibaba'
    clf = rf"^((?P<label>\w+):)?({platform_re}\/)?((?P<name>[^.]+))(\.(?P<vendor_id>.*))?$"

class clamav(EngineProcessor):
    name = 'clamav'
    clf = rf"^((?P<prefix>BC|Clamav)\.)?({platform_re}\.)?((?P<label>\w+)\.)?(?P<name>.+?)?(\-(?P<vendor_id>[-0-9]+))?$"

class drweb(EngineProcessor):
    name = 'drweb'
    clf = rf"^((?P<confidence>probably|modification of)\s*)?({platform_re}(\.|$))?((?P<label>[\.\w]+?)\.)?(((?P<name>[A-Za-z][-\w]+))(\.(?P<variant>[0-9]+))?)?(\.origin)?$"

class ikarus(EngineProcessor):
    name = 'ikarus'
    clf = rf"^((?P<obfuscation>Packed)\.)?((?P<meta>not\-a\-virus|HEUR)(\.|\:))?((?P<label>[\w-]*?))?((^|[^\w]){platform_re})?(\.(?P<name>..+))?$"

class jiangmin(EngineProcessor):
    name = 'jiangmin'
    clf = rf"^((?P<label>[-\w]+)(\.|\/))?({platform_re}\.?)?((?P<name>[\.\-\w]+?)\.)?(?P<extra>\w*)?$"

class k7(EngineProcessor):
    name = 'k7'
    clf = rf"(?P<label>[\w-]+)( \( (?P<extra>[a-f0-9]+) \))?"

class lionic(EngineProcessor):
    name = 'lionic'
    clf = rf"^((?P<label>\w+)\.)?({platform_re}\.)?((?P<name>[-\w\.]+))(\!\w.*)?"

class nanoav(EngineProcessor):
    name = 'nanoav'
    clf = rf"^^((?P<confidence>HEUR)\/)?((?P<platform1>\w+)\/)?((?P<label>[\w\/]+))?\.?({platform_re}\.)?(?P<name>[\-\.\w]+(\.[A-Z]+)?)?$"

class qihoo360(EngineProcessor):
    name = 'qihoo360'
    clf = rf"^((?P<platform>\w+)\/)?((?P<label>[^.]+)\.)((?P<name>\w+)\.)?(.*)$"

class quickheal(EngineProcessor):
    name = 'quickheal'
    clf = rf"^((Exp\.)?({SCRIPT})|({MACRO}))?((^|\.){LABEL})?((^|\.){PLATFORM})?(\/(?P<family>\w+))?((\.(?P<name>[-\w]+))(\.(?P<variant>[\.\w]*))?)?$"

class rising(EngineProcessor):
    name = 'rising'
    clf = rf"^((?P<label>\w+))?(?=.).((?P<platform>[\/\w]*?)\.)?(?P<name>[^!\s\/\.]+)?(\.(?P<variant>\w+))?(/(?P<platform2>\w+))?(\!(?P<extra>.*))?$"

class virusdie(EngineProcessor):
    name = 'virusdie'
    clf = rf"((?P<label>\w+)\.)?((?P<behavior>\w+)\.)?(?P<extra>\w*)"


def color(color, ss):
    return color(ss) + style.RESET('')

# {
#     'label': style.RED,
#     'platform': style.BLUE,
#     'behavior': style.
# }

def print_string(ss, groups):
    matches = {
        'meta': style.UNDERLINE,
        'name': style.YELLOW,
        'behavior': style.BLUE,
        'macro': style.YELLOW,
        'obfuscation': style.GREEN,
        'family': style.YELLOW,
        'vendor_id': style.WHITE,
        'platform2': style.RED,
        'platform': style.RED,
        'label': style.CYAN,
        'confidence': style.UNDERLINE,
        'variant': style.MAGENTA,
        'script': style.RED,
        'extra': style.UNDERLINE
    }
    idx = 0
    for k, v in groups.items():
        if k in matches and v in ss:
            cr = ss.find(v, idx)
            idx = cr + len(v)
            ss = ss[:cr] + color(matches[k], ss[cr:idx]) + ss[idx:]
    print(ss)


platform_map = {}
import pprint
if __name__ == '__main__':
    # for x in dir(FamilyExtractor):
    #     y = getattr(FamilyExtractor, x)
    #     if isinstance(y, Engine):
    #         print(y.regex)

    elts = set()
    for engine, family in seen('engine_families.csv'):
        res = FamilyExtractor.parse(engine, family)
        try:
            if res:
                print_string(family, res.values)
                for k in res.values.keys():
                    elts.add(k)
        except AttributeError as e:
            print("ATTRERRR", e)
            continue
        if type(res) != dict:
            continue
        # for k, v in res.items():
        #     platform_map.setdefault(engine, {})
        #     platform_map[engine].setdefault(k, set())
        #     platform_map[engine][k].add(str(v).lower())
    print(elts)
    pprint.pprint(platform_map)
