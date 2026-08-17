from decimal import Decimal
from types import MappingProxyType
from typing import Final, Mapping

FORMULA_VERSION: Final = "phase6b-v1"
ZERO: Final = Decimal("0")
ONE: Final = Decimal("1")
HUNDRED: Final = Decimal("100")
STALE_WINDOW_DAYS: Final = 30

PROVIDER_TTL_SECONDS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "nvd": 86400,
        "cisa_kev": 21600,
        "epss": 86400,
        "virustotal": 86400,
        "abuseipdb": 86400,
    }
)

CVE_WEIGHTS: Final[Mapping[str, Decimal]] = MappingProxyType(
    {
        "nvd_cvss": Decimal("35"),
        "cisa_kev": Decimal("30"),
        "epss_probability": Decimal("15"),
        "epss_percentile": Decimal("10"),
        "independent_sources": Decimal("10"),
    }
)

NON_CVE_VT_WEIGHT: Final = Decimal("80")
IP_PROVIDER_WEIGHT: Final = Decimal("40")
NON_CVE_SOURCE_WEIGHT: Final = Decimal("10")
