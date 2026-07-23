class EnrichmentError(Exception):
    """Base exception safe for conversion into a controlled failure result."""


class ProviderAuthenticationError(EnrichmentError):
    pass


class ProviderRateLimitError(EnrichmentError):
    pass


class ProviderTemporaryError(EnrichmentError):
    pass


class ProviderResponseError(EnrichmentError):
    pass
