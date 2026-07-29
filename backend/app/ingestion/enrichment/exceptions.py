class EnrichmentError(Exception):
    """Base exception safe for conversion into a controlled failure result."""

    error_code = "enrichment_error"


class ProviderAuthenticationError(EnrichmentError):
    error_code = "authentication_error"


class ProviderRateLimitError(EnrichmentError):
    error_code = "rate_limited"

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ProviderTemporaryError(EnrichmentError):
    error_code = "temporary_failure"


class ProviderResponseError(EnrichmentError):
    error_code = "invalid_response"
