class IntegrationError(Exception):
    """Base integration exception."""


class ContractError(IntegrationError):
    """Raised for non-retryable contract issues."""


class UpstreamUnavailable(IntegrationError):
    """Raised when the management system is unavailable."""

