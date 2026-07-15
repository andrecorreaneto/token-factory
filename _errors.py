class CallerAssertionValidationError(RuntimeError):
    """Raised when an incoming caller assertion fails validation."""


class OAuthClientResolutionError(RuntimeError):
    """Raised when the selected OAuth client cannot be resolved."""


class AuthorizationError(RuntimeError):
    """Raised when a validated caller is not authorized for a requested scope."""


class AuthorizationPolicyError(RuntimeError):
    """Raised when authorization policy cannot be loaded or parsed."""
