"""Security primitives: secret redaction and target/scope validation."""
from .redact import find_secrets, mask_secret, redact_mapping, redact_text  # noqa: F401
from .validate import (  # noqa: F401
    classify_target,
    is_special_address,
    target_in_scope,
    validate_target,
)
