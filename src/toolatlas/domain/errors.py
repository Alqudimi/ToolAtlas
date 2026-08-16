"""Typed failures exposed by the application boundary."""


class ToolAtlasError(Exception):
    """Base class for expected, user-actionable failures."""

    code = "TOOLATLAS_ERROR"
    exit_code = 5


class InputError(ToolAtlasError):
    code = "INVALID_INPUT"
    exit_code = 2


class InputTooLargeError(InputError):
    code = "INPUT_TOO_LARGE"


class SchemaError(InputError):
    code = "SCHEMA_ERROR"


class PolicyViolation(ToolAtlasError):
    code = "POLICY_VIOLATION"
    exit_code = 3


class ManifestDrift(ToolAtlasError):
    code = "MANIFEST_DRIFT"
    exit_code = 4


class PathSafetyError(InputError):
    code = "UNSAFE_PATH"
