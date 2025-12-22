"""
Utility functions shared across the torscope package.
"""


def pad_base64(value: str) -> str:
    """
    Add standard base64 padding if missing.

    Base64 strings should be padded to a multiple of 4 characters.
    This function adds the required '=' padding characters.

    Args:
        value: Base64 string (possibly without padding)

    Returns:
        Base64 string with proper padding
    """
    stripped = value.rstrip("=")
    padding = (4 - len(stripped) % 4) % 4
    return stripped + "=" * padding if padding else stripped
