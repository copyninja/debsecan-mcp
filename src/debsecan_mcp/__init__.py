"""debsecan-mcp — DEPRECATED.

This package has been renamed to **debvulns** to avoid a name clash
with the system utility ``debsecan``.

Please update your dependencies::

    pip install debvulns

or in pyproject.toml::

    dependencies = ["debvulns"]

This release (0.1.5) is the final release under the ``debsecan-mcp`` name.
All future development and releases will happen under ``debvulns``.
"""

import warnings

warnings.warn(
    "debsecan-mcp has been renamed to debvulns. "
    "Please update your dependency to 'debvulns'. "
    "This package will receive no further updates.",
    DeprecationWarning,
    stacklevel=2,
)
