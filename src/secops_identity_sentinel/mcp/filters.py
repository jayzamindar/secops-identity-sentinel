"""
Sensitive Query Parameter Logging Filter.

Sanitizes sensitive API keys (e.g. ?apiKey=... or ?api_key=...) from HTTP access logs
adhering to GEMINI.md Section 3.4 and TRD Section 5.2.
"""

from __future__ import annotations

import logging
import re
from typing import Any

# Pattern matching apiKey or api_key query parameters in URL strings
API_KEY_QUERY_PATTERN: re.Pattern[str] = re.compile(
    r"(apiKey|api_key)=([^&\s\"']+)",
    flags=re.IGNORECASE,
)


class SensitiveQueryParamFilter(logging.Filter):
    """
    Logging filter that redacts API keys from log messages and URL records.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Redact sensitive query parameter values in-place before output.
        """
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)

        if record.args:
            if isinstance(record.args, tuple):
                new_args: list[Any] = []
                for arg in record.args:
                    if isinstance(arg, str):
                        new_args.append(self.redact(arg))
                    else:
                        new_args.append(arg)
                record.args = tuple(new_args)
            elif isinstance(record.args, dict):
                record.args = {
                    k: (self.redact(v) if isinstance(v, str) else v) for k, v in record.args.items()
                }

        return True

    @staticmethod
    def redact(text: str) -> str:
        """
        Replace sensitive key values with '***'.
        """
        return API_KEY_QUERY_PATTERN.sub(r"\1=***", text)
