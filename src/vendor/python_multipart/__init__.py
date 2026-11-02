"""Python-multipart compatibility module for FastAPI / Starlette."""

__version__ = "0.0.9"

from .multipart import (
    MultipartParser,
    parse_options_header,
)

__all__ = ["MultipartParser", "parse_options_header", "__version__"]
