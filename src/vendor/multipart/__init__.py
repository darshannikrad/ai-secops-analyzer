"""Multipart compatibility module."""

from python_multipart import __version__
from python_multipart.multipart import MultipartParser, parse_options_header

__all__ = ["MultipartParser", "parse_options_header", "__version__"]
