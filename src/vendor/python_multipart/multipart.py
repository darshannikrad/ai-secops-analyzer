"""MultipartParser and header parsing utilities for Starlette/FastAPI."""

from __future__ import annotations

from typing import Any, Callable, Dict, Tuple


def parse_options_header(value: Any) -> Tuple[bytes, Dict[bytes, bytes]]:
    """Parse Content-Type or Content-Disposition options header into (type, params)."""
    if not value:
        return b"", {}
    if isinstance(value, str):
        bval = value.encode("latin-1")
    else:
        bval = value

    parts = bval.split(b";")
    content_type = parts[0].strip()
    options: Dict[bytes, bytes] = {}
    for part in parts[1:]:
        if b"=" in part:
            k, v = part.split(b"=", 1)
            k = k.strip().lower()
            v = v.strip()
            if v.startswith(b'"') and v.endswith(b'"'):
                v = v[1:-1]
            options[k] = v
    return content_type, options


class MultipartParser:
    """Incremental or buffered parser for multipart/form-data."""

    def __init__(self, boundary: bytes, callbacks: Dict[str, Callable[..., Any]]):
        self.boundary = boundary
        self.callbacks = callbacks
        self.buffer = bytearray()

    def write(self, data: bytes) -> None:
        """Accumulate chunk and stream parsed parts."""
        self.buffer.extend(data)
        # Parse complete parts if any
        self._process_buffer(is_final=False)

    def finalize(self) -> None:
        """Flush remaining buffer."""
        self._process_buffer(is_final=True)
        if "on_end" in self.callbacks:
            self.callbacks["on_end"]()

    def _process_buffer(self, is_final: bool) -> None:
        buf = bytes(self.buffer)
        b_delimiter = b"--" + self.boundary

        if b_delimiter not in buf:
            return

        parts = buf.split(b_delimiter)
        # Keep the last part in buffer if not final
        if not is_final:
            self.buffer = bytearray(parts[-1])
            parts = parts[:-1]
        else:
            self.buffer.clear()

        for part in parts:
            part_clean = part.strip()
            if not part_clean or part_clean == b"--":
                continue
            if part_clean.endswith(b"--"):
                part_clean = part_clean[:-2].rstrip()

            if b"\r\n\r\n" in part_clean:
                header_data, body = part_clean.split(b"\r\n\r\n", 1)
            elif b"\n\n" in part_clean:
                header_data, body = part_clean.split(b"\n\n", 1)
            else:
                continue

            if "on_part_begin" in self.callbacks:
                self.callbacks["on_part_begin"]()

            for hline in header_data.splitlines():
                if b":" in hline:
                    hname, hval = hline.split(b":", 1)
                    if "on_header_field" in self.callbacks:
                        self.callbacks["on_header_field"](hname.strip(), 0, len(hname.strip()))
                    if "on_header_value" in self.callbacks:
                        self.callbacks["on_header_value"](hval.strip(), 0, len(hval.strip()))
                    if "on_header_end" in self.callbacks:
                        self.callbacks["on_header_end"]()

            if "on_headers_finished" in self.callbacks:
                self.callbacks["on_headers_finished"]()

            if "on_part_data" in self.callbacks:
                self.callbacks["on_part_data"](body, 0, len(body))

            if "on_part_end" in self.callbacks:
                self.callbacks["on_part_end"]()
