# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 6.2: bounded, SHA256-pinned *data* cache; not remote physical RAM."""
from collections import OrderedDict
import hashlib
import re


class CacheUnavailable(Exception):
    pass


class IntegrityFailure(Exception):
    pass


class RemotePageCache:
    def __init__(self, capacity_pages=8, page_size=4096):
        if not isinstance(capacity_pages, int) or isinstance(capacity_pages, bool) or not 1 <= capacity_pages <= 64:
            raise ValueError("capacity must be 1..64 pages")
        if page_size != 4096:
            raise ValueError("this prototype supports exactly 4096-byte data pages")
        self.capacity = capacity_pages
        self.page_size = page_size
        self._pages = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, page_id: str, pinned_sha256: str, fetch, *, purpose="public-data") -> bytes:
        if (not isinstance(page_id, str) or
            re.fullmatch(r"[a-z0-9_-]{1,64}", page_id) is None or
            not isinstance(pinned_sha256, str) or
            re.fullmatch(r"[0-9a-f]{64}", pinned_sha256) is None or
            purpose != "public-data"):
            raise ValueError("only pinned non-sensitive named data pages supported")
        if not callable(fetch):
            raise TypeError("fetch must be a callable")
        key=(page_id,pinned_sha256)
        if key in self._pages:
            value=self._pages[key]
            if hashlib.sha256(value).hexdigest() != pinned_sha256:
                self._pages.pop(key)
                raise IntegrityFailure("cached data integrity failure")
            self._pages.move_to_end(key)
            self.hits += 1
            return value
        self.misses += 1
        try:
            page = fetch(page_id)
        except Exception as exc:
            raise CacheUnavailable("remote read unavailable; no unverified fallback") from exc
        if not isinstance(page, bytes) or len(page) != self.page_size:
            raise IntegrityFailure("remote page length mismatch")
        if hashlib.sha256(page).hexdigest() != pinned_sha256:
            raise IntegrityFailure("remote SHA256 does not match pinned digest")
        self._pages[key] = page
        if len(self._pages) > self.capacity:
            self._pages.popitem(last=False)
            self.evictions += 1
        return page

    def invalidate(self, page_id):
        for key in list(self._pages):
            if key[0] == page_id:
                del self._pages[key]

    def clear(self):
        self._pages.clear()

    @property
    def resident_bytes(self):
        return len(self._pages) * self.page_size
