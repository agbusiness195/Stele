"""
Stele in-memory covenant store.

Provides a MemoryStore implementation for covenant document storage,
suitable for testing, CLI tools, and scenarios where persistence
is not required.
"""

from __future__ import annotations

import copy
from typing import Optional


class MemoryStore:
    """In-memory covenant store backed by a dict.

    All operations are synchronous. Documents are defensively copied
    on put and get to prevent external mutation.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict] = {}

    def put(self, id: str, doc: dict) -> None:
        """Store a covenant document.

        Args:
            id: The document ID (typically the SHA-256 hex hash).
            doc: The covenant document dict to store.

        Raises:
            ValueError: When id is empty or doc is not a dict.
        """
        if not id or not isinstance(id, str) or id.strip() == "":
            raise ValueError("put(): id must be a non-empty string")
        if not isinstance(doc, dict):
            raise ValueError("put(): doc must be a dict")
        self._data[id] = copy.deepcopy(doc)

    def get(self, id: str) -> Optional[dict]:
        """Retrieve a covenant document by its ID.

        Returns a defensive copy so callers cannot mutate the stored data.

        Args:
            id: The document ID to look up.

        Returns:
            The document dict, or None if not found.

        Raises:
            ValueError: When id is empty.
        """
        if not id or not isinstance(id, str) or id.strip() == "":
            raise ValueError("get(): id must be a non-empty string")
        doc = self._data.get(id)
        return copy.deepcopy(doc) if doc is not None else None

    def delete(self, id: str) -> bool:
        """Delete a document by ID.

        Args:
            id: The document ID to delete.

        Returns:
            True if the document was found and deleted, False otherwise.

        Raises:
            ValueError: When id is empty.
        """
        if not id or not isinstance(id, str) or id.strip() == "":
            raise ValueError("delete(): id must be a non-empty string")
        if id in self._data:
            del self._data[id]
            return True
        return False

    def list(self) -> list[dict]:
        """List all stored documents.

        Returns:
            A list of defensive copies of all stored documents.
        """
        return [copy.deepcopy(doc) for doc in self._data.values()]

    def has(self, id: str) -> bool:
        """Check whether a document with the given ID exists.

        Args:
            id: The document ID to check.

        Returns:
            True if a document with this ID exists.
        """
        return id in self._data

    def count(self) -> int:
        """Count the number of stored documents.

        Returns:
            The number of documents in the store.
        """
        return len(self._data)
