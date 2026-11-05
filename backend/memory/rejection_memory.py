"""
ChromaDB Rejection-Memory RAG for AegisCI.

Stores rejected patches so the Fix-Proposer agent can avoid re-proposing
approaches that have already been tried and failed.
"""

import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aegis.memory")


def _get_client_and_collection(persist_dir: Optional[str] = None):
    """Return (chroma_client, collection). Lazy-initialised per call."""
    import chromadb  # noqa: PLC0415

    persist = persist_dir or os.getenv("CHROMA_PERSIST_DIR", "./chroma_data")
    client = chromadb.PersistentClient(path=persist)
    collection = client.get_or_create_collection(
        name="rejected_patches",
        metadata={"hnsw:space": "cosine"},
    )
    return client, collection


class RejectionMemory:
    """
    Stores rejected patches for a given incident using ChromaDB.

    Each entry captures:
    - The patch diff (truncated for embedding)
    - Diagnosis category, evidence, and rejection reason
    - Incident and attempt metadata

    Before generating a new patch the Fix-Proposer calls
    ``retrieve_similar`` to surface past failures and avoid repeating them.
    """

    def __init__(self, persist_dir: Optional[str] = None):
        self._persist_dir = persist_dir or os.getenv("CHROMA_PERSIST_DIR", "./chroma_data")
        _, self._collection = _get_client_and_collection(self._persist_dir)

    # ------------------------------------------------------------------
    # Schema helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_document(
        patch_diff: str,
        diagnosis: str,
        evidence: str,
        rejection_reason: str,
    ) -> str:
        """Compose the text string that will be embedded and searched."""
        # We embed diagnosis + evidence + a prefix of the diff so the
        # embedding captures *what failed* rather than raw diff syntax.
        snippet = patch_diff[:800].replace("\n", " ")
        return (
            f"Diagnosis: {diagnosis}\n"
            f"Evidence: {evidence}\n"
            f"Rejection reason: {rejection_reason}\n"
            f"Patch snippet: {snippet}"
        )

    @staticmethod
    def _make_metadata(
        incident_id: str,
        attempt: int,
        affected_files: List[str],
        diagnosis: str,
        rejection_reason: str,
    ) -> Dict[str, Any]:
        return {
            "incident_id": incident_id,
            "attempt": attempt,
            "affected_files": json.dumps(affected_files),
            "diagnosis": diagnosis,
            "rejection_reason": rejection_reason,
        }

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def store_rejected_patch(
        self,
        incident_id: str,
        attempt: int,
        patch_diff: str,
        diagnosis: str,
        evidence: str,
        rejection_reason: str,
        affected_files: Optional[List[str]] = None,
    ) -> str:
        """
        Persist a rejected patch. Returns the ChromaDB document ID.

        Skips storage if the patch is empty or already stored under the
        same incident + attempt combination (idempotent).
        """
        if not patch_diff or not patch_diff.strip():
            logger.warning(f"[{incident_id}] Skipping empty patch storage.")
            return ""

        doc_id = f"rej-{incident_id}-attempt{attempt}"

        # Idempotent: check if already stored
        try:
            existing = self._collection.get(ids=[doc_id])
            if existing and existing.get("ids"):
                logger.info(f"[{incident_id}] Rejection entry already stored: {doc_id}")
                return doc_id
        except Exception:
            pass  # collection may be empty

        document = self._make_document(patch_diff, diagnosis, evidence, rejection_reason)
        metadata = self._make_metadata(
            incident_id=incident_id,
            attempt=attempt,
            affected_files=affected_files or [],
            diagnosis=diagnosis,
            rejection_reason=rejection_reason,
        )

        try:
            self._collection.add(
                ids=[doc_id],
                documents=[document],
                metadatas=[metadata],
            )
            logger.info(
                f"[{incident_id}] Stored rejection entry {doc_id} "
                f"(attempt {attempt}): {rejection_reason[:80]}"
            )
        except Exception as e:
            logger.error(f"[{incident_id}] Failed to store rejection entry: {e}")

        return doc_id

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def retrieve_similar(
        self,
        query_diagnosis: str,
        query_evidence: str,
        query_patch_prefix: str = "",
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Return up to ``top_k`` stored rejections whose diagnosis and evidence
        most closely match the current failure context.

        Returns a list of dicts, each with:
        - ``document``: embedded text
        - ``metadata``: stored metadata dict
        - ``distance``: cosine distance (lower = more similar)
        """
        if self._collection.count() == 0:
            return []

        query_text = (
            f"Diagnosis: {query_diagnosis}\n"
            f"Evidence: {query_evidence}\n"
            f"Patch snippet: {query_patch_prefix[:400]}"
        )

        try:
            results = self._collection.query(
                query_texts=[query_text],
                n_results=min(top_k, self._collection.count()),
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:
            logger.error(f"ChromaDB retrieval error: {e}")
            return []

        output = []
        docs = (results.get("documents") or [[]])[0]
        metas = (results.get("metadatas") or [[]])[0]
        dists = (results.get("distances") or [[]])[0]
        for doc, meta, dist in zip(docs, metas, dists):
            output.append({"document": doc, "metadata": meta, "distance": dist})

        return output

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def count(self) -> int:
        """Return total number of stored rejection entries."""
        return self._collection.count()
