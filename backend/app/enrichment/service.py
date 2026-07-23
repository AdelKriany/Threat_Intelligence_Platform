"""IOC enrichment service scaffolding."""

from typing import Any


class IOCService:
    """Service entrypoint for Phase 3 IOC enrichment."""

    async def extract_and_save(self, db: Any, article: Any) -> None:
        """Extract IOCs from an article and persist them."""

        pass
