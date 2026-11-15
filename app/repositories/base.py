"""Base repository interface enforcing circle-level isolation."""
from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, List, Optional, TypeVar

from app.services.firestore import CircleSecurityContext

T = TypeVar("T")


class BaseRepositoryInterface(ABC, Generic[T]):
    """
    Abstract Base Repository contract.
    Mandates that all entity queries and mutations are bounded by CircleSecurityContext.
    """

    def __init__(self, circle_context: CircleSecurityContext):
        self.context = circle_context
        self.circle_id = circle_context.circle_id

    @property
    @abstractmethod
    def collection_name(self) -> str:
        """Firestore collection name for this entity."""
        pass

    @abstractmethod
    async def get_by_id(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a document by ID with verified circle isolation."""
        pass

    @abstractmethod
    async def list_for_circle(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List documents strictly belonging to the authenticated circle."""
        pass

    @abstractmethod
    async def create(self, doc_id: Optional[str], data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a document ensuring circle_id payload isolation."""
        pass

    @abstractmethod
    async def update(self, doc_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a document after verifying circle ownership."""
        pass

    @abstractmethod
    async def delete(self, doc_id: str) -> bool:
        """Delete a document strictly after verifying circle ownership."""
        pass
