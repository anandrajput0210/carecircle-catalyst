"""Repository interfaces for CareCircle healthcare domain entities."""
from app.repositories.base import BaseRepositoryInterface
from app.repositories.circle import CircleRepositoryInterface
from app.repositories.invitation import InvitationRepositoryInterface
from app.repositories.medication import MedicationRepositoryInterface
from app.repositories.ledger import DoseLedgerRepositoryInterface
from app.repositories.appointment import AppointmentRepositoryInterface
from app.repositories.escalation import EscalationRepositoryInterface

__all__ = [
    "BaseRepositoryInterface",
    "CircleRepositoryInterface",
    "InvitationRepositoryInterface",
    "MedicationRepositoryInterface",
    "DoseLedgerRepositoryInterface",
    "AppointmentRepositoryInterface",
    "EscalationRepositoryInterface",
]
