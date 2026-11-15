"""Medication scheduling, administration, shared dose ledger, and care brief service."""
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from fastapi import HTTPException, status

from app.models.auth import MemberDoc, MemberRole
from app.models.medication import (
    CareBriefResponse,
    DoseItemResponse,
    DoseStatus,
    MedicationCreateRequest,
    MedicationDoc,
    MedicationPublicResponse,
    MedicationUpdateRequest,
)
from app.repositories.firestore_circle import FirestoreCircleRepository
from app.repositories.firestore_ledger import FirestoreDoseLedgerRepository
from app.repositories.firestore_medication import FirestoreMedicationRepository
from app.services.firestore import (
    CircleIsolationViolation,
    DoseConflictError,
    make_deterministic_dose_id,
)

logger = logging.getLogger("carecircle.service.medication")


class MedicationService:
    """Service handling prescription regimens, daily schedules, dose ledgers, and care briefs."""

    def __init__(
        self,
        med_repo: Optional[FirestoreMedicationRepository] = None,
        ledger_repo: Optional[FirestoreDoseLedgerRepository] = None,
        circle_repo: Optional[FirestoreCircleRepository] = None,
    ):
        self.med_repo = med_repo or FirestoreMedicationRepository()
        self.ledger_repo = ledger_repo or FirestoreDoseLedgerRepository()
        self.circle_repo = circle_repo or FirestoreCircleRepository()

    # =========================================================================
    # Medication Regimen Management
    # =========================================================================

    async def create_medication(
        self,
        circle_id: str,
        creator: MemberDoc,
        payload: MedicationCreateRequest,
    ) -> MedicationPublicResponse:
        """Create a new prescription medication regimen (Primary Caregiver only)."""
        circle = await self.circle_repo.get_circle(circle_id)
        if not circle or not circle.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Care circle not found.",
            )

        # Identify elder member for association
        elder_id = payload.elder_id
        if not elder_id:
            members = await self.circle_repo.list_members(circle_id)
            for m in members:
                if m.get("role") == MemberRole.ELDER.value and m.get("is_active", True):
                    elder_id = m["member_id"]
                    break
        if not elder_id:
            elder_id = f"elder_{circle_id[:8]}"

        # Clinical Safety Guard: Prevent duplicate active prescriptions in the same circle
        active_meds = await self.med_repo.list_medications(circle_id, active_only=True)
        for existing in active_meds:
            if existing.get("name", "").strip().lower() == payload.name.strip().lower():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Safety conflict: An active prescription for '{payload.name}' already exists in this care circle. Please update the existing regimen instead of creating a duplicate.",
                )

        now_iso = datetime.now(timezone.utc).isoformat()
        med_id = str(uuid.uuid4())

        med_doc = MedicationDoc(
            med_id=med_id,
            circle_id=circle_id,
            elder_id=elder_id,
            name=payload.name,
            dosage_instructions=payload.dosage_instructions,
            frequency=payload.frequency,
            scheduled_times=payload.scheduled_times,
            start_date=payload.start_date,
            end_date=payload.end_date,
            notes=payload.notes,
            is_active=True,
            is_paused=False,
            created_by=creator.member_id,
            created_by_name=creator.display_name,
            created_at=now_iso,
        )

        saved = await self.med_repo.create_medication(circle_id, med_doc.model_dump(), med_id=med_id)
        return MedicationPublicResponse(**saved)

    async def update_medication(
        self,
        circle_id: str,
        updater: MemberDoc,
        med_id: str,
        payload: MedicationUpdateRequest,
    ) -> MedicationPublicResponse:
        """Update medication details (Primary Caregiver only)."""
        try:
            existing = await self.med_repo.get_medication(circle_id, med_id)
        except CircleIsolationViolation:
            existing = None
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Medication not found in care circle.",
            )

        update_data: Dict[str, Any] = {}
        if payload.name is not None:
            update_data["name"] = payload.name
        if payload.dosage_instructions is not None:
            update_data["dosage_instructions"] = payload.dosage_instructions
        if payload.frequency is not None:
            update_data["frequency"] = payload.frequency.value
        if payload.scheduled_times is not None:
            update_data["scheduled_times"] = payload.scheduled_times
        if payload.start_date is not None:
            update_data["start_date"] = payload.start_date
        if payload.end_date is not None:
            update_data["end_date"] = payload.end_date
        if payload.notes is not None:
            update_data["notes"] = payload.notes
        if payload.is_active is not None:
            update_data["is_active"] = payload.is_active
        if payload.is_paused is not None:
            update_data["is_paused"] = payload.is_paused

        updated = await self.med_repo.update_medication(circle_id, med_id, update_data)
        return MedicationPublicResponse(**updated)

    async def get_medication(self, circle_id: str, med_id: str) -> MedicationPublicResponse:
        """Retrieve single medication document ensuring circle isolation."""
        try:
            med = await self.med_repo.get_medication(circle_id, med_id)
        except CircleIsolationViolation:
            med = None
        if not med:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Medication not found in care circle.",
            )
        return MedicationPublicResponse(**med)

    async def list_medications(
        self, circle_id: str, active_only: bool = False
    ) -> List[MedicationPublicResponse]:
        """List medications for circle."""
        meds = await self.med_repo.list_medications(circle_id, active_only=active_only)
        return [MedicationPublicResponse(**m) for m in meds]

    async def deactivate_medication(
        self, circle_id: str, actor: MemberDoc, med_id: str
    ) -> MedicationPublicResponse:
        """Soft-deactivate a medication regimen, preserving historical dose logs."""
        try:
            med = await self.med_repo.get_medication(circle_id, med_id)
        except CircleIsolationViolation:
            med = None
        if not med:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Medication not found in care circle.",
            )
        updated = await self.med_repo.set_active_status(med_id, is_active=False, circle_id=circle_id)
        return MedicationPublicResponse(**updated)

    async def toggle_paused_medication(
        self, circle_id: str, actor: MemberDoc, med_id: str, is_paused: bool
    ) -> MedicationPublicResponse:
        """Pause or resume a medication regimen."""
        try:
            med = await self.med_repo.get_medication(circle_id, med_id)
        except CircleIsolationViolation:
            med = None
        if not med:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Medication not found in care circle.",
            )
        updated = await self.med_repo.set_paused_status(med_id, is_paused=is_paused, circle_id=circle_id)
        return MedicationPublicResponse(**updated)

    # =========================================================================
    # Daily Schedule Generation & Dose State Machine
    # =========================================================================

    async def get_daily_schedule(
        self,
        circle_id: str,
        member: MemberDoc,
        target_date: Optional[str] = None,
    ) -> List[DoseItemResponse]:
        """
        Generate deterministic daily dose schedule for target_date (YYYY-MM-DD).
        - Computes deterministic dose_id for each time slot.
        - Correlates with immutable ledger records.
        - Evaluates status transitions: UPCOMING -> DUE -> CONFIRMED / OVERDUE / MISSED / PAUSED.
        - Enforces role-based action permissions: Family members have read-only observer view.
        """
        now = datetime.now(timezone.utc)
        today_str = now.strftime("%Y-%m-%d")
        eval_date = target_date.strip() if target_date else today_str

        # Bounded query: active medications only
        active_meds = await self.med_repo.list_medications(circle_id, active_only=True)
        # Bounded query: dose events on eval_date only
        ledger_doses = await self.ledger_repo.list_doses_for_date(eval_date, circle_id=circle_id)
        ledger_lookup = {d["dose_id"]: d for d in ledger_doses}

        # Role permission: Family members cannot confirm doses
        is_family = (member.role == MemberRole.FAMILY)

        results: List[DoseItemResponse] = []

        for med in active_meds:
            # Check date boundaries
            start_date = med.get("start_date", "")
            end_date = med.get("end_date")
            if eval_date < start_date:
                continue
            if end_date and eval_date > end_date:
                continue

            is_paused = med.get("is_paused", False)
            times = med.get("scheduled_times", [])

            for time_str in times:
                dose_id = make_deterministic_dose_id(circle_id, med["med_id"], eval_date, time_str)
                scheduled_iso = f"{eval_date}T{time_str}:00+00:00"

                # Check if already logged in ledger
                ledger_record = ledger_lookup.get(dose_id)

                if is_paused and not ledger_record:
                    results.append(
                        DoseItemResponse(
                            dose_id=dose_id,
                            medication_id=med["med_id"],
                            medication_name=med["name"],
                            dosage_instructions=med["dosage_instructions"],
                            scheduled_date=eval_date,
                            scheduled_time=time_str,
                            scheduled_iso=scheduled_iso,
                            status=DoseStatus.PAUSED,
                            status_label="Paused",
                            is_taken=False,
                            can_confirm=False,
                            notes=med.get("notes"),
                        )
                    )
                    continue

                if ledger_record and ledger_record.get("status") == "taken":
                    results.append(
                        DoseItemResponse(
                            dose_id=dose_id,
                            medication_id=med["med_id"],
                            medication_name=med["name"],
                            dosage_instructions=med["dosage_instructions"],
                            scheduled_date=eval_date,
                            scheduled_time=time_str,
                            scheduled_iso=scheduled_iso,
                            status=DoseStatus.TAKEN,
                            status_label="Confirmed",
                            is_taken=True,
                            can_confirm=False,
                            confirmed_at=ledger_record.get("logged_at"),
                            confirmed_by_name=ledger_record.get("logged_by_name"),
                            confirmed_by_role=ledger_record.get("logged_by_role"),
                            notes=ledger_record.get("notes"),
                        )
                    )
                    continue

                if ledger_record and ledger_record.get("status") == "skipped":
                    results.append(
                        DoseItemResponse(
                            dose_id=dose_id,
                            medication_id=med["med_id"],
                            medication_name=med["name"],
                            dosage_instructions=med["dosage_instructions"],
                            scheduled_date=eval_date,
                            scheduled_time=time_str,
                            scheduled_iso=scheduled_iso,
                            status=DoseStatus.MISSED,
                            status_label="Missed",
                            is_taken=False,
                            can_confirm=False,
                            notes=ledger_record.get("notes"),
                        )
                    )
                    continue

                # Deterministic time calculation for pending doses
                sched_dt = datetime.fromisoformat(scheduled_iso)

                if now < sched_dt - timedelta(minutes=30):
                    dose_status = DoseStatus.UPCOMING
                    status_label = "Upcoming"
                    can_confirm = (not is_family)
                elif sched_dt - timedelta(minutes=30) <= now <= sched_dt + timedelta(minutes=60):
                    dose_status = DoseStatus.DUE
                    status_label = "Due Now"
                    can_confirm = (not is_family)
                elif eval_date < today_str:
                    dose_status = DoseStatus.MISSED
                    status_label = "Missed"
                    can_confirm = False
                else:
                    # Scheduled time + 60 min elapsed today without confirmation
                    dose_status = DoseStatus.OVERDUE
                    status_label = "Overdue"
                    can_confirm = (not is_family)

                results.append(
                    DoseItemResponse(
                        dose_id=dose_id,
                        medication_id=med["med_id"],
                        medication_name=med["name"],
                        dosage_instructions=med["dosage_instructions"],
                        scheduled_date=eval_date,
                        scheduled_time=time_str,
                        scheduled_iso=scheduled_iso,
                        status=dose_status,
                        status_label=status_label,
                        is_taken=False,
                        can_confirm=can_confirm,
                        notes=med.get("notes"),
                    )
                )

        # Chronological sort by scheduled time
        results.sort(key=lambda d: d.scheduled_time)
        return results

    # =========================================================================
    # Shared Dose Ledger Confirmation & Concurrency Control
    # =========================================================================

    async def confirm_dose(
        self,
        circle_id: str,
        confirming_member: MemberDoc,
        dose_id: str,
        notes: Optional[str] = None,
    ) -> DoseItemResponse:
        """
        Atomically record dose confirmation into immutable shared ledger.
        - Enforces role RBAC: Family members strictly prohibited.
        - Enforces deterministic duplicate prevention: Concurrent or duplicate confirmations
          are rejected atomically with HTTP 409 Conflict via DoseConflictError.
        """
        # Role guard: Family role is read-only observer
        if confirming_member.role == MemberRole.FAMILY:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access forbidden: Family members have read-only observer permissions and cannot administer or confirm medications.",
            )

        if not dose_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="dose_id is required.")

        # Parse deterministic dose_id format: {circle_id}_{med_id}_{YYYY-MM-DD}_{HH-MM}
        parts = dose_id.split("_")
        if len(parts) < 4:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid dose_id format.")

        # Check that the dose belongs to the caller's circle
        if parts[0] != circle_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dose does not belong to this care circle.",
            )

        med_id = parts[1]
        sched_date = parts[2]
        sched_time = parts[3].replace("-", ":")

        # Validate medication belongs to current circle
        try:
            med = await self.med_repo.get_medication(circle_id, med_id)
        except CircleIsolationViolation:
            med = None
        if not med:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Medication not found in care circle.",
            )

        initial_meta = {
            "elder_id": med.get("elder_id", ""),
            "medication_id": med["med_id"],
            "medication_name": med["name"],
            "dosage_instructions": med["dosage_instructions"],
            "scheduled_date": sched_date,
            "scheduled_time": sched_time,
            "scheduled_datetime_utc": f"{sched_date}T{sched_time}:00+00:00",
            "source": "elder_tap" if confirming_member.role == MemberRole.ELDER else "caregiver_log",
        }

        try:
            confirmed_record = await self.ledger_repo.confirm_dose_atomic(
                dose_id=dose_id,
                logged_by_member_id=confirming_member.member_id,
                logged_by_name=confirming_member.display_name,
                logged_by_role=confirming_member.role.value,
                notes=notes,
                circle_id=circle_id,
                initial_dose_meta=initial_meta,
            )
        except DoseConflictError as e:
            logger.warning(f"Duplicate dose confirmation blocked: {e}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e),
            )

        return DoseItemResponse(
            dose_id=dose_id,
            medication_id=med["med_id"],
            medication_name=med["name"],
            dosage_instructions=med["dosage_instructions"],
            scheduled_date=sched_date,
            scheduled_time=sched_time,
            scheduled_iso=f"{sched_date}T{sched_time}:00+00:00",
            status=DoseStatus.TAKEN,
            status_label="Confirmed",
            is_taken=True,
            can_confirm=False,
            confirmed_at=confirmed_record.get("logged_at"),
            confirmed_by_name=confirmed_record.get("logged_by_name"),
            confirmed_by_role=confirmed_record.get("logged_by_role"),
            notes=confirmed_record.get("notes"),
        )

    async def list_dose_ledger(
        self, circle_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieve recent immutable dose ledger audit history (bounded)."""
        return await self.ledger_repo.list_dose_history(circle_id, limit=limit)

    # =========================================================================
    # Context-Aware Care Brief (Zero-Hallucination Local Intelligence)
    # =========================================================================

    async def get_care_brief(
        self,
        circle_id: str,
        member: MemberDoc,
        target_date: Optional[str] = None,
    ) -> CareBriefResponse:
        """
        Generate deterministic, context-aware Care Brief from actual application records.
        - Reads authorized circle schedule.
        - Analyzes confirmed vs pending vs overdue doses.
        - Strictly factual: never diagnoses, prescribes, or claims unverified events.
        """
        now = datetime.now(timezone.utc)
        today_str = now.strftime("%Y-%m-%d")
        eval_date = target_date.strip() if target_date else today_str

        doses = await self.get_daily_schedule(circle_id, member, target_date=eval_date)
        active_meds = await self.med_repo.list_medications(circle_id, active_only=True)

        total_doses = len(doses)
        confirmed_doses = [d for d in doses if d.is_taken]
        overdue_doses = [d for d in doses if d.status == DoseStatus.OVERDUE]
        missed_doses = [d for d in doses if d.status == DoseStatus.MISSED]
        due_doses = [d for d in doses if d.status == DoseStatus.DUE]
        upcoming_doses = [d for d in doses if d.status == DoseStatus.UPCOMING]

        confirmed_count = len(confirmed_doses)
        overdue_count = len(overdue_doses)
        missed_count = len(missed_doses)
        due_count = len(due_doses)
        pending_count = overdue_count + missed_count + due_count + len(upcoming_doses)

        bullet_points: List[str] = []
        next_dose_summary: Optional[str] = None
        last_confirmed_summary: Optional[str] = None

        # Determine next dose
        if due_doses:
            next_due = due_doses[0]
            next_dose_summary = f"{next_due.medication_name} ({next_due.dosage_instructions}) at {next_due.scheduled_time} — DUE NOW"
        elif upcoming_doses:
            next_up = upcoming_doses[0]
            next_dose_summary = f"{next_up.medication_name} at {next_up.scheduled_time}"

        # Determine last confirmed dose
        if confirmed_doses:
            latest = confirmed_doses[-1]
            time_part = latest.confirmed_at[11:16] if latest.confirmed_at else latest.scheduled_time
            by_part = f" by {latest.confirmed_by_name}" if latest.confirmed_by_name else ""
            last_confirmed_summary = f"{latest.medication_name} confirmed at {time_part} UTC{by_part}"

        # Evaluate Tone & Bullet Points
        if overdue_count > 0 or missed_count > 0:
            status_tone = "alert"
            headline = f"Action Required: {overdue_count + missed_count} Dose(s) Need Attention"
            for od in overdue_doses:
                bullet_points.append(
                    f"OVERDUE: {od.medication_name} scheduled for {od.scheduled_time} has not been recorded."
                )
            for md in missed_doses:
                bullet_points.append(
                    f"MISSED: {md.medication_name} scheduled for {md.scheduled_time} was unrecorded on {eval_date}."
                )
            if confirmed_count > 0:
                bullet_points.append(f"{confirmed_count} of {total_doses} dose(s) successfully recorded today.")
        elif due_count > 0:
            status_tone = "warning"
            headline = f"Medication Due Now: {due_count} Dose(s) Scheduled"
            for dd in due_doses:
                bullet_points.append(
                    f"DUE NOW: {dd.medication_name} ({dd.dosage_instructions}) scheduled for {dd.scheduled_time}."
                )
            if confirmed_count > 0:
                bullet_points.append(f"{confirmed_count} of {total_doses} dose(s) already completed.")
        elif total_doses > 0 and confirmed_count == total_doses:
            status_tone = "success"
            headline = f"All Set! All {total_doses} Scheduled Doses Confirmed"
            bullet_points.append(f"All medications for {eval_date} have been confirmed.")
            if last_confirmed_summary:
                bullet_points.append(f"Latest: {last_confirmed_summary}.")
        elif total_doses == 0:
            status_tone = "neutral"
            headline = "No Active Prescriptions Scheduled Today"
            bullet_points.append("No medication times are currently scheduled for this date.")
        else:
            status_tone = "neutral"
            headline = f"Today's Schedule: {confirmed_count} of {total_doses} Doses Completed"
            if next_dose_summary:
                bullet_points.append(f"Upcoming: {next_dose_summary}.")
            if last_confirmed_summary:
                bullet_points.append(f"Last confirmed: {last_confirmed_summary}.")

        return CareBriefResponse(
            headline=headline,
            scheduled_today_count=total_doses,
            confirmed_today_count=confirmed_count,
            pending_today_count=pending_count,
            overdue_count=overdue_count,
            missed_count=missed_count,
            active_medications_count=len(active_meds),
            status_tone=status_tone,
            bullet_points=bullet_points,
            next_dose_summary=next_dose_summary,
            last_confirmed_summary=last_confirmed_summary,
            generated_at=now.isoformat(),
        )
