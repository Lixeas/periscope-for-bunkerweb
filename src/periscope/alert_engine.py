"""Alert engine: compares what the collector observed with what was last notified, per subject.

Works only from the database (like the web layer). `evaluate_*` return the `Notification`s to send;
delivery is `alert_send`'s job. State lives in `alert_state` so confirmations survive a restart.
"""
import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from periscope import diff
from periscope.clock import utcnow
from periscope.db import session_scope
from periscope.models import AlertState, CertProbe, Instance

log = logging.getLogger("periscope.alerts")

CONFIRM = 2  # consecutive observations of a new status before it is notified
REMIND_AFTER = timedelta(hours=24)  # reminder period while an instance stays degraded / down
STATUSES = ("ok", "degraded", "down")


@dataclass(frozen=True)
class Notification:
    type: str  # instance_down|degraded|resolved|reminder, cert_orange|red|expired|error|resolved, instance_version_changed, test
    event: str  # channel switch it falls under: down | degraded | certificate | version | test
    instance_id: int
    instance: str
    tags: tuple[str, ...]
    status: str = ""
    message: str = ""  # stored (language-neutral) last_error; rendered in the channel's language
    domain: str = ""
    not_after: datetime | None = None
    days_left: int | None = None
    since: datetime | None = None
    version: str = ""


def step(st: AlertState, observed: str, now: datetime) -> tuple[str, str] | None:
    """Advance one subject. Returns ("change", previous_notified), ("reminder", observed) or None."""
    if observed == st.notified:
        st.pending, st.pending_count = "", 0
        if observed != "ok" and st.notified_at and now - st.notified_at >= REMIND_AFTER:
            st.notified_at = now
            return "reminder", observed
        return None
    # two different problem states in a row (down, degraded, down...) still count as "not ok": the latest wins
    same = st.pending == observed or (st.pending not in ("", "ok") and observed != "ok")
    st.pending_count = st.pending_count + 1 if same else 1
    st.pending = observed
    if st.pending_count < CONFIRM:
        return None
    previous = st.notified
    st.notified, st.pending, st.pending_count, st.notified_at = observed, "", 0, now
    return "change", previous


def _get_state(s, kind: str, instance_id: int, subject: str, baseline: str, now: datetime):
    """(state, created): a new subject starts as a silent baseline, already 'notified'."""
    st = s.query(AlertState).filter_by(kind=kind, instance_id=instance_id, subject=subject).one_or_none()
    if st is not None:
        return st, False
    st = AlertState(kind=kind, instance_id=instance_id, subject=subject, notified=baseline,
                    pending="", pending_count=0, notified_at=now)
    s.add(st)
    return st, True


def _drop_states(s, instance_id: int) -> None:
    s.query(AlertState).filter_by(instance_id=instance_id).delete()


def evaluate_status(now: datetime | None = None) -> list[Notification]:
    """Instance status (with reminders) and BunkerWeb version changes."""
    now = now or utcnow()
    out: list[Notification] = []
    with session_scope() as s:
        for inst in s.query(Instance).order_by(Instance.id):
            if not inst.enabled:
                _drop_states(s, inst.id)
                continue
            if inst.silenced_until and inst.silenced_until > now:
                continue
            tags = tuple(t.name for t in inst.tags)
            base = {"instance_id": inst.id, "instance": inst.name, "tags": tags}
            observed = inst.status if inst.status in STATUSES else None
            st, created = _get_state(s, "status", inst.id, "", observed or "ok", now)
            if observed and not created:
                before = st.notified_at
                result = step(st, observed, now)
                if result and result[0] == "reminder":
                    out.append(Notification("instance_reminder", observed, status=observed, message=inst.last_error,
                                            since=before, **base))
                elif result:
                    new, previous = observed, result[1]
                    if new == "ok":
                        out.append(Notification("instance_resolved", previous, status="ok", since=now, **base))
                    else:
                        out.append(Notification(f"instance_{new}", new, status=new, message=inst.last_error,
                                                since=now, **base))
            if inst.version:
                vst, vcreated = _get_state(s, "version", inst.id, "", inst.version, now)
                if not vcreated and vst.notified != inst.version:
                    vst.notified, vst.notified_at = inst.version, now
                    out.append(Notification("instance_version_changed", "version", version=inst.version, **base))
    return out


CERT_TYPES = {"orange": "cert_orange", "red": "cert_red", "expired": "cert_expired", "none": "cert_error",
              "ok": "cert_resolved"}


def evaluate_certs(now: datetime | None = None) -> list[Notification]:
    """Certificate zone changes per (instance, domain); `none` = the TLS probe failed. No reminders."""
    now = now or utcnow()
    out: list[Notification] = []
    with session_scope() as s:
        for inst in s.query(Instance).order_by(Instance.id):
            if not inst.enabled:
                _drop_states(s, inst.id)
                continue
            if inst.silenced_until and inst.silenced_until > now:
                continue
            probes = s.query(CertProbe).filter_by(instance_id=inst.id).order_by(CertProbe.domain).all()
            domains = {p.domain for p in probes}
            s.query(AlertState).filter(AlertState.kind == "cert", AlertState.instance_id == inst.id,
                                       AlertState.subject.not_in(domains)).delete(synchronize_session=False)
            tags = tuple(t.name for t in inst.tags)
            for p in probes:
                zone = diff.cert_status(p.present, p.not_after, now)
                st, created = _get_state(s, "cert", inst.id, p.domain, zone, now)
                if created:
                    continue
                result = step(st, zone, now)
                if result and result[0] == "change":
                    out.append(Notification(CERT_TYPES[zone], "certificate", inst.id, inst.name, tags, domain=p.domain,
                                            not_after=p.not_after, days_left=diff.days_left(p.not_after, now),
                                            message=p.error, since=now))
    return out


_background: set[asyncio.Task] = set()  # delivery tasks in flight (a reference keeps them alive)


async def drain() -> None:
    """Wait for the deliveries in flight (tests, shutdown)."""
    while _background:
        await asyncio.gather(*list(_background), return_exceptions=True)


async def _run(evaluate: Callable[[], list[Notification]]) -> None:
    """Evaluate (DB work in a thread), then deliver in the background: a dead webhook or a slow SMTP
    server (3 attempts, timeouts) must not delay the next collection. Never raises: alerting must not
    be able to break the collector. State already advanced, so delivery order does not matter."""
    try:
        notifications = await asyncio.to_thread(evaluate)
        if notifications:
            from periscope import alert_send  # alert_send imports this module

            task = asyncio.create_task(alert_send.dispatch(notifications))
            _background.add(task)
            task.add_done_callback(_background.discard)
    except Exception:
        log.exception("alert evaluation failed")


async def run_status() -> None:
    await _run(evaluate_status)


async def run_certs() -> None:
    await _run(evaluate_certs)
