"""Instance tags: free labels (typically one per customer) used to filter every view."""
import re

from periscope.i18n import N_, LocalizedError
from periscope.models import Instance, Tag, instance_tags

TAG_RE = re.compile(r"[\w][\w .-]{0,31}")
MAX_TAGS = 10


def parse(raw: str) -> list[str]:
    """Comma-separated input -> unique names (case-insensitive), in the order typed."""
    out: list[str] = []
    for part in (raw or "").split(","):
        name = " ".join(part.split())
        if not name:
            continue
        if not TAG_RE.fullmatch(name):
            raise LocalizedError(N_("Invalid tag “{tag}” (1-32 characters: letters, digits, space, . _ -)"),
                                 tag=name[:40])
        if name.casefold() not in {n.casefold() for n in out}:
            out.append(name)
    if len(out) > MAX_TAGS:
        raise LocalizedError(N_("At most {max} tags per instance"), max=MAX_TAGS)
    return out


def assign(db, inst: Instance, names: list[str]) -> None:
    """Set the instance's tags, reusing existing tags whatever their case; then drop unused tags."""
    existing = {t.name.casefold(): t for t in db.query(Tag)}
    chosen = []
    for n in names:
        tag = existing.get(n.casefold())
        if tag is None:
            tag = existing[n.casefold()] = Tag(name=n)
            db.add(tag)
        chosen.append(tag)
    inst.tags = chosen
    db.flush()
    prune(db)


def prune(db) -> None:
    used = db.query(instance_tags.c.tag_id)
    db.query(Tag).filter(~Tag.id.in_(used)).delete(synchronize_session=False)


def names(db) -> list[str]:
    return [t.name for t in db.query(Tag).order_by(Tag.name)]
