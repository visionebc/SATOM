"""New Server Policy from a line profile — plan, then apply, then compensate.

**Why a planner and not a form handler.** Creating one server policy this way
touches five systems that fail independently: the IPAM pool, DNS, the
certificate authority, the appliance, and SATOM's own template store. The
existing ``workspace.create_policy`` stops at the first failure and leaves
everything created before it — which is survivable when the objects are all on
one device and an operator can see them, and is NOT survivable once a reserved
address and an issued certificate are in the chain. Nobody finds those by
looking at the appliance.

So this module follows the three rules ``provision_runner`` is built on, for
the same reasons:

1. **A step that cannot run is refused UP FRONT.** :func:`build_plan` changes
   nothing and returns every blocker it can find, including a live name-
   collision check against the device. A run that would die after reserving an
   address is worse than one that never started.

2. **Compensation undoes only what THIS run recorded doing.** The address is
   released only if we took it, the DNS record removed only if we created it.
   Never inferred from the state of the world.

3. **The certificate is deliberately NOT revoked.** A certificate that exists
   is not harmful, revocation is destructive and irreversible, and an
   automatic revoke on a failed policy build would be this module deciding
   something no operator asked for. It is NAMED in the report instead — the
   same treatment ``provision_runner.rollback`` gives an Appliance row.

**It does not answer "what does this line get".** That is
:func:`services.line_profiles.line_plan`, and this module calls it. A second
author of that answer is the defect §132 exists to prevent.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import line_profiles as lp
from . import naming
from . import settings_store as store

#: FortiWeb create endpoints, in dependency order. Mirrors
#: ``views.workspace._CREATE_EPS`` — imported from there rather than copied so
#: the two cannot drift.
STEP_ADDRESS = "address"
STEP_DNS = "dns"
STEP_CERT = "certificate"
STEP_OBJECTS = "objects"

#: How the FortiWeb SERVER pool this policy binds comes to exist. NOT the IPAM
#: address pool — that is ``SpoPlan.pool``, a different object wearing the same
#: English word.
POOL_NEW = "new"            # this plan creates the pool and its members
POOL_EXISTING = "existing"  # already on THIS device; bind it, create nothing
POOL_SHARED = "shared"      # a sibling plan in the same batch creates it
POOL_MODES = (POOL_NEW, POOL_EXISTING, POOL_SHARED)

#: Naming elements every policy needs. These are the REAL keys
#: ``services.naming`` emits — checked against it by a guard, because inventing
#: them is exactly how this module first shipped an unnamed policy.
REQUIRED_NAMES = ("server_policy", "virtual_server", "server_pool", "vip")


@dataclass
class Blocker:
    code: str
    detail: str

    def as_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail}


@dataclass
class SpoPlan:
    appliance_id: int
    product: str
    line: str
    web_address: str
    hostname: str = ""
    names: dict = field(default_factory=dict)
    segment: dict = field(default_factory=dict)
    department: str = ""              # narrows the choice; never invents one
    pool: str = ""                    # the IPAM ADDRESS pool
    #: The FortiWeb SERVER pool the policy binds. A different object from
    #: ``pool`` above: one hands out IP addresses, the other holds real
    #: servers. They are spelled out separately everywhere they appear
    #: because one word for two objects is how a plan describes one and
    #: allocates from the other.
    pool_name: str = ""
    pool_mode: str = POOL_NEW
    #: When the operator picked a pool that lives on ANOTHER appliance, the
    #: name of that appliance. Recorded for the summary only — a foreign pool
    #: is never bound (a server pool is a per-device object), its members are
    #: copied, so the plan below is a plain ``new``.
    pool_from: str = ""
    use_ipam: bool = False
    address: str = ""                 # operator-supplied when not using IPAM
    cert_class: str = ""
    issue_cert: bool = False
    wpp_template_id: int | None = None
    wpp_template_name: str = ""
    backends: list = field(default_factory=list)
    #: Which backend each half of the plan resolved to. Shown in the summary
    #: because with several configured, "an address will be reserved" is only
    #: half a sentence — the operator has to be able to see that the address
    #: comes from one system and the name is published in another BEFORE the
    #: run, not by reading the log afterwards.
    ipam_backend: str = ""
    dns_backend: str = ""
    #: What the OPERATOR picked ("" = Auto), kept apart from what the plan
    #: RESOLVED to. Folding them would make "Auto happened to land on this
    #: one" indistinguishable from "somebody chose this one", and only the
    #: second survives an edit to the registry.
    ipam_pick: str = ""
    dns_pick: str = ""
    #: The resolved row ids. Recorded on the plan so ``apply_plan`` acts on
    #: the backend the PREVIEW named instead of resolving a second time: two
    #: resolutions in one request is how the summary and the write end up
    #: describing different systems.
    ipam_backend_id: int | None = None
    dns_backend_id: int | None = None
    line_source: str = "inferred"
    blockers: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.blockers

    def as_dict(self) -> dict:
        return {
            "appliance_id": self.appliance_id, "product": self.product,
            "line": self.line, "line_source": self.line_source,
            "web_address": self.web_address, "hostname": self.hostname,
            "names": self.names, "segment": self.segment,
            "department": self.department,
            "segment_departments": list(self.segment.get("departments") or []),
            "pool": self.pool,
            "pool_name": self.pool_name, "pool_mode": self.pool_mode,
            "pool_from": self.pool_from,
            "use_ipam": self.use_ipam, "address": self.address,
            "cert_class": self.cert_class, "issue_cert": self.issue_cert,
            "wpp_template_id": self.wpp_template_id,
            "wpp_template_name": self.wpp_template_name,
            "backends": self.backends, "ok": self.ok,
            "ipam_backend": self.ipam_backend, "dns_backend": self.dns_backend,
            "ipam_pick": self.ipam_pick, "dns_pick": self.dns_pick,
            "ipam_backend_id": self.ipam_backend_id,
            "dns_backend_id": self.dns_backend_id,
            "blockers": [b.as_dict() for b in self.blockers],
            "warnings": list(self.warnings),
        }


# --------------------------------------------------------------------------- #
#  plan — pure inspection                                                      #
# --------------------------------------------------------------------------- #
def build_plan(appliance, *, line: str, web_address: str,
               segment_name: str = "", department: str = "", hostname: str = "",
               use_ipam: bool = False, address: str = "",
               issue_cert: bool = False, backends=None,
               ipam_backend_id: object = None, dns_backend_id: object = None,
               pool_name: str = "", pool_mode: str = POOL_NEW,
               pool_from: str = "", product: str = "") -> SpoPlan:
    """Everything the run will do, and every reason it cannot. Writes nothing."""
    product = product or getattr(appliance, "kind", "") or "fortiweb"
    web_address = (web_address or "").strip()
    plan = SpoPlan(appliance_id=getattr(appliance, "id", 0), product=product,
                   line=(line or "").strip(), web_address=web_address,
                   # NOT defaulted to the web address: publishing a name is
                   # a decision, and the form says blank means "do not
                   # publish". A service that quietly published anyway would
                   # contradict the control the operator was given.
                   hostname=(hostname or "").strip(),
                   use_ipam=bool(use_ipam), address=(address or "").strip(),
                   issue_cert=bool(issue_cert),
                   department=(department or "").strip(),
                   ipam_pick=str(ipam_backend_id or "").strip(),
                   dns_pick=str(dns_backend_id or "").strip(),
                   backends=list(backends or []))

    if not web_address:
        plan.blockers.append(Blocker(
            "no_web_address", "a web address is required — every object name "
            "is derived from it"))
        return plan
    plan.names = naming.render_names(web_address, None, product)
    # The naming scheme is operator-editable, and a key that is missing or
    # renders empty does NOT crash — it produces an object called "", which
    # FortiWeb accepts far enough to be confusing. Refuse instead. (This
    # guard exists because the first version of this module used invented key
    # names, got empty strings for all four, and silently disabled the
    # name-collision check.)
    missing = [k for k in REQUIRED_NAMES if not (plan.names.get(k) or "").strip()]
    if missing:
        plan.blockers.append(Blocker(
            "naming_incomplete",
            "the naming scheme produced no name for: " + ", ".join(missing)
            + " — fix it in Settings -> Naming"))

    # -- which SERVER pool -------------------------------------------------
    plan.pool_mode = pool_mode if pool_mode in POOL_MODES else POOL_NEW
    plan.pool_from = (pool_from or "").strip()
    plan.pool_name = ((pool_name or "").strip()
                      or (plan.names.get("server_pool") or "").strip())
    if plan.pool_mode != POOL_NEW and not (pool_name or "").strip():
        # Binding "" builds a policy whose server-pool field is empty, which
        # FortiWeb accepts far enough to be confusing — the same failure the
        # naming guard above exists for.
        plan.blockers.append(Blocker(
            "no_pool_name",
            f"pool mode {plan.pool_mode!r} needs the name of the pool to bind"))

    # -- what the line gives us. ONE author; never re-derived here. ---------
    lplan = lp.line_plan(plan.line, product)
    plan.line_source = lplan.source
    for p in lplan.problems:
        if p.code in lp.BLOCKING:
            plan.blockers.append(Blocker(p.code, p.detail))
        else:
            plan.warnings.append(p.detail)
    if not lplan.declared:
        # NOT a blocker: a fleet that has not filled in profiles must still be
        # able to work. But it is the loudest warning on the page, because
        # every value below came from a string match nobody confirmed.
        plan.warnings.append(
            f"no line profile exists for {plan.line!r} — the segment, "
            "certificate class and Web Protection Profile below were INFERRED "
            "by matching names, not declared. Confirm each one.")

    # -- the segment ------------------------------------------------------
    # ONE indexer, shared with line_profiles: three call sites keying this list
    # their own way is what let a plan describe one row and allocate from
    # another when two rows shared a name (§135).
    on_line = lp.index_by_name(lplan.segments)

    # A department NARROWS the choice; it never picks a network on its own and
    # nothing downstream is named after it. Enforced HERE and not only in the
    # page, because a filter the server does not apply is a filter the server
    # does not have: the browser could post any segment on the line while the
    # operator believes the department constrained it.
    available = dict(on_line)
    if plan.department:
        available = {n: sg for n, sg in on_line.items()
                     if plan.department in (sg.get("departments") or [])}
        if not available:
            plan.blockers.append(Blocker(
                "department_not_on_line",
                f"no segment on line {plan.line!r} serves department "
                f"{plan.department!r}"))

    if segment_name:
        seg = on_line.get(segment_name)
        if seg is None:
            plan.blockers.append(Blocker(
                "segment_not_on_line",
                f"segment {segment_name!r} is not one of the segments line "
                f"{plan.line!r} receives ({', '.join(sorted(on_line)) or 'none'})"))
        elif plan.department and segment_name not in available:
            # Reported as its own refusal, not folded into the one above: "not
            # on this line" and "on this line but not for that department" are
            # different facts and lead to different fixes.
            plan.blockers.append(Blocker(
                "segment_not_in_department",
                f"segment {segment_name!r} is on line {plan.line!r} but does "
                f"not serve department {plan.department!r} — it serves "
                + (", ".join(seg.get("departments") or []) or "no department")))
        else:
            plan.segment = dict(seg)
    elif len(available) == 1:
        plan.segment = dict(next(iter(available.values())))
    elif available:
        plan.blockers.append(Blocker(
            "segment_not_chosen",
            f"line {plan.line!r} receives {len(available)} segments — pick one"))

    plan.pool = lp.pool_for(lplan, (plan.segment.get("name") or ""))

    # -- addressing -------------------------------------------------------
    if plan.use_ipam:
        if not plan.pool:
            plan.blockers.append(Blocker(
                "no_pool", "IPAM allocation was requested but neither the "
                           "line profile nor the segment says which pool to "
                           "take the address from"))
        from . import dns_providers as _dp
        res = _dp.choose("ipam", plan.pool, plan.ipam_pick)
        if res.code == _dp.NO_BACKEND:
            plan.blockers.append(Blocker(
                "no_ipam_provider", "IPAM allocation was requested but no "
                                    "backend carries the IPAM role"))
        elif plan.ipam_pick and not res.ok:
            # A rejected CHOICE is its own refusal. Folding it into
            # "not resolved" would send an operator who named a backend off
            # to fix the scope rules, when the fix is to that one row (or to
            # the choice itself).
            plan.blockers.append(Blocker(
                "ipam_backend_rejected",
                f"the chosen IPAM backend cannot reserve this address: "
                f"{res.detail}"))
        elif not res.ok:
            # A pool no backend claims, or two claiming it equally. Reported
            # under its own code and NOT folded into "none configured": the
            # fix is different (scope a backend / break the tie) and an
            # operator told "none is configured" while three are would go
            # looking in the wrong place.
            plan.blockers.append(Blocker(
                "ipam_not_resolved",
                f"IPAM allocation was requested but {res.detail}"))
        else:
            plan.ipam_backend = res.backend.name
            plan.ipam_backend_id = res.backend.id
            caps = _dp.capabilities_of(res.backend)
            if caps is None:
                plan.blockers.append(Blocker(
                    "ipam_unreachable",
                    f"{res.backend.name} was chosen to reserve the address "
                    "but did not answer — unreachable or misconfigured"))
            elif not caps.can_allocate:
                plan.blockers.append(Blocker(
                    "ipam_cannot_allocate",
                    f"{res.backend.name} ({caps.label}) does not hand out "
                    "addresses"))
    elif not plan.address:
        plan.blockers.append(Blocker(
            "no_address", "no VIP address given and IPAM allocation was not "
                          "requested"))
    if plan.ipam_pick and not plan.use_ipam:
        # A control that silently does nothing reads as a control that worked.
        plan.warnings.append(
            "an IPAM backend was chosen but 'Reserve the VIP from IPAM' is "
            "off, so no address will be reserved from it")

    # -- DNS --------------------------------------------------------------
    # Same honesty rule as the provisioning DNS step (§130): a configured
    # backend that cannot write records, plus a requested hostname, is a
    # refusal — not a step that reports success and publishes nothing.
    if plan.hostname:
        from . import dns_providers as _dp
        res = _dp.choose("dns", plan.hostname, plan.dns_pick)
        if res.code == _dp.NO_BACKEND:
            # A fleet with no DDI at all is a supported install: a WARNING,
            # and the policy still gets built.
            plan.warnings.append(
                f"no backend carries the DNS role — {plan.hostname} will NOT "
                "be published; create the record by hand")
        elif plan.dns_pick and not res.ok:
            plan.blockers.append(Blocker(
                "dns_backend_rejected",
                f"the chosen DNS backend cannot publish {plan.hostname}: "
                f"{res.detail}"))
        elif not res.ok:
            # Backends EXIST and none of them covers this name (or two cover
            # it equally). That is a misconfiguration, not a deployment
            # choice, so it blocks — the operator asked for a name they
            # plainly expected to be published.
            plan.blockers.append(Blocker(
                "dns_not_resolved",
                f"the hostname {plan.hostname} cannot be published: "
                f"{res.detail}"))
        else:
            plan.dns_backend = res.backend.name
            plan.dns_backend_id = res.backend.id
            caps = _dp.capabilities_of(res.backend)
            if caps is None:
                plan.blockers.append(Blocker(
                    "dns_unreachable",
                    f"{res.backend.name} was chosen to publish "
                    f"{plan.hostname} but did not answer — unreachable or "
                    "misconfigured"))
            elif not caps.can_write:
                plan.blockers.append(Blocker(
                    "dns_cannot_write",
                    f"{res.backend.name} ({caps.label}) cannot create DNS "
                    f"records, but this policy asks for the hostname "
                    f"{plan.hostname}"))
    elif plan.dns_pick:
        plan.warnings.append(
            "a DNS backend was chosen but no hostname was given, so nothing "
            "will be published")

    # -- certificate ------------------------------------------------------
    plan.cert_class = lplan.cert_class or ""
    if plan.issue_cert:
        if not plan.cert_class:
            plan.blockers.append(Blocker(
                "no_cert_class", "a certificate was requested but this line "
                                 "does not declare a certificate class"))
        elif plan.cert_class not in store.CERT_CLASSES:
            plan.blockers.append(Blocker(
                "bad_cert_class",
                f"{plan.cert_class!r} is not a certificate class"))
        elif not store.cert_class_config(plan.cert_class).get("template"):
            plan.blockers.append(Blocker(
                "cert_class_unconfigured",
                f"certificate class {plan.cert_class!r} has no CA template "
                "configured (Settings -> Certificate Manager)"))

    # -- the Web Protection Profile --------------------------------------
    plan.wpp_template_id = lplan.wpp_template_id
    plan.wpp_template_name = lplan.wpp_template_name

    # -- backends ---------------------------------------------------------
    if plan.pool_mode == POOL_NEW:
        if not plan.backends:
            plan.blockers.append(Blocker(
                "no_backends", "a server pool with no members is a policy that "
                               "answers nothing — add at least one real server"))
    elif plan.pool_mode == POOL_EXISTING:
        if plan.backends:
            # A control that silently does nothing reads as a control that
            # worked. These rows are written NOWHERE when an existing pool is
            # bound: its members are whatever the device already holds.
            plan.warnings.append(
                f"the real servers listed are NOT used — this policy binds the "
                f"existing pool {plan.pool_name!r}, whose members are whatever "
                f"{getattr(appliance, 'name', 'the device')} already has")
    else:  # POOL_SHARED — the members ARE used, once, by the first plan
        plan.warnings.append(
            f"this policy binds {plan.pool_name!r}, created by the FIRST "
            "domain of this batch — the real servers are written once, not "
            "once per domain")

    # -- name collision, read from the LIVE device ------------------------
    _collision_check(appliance, plan)
    return plan


def _collision_check(appliance, plan: SpoPlan) -> None:
    """Refuse a name the device already has, before anything is created.

    Reading this costs one call and turns a half-built policy into a clean
    refusal. An unreachable device is itself a blocker: applying against a box
    we cannot read is how a run discovers at step four that step one was
    impossible.
    """
    from ..views.workspace import EP_POOL
    from .policy_ops import EP_POLICY
    want = (plan.names.get("server_policy") or "").strip()
    if not want:
        return
    try:
        client = appliance.build_client(timeout=15.0)
        names = set(client.cmdb_names(EP_POLICY) or [])
        # Read in the SAME probe, against the SAME device. "bind one that
        # exists" and "create one that does not" fail in opposite directions,
        # and both would otherwise fail at the object step — after the address
        # was reserved, the record published and the certificate issued.
        pools = set(client.cmdb_names(EP_POOL) or [])
    except Exception as exc:  # noqa: BLE001 — a probe must not 500 the page
        plan.blockers.append(Blocker(
            "device_unreachable",
            f"cannot read the existing policies to check for a name clash: "
            f"{type(exc).__name__}: {exc}"))
        return
    if plan.pool_mode == POOL_EXISTING and plan.pool_name not in pools:
        plan.blockers.append(Blocker(
            "pool_not_on_device",
            f"no server pool named {plan.pool_name!r} exists on "
            f"{getattr(appliance, 'name', 'this device')} — a server pool is "
            "a per-device object, so one that lives on another appliance "
            "cannot be bound; copy its members into a new pool instead"))
    elif plan.pool_mode == POOL_NEW and plan.pool_name in pools:
        plan.blockers.append(Blocker(
            "pool_exists",
            f"a server pool named {plan.pool_name!r} already exists on "
            f"{getattr(appliance, 'name', 'this device')} — bind it instead "
            "of creating a second one with the same name"))
    if want in names:
        plan.blockers.append(Blocker(
            "policy_exists",
            f"a server policy named {want!r} already exists on "
            f"{getattr(appliance, 'name', 'this device')}"))


# --------------------------------------------------------------------------- #
#  apply                                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class RunStep:
    key: str
    label: str
    ok: bool = True
    detail: str = ""

    def as_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "ok": self.ok,
                "detail": self.detail}


def apply_plan(appliance, plan: SpoPlan, *, dry_run: bool = True,
               actor: str = "") -> dict:
    """Execute the plan. ``dry_run`` (the default) writes nothing, anywhere.

    Returns ``{ok, dry_run, steps, compensated, stranded}``. ``stranded`` names
    anything a failure left behind that this module deliberately does not undo.
    """
    steps: list[RunStep] = []
    stranded: list[str] = []
    compensated: list[str] = []
    # Recorded facts — the ONLY things compensation acts on.
    took_address = ""
    address_ref = ""
    address_backend = None
    dns_record_id = ""
    dns_backend = None

    if not plan.ok:
        # A blocked plan is never applied, dry-run or not. Letting apply run
        # "just to see" is how a blocker becomes advisory.
        return {"ok": False, "dry_run": dry_run, "steps": [],
                "error": "this plan is blocked: "
                         + "; ".join(b.detail for b in plan.blockers),
                "compensated": [], "stranded": []}

    from . import dns_providers

    #: Things a failure leaves behind ON PURPOSE. Appended as they come into
    #: existence, so ``fail`` reports them without needing to know the order
    #: steps ran in.
    keep_notes: list[str] = []

    def fail(msg: str) -> dict:
        stranded.extend(keep_notes)
        # Compensate in reverse, guarded by recorded facts only.
        if dns_record_id:
            try:
                dns_providers.delete_record(dns_record_id, name=plan.hostname,
                                            rtype="A", backend_id=dns_backend)
                compensated.append(f"removed the DNS record for {plan.hostname}")
            except Exception as exc:  # noqa: BLE001
                stranded.append(f"DNS record {plan.hostname} could not be "
                                f"removed: {exc}")
        if took_address:
            try:
                dns_providers.release_address(took_address, ref=address_ref,
                                              backend_id=address_backend,
                                              pool=plan.pool)
                compensated.append(f"released {took_address}")
            except Exception as exc:  # noqa: BLE001
                stranded.append(f"address {took_address} could not be "
                                f"released: {exc}")
        return {"ok": False, "dry_run": dry_run,
                "steps": [s.as_dict() for s in steps], "error": msg,
                "compensated": compensated, "stranded": stranded}

    # -- 1. address -------------------------------------------------------
    vip = plan.address
    if plan.use_ipam:
        if dry_run:
            steps.append(RunStep(STEP_ADDRESS, "Reserve an address",
                                 detail=f"would take the next free address "
                                        f"from {plan.pool}"))
            vip = vip or "<allocated at apply>"
        else:
            try:
                addr = dns_providers.allocate_address(
                    hostname=plan.hostname or plan.web_address, pool=plan.pool,
                    backend_id=plan.ipam_backend_id)
            except Exception as exc:  # noqa: BLE001
                steps.append(RunStep(STEP_ADDRESS, "Reserve an address",
                                     ok=False, detail=str(exc)))
                return fail(f"IPAM refused to allocate: {exc}")
            vip = addr.address
            took_address, address_ref = addr.address, addr.ref
            address_backend = addr.backend_id
            steps.append(RunStep(STEP_ADDRESS, "Reserve an address",
                                 detail=f"{addr.address} from "
                                        f"{addr.pool or plan.pool}"))
    else:
        steps.append(RunStep(STEP_ADDRESS, "Address",
                             detail=f"using the supplied {vip}"))

    # -- 2. DNS -----------------------------------------------------------
    if plan.hostname:
        # ONLY the "no DDI anywhere" case is a pass here. Every other refusal
        # (no backend claims this name, two claim it equally, the chosen one
        # cannot write) was already turned into a BLOCKER in build_plan, and a
        # blocked plan is never applied — so reaching this point with an
        # unresolvable name is not possible without also having bypassed the
        # blocker, which apply_plan refuses to do.
        # NOT resolved again here. ``build_plan`` already chose, honouring
        # the operator's pick, and recorded the row id; resolving a second
        # time could answer differently (the registry is editable between the
        # preview and the press) and would write to a backend the summary
        # never named. ``None`` therefore means exactly one thing: no backend
        # carried the DNS role when the plan was built.
        if plan.dns_backend_id is None:
            # Said plainly, and it is NOT recorded as a creation.
            steps.append(RunStep(
                STEP_DNS, "Publish the hostname",
                detail=f"NO DNS BACKEND IS CONFIGURED — no record was created "
                       f"for {plan.hostname}; publish {plan.hostname} A {vip} "
                       "by hand"))
        elif dry_run:
            steps.append(RunStep(
                STEP_DNS, "Publish the hostname",
                detail=f"would create {plan.hostname} A {vip}"
                       + (f" via {plan.dns_backend}" if plan.dns_backend
                          else "")))
        else:
            try:
                rec = dns_providers.create_record(
                    name=plan.hostname, rtype="A", value=vip,
                    backend_id=plan.dns_backend_id)
                dns_record_id = str(rec.id or "")
                dns_backend = rec.backend_id
                steps.append(RunStep(STEP_DNS, "Publish the hostname",
                                     detail=f"created {plan.hostname} A {vip}"))
            except Exception as exc:  # noqa: BLE001
                steps.append(RunStep(STEP_DNS, "Publish the hostname",
                                     ok=False, detail=str(exc)))
                return fail(f"DNS provider refused the record: {exc}")

    # -- 3. certificate ---------------------------------------------------
    if plan.issue_cert:
        if dry_run:
            steps.append(RunStep(
                STEP_CERT, "Issue the certificate",
                detail=f"would issue a {plan.cert_class} certificate for "
                       f"CN={plan.hostname or plan.web_address}"))
        else:
            from . import cert_manager
            res = cert_manager.create_certificate(
                appliance, plan.hostname or plan.web_address, plan.cert_class,
                deploy=True, actor=actor)
            if not res.get("ok"):
                steps.append(RunStep(STEP_CERT, "Issue the certificate",
                                     ok=False, detail=res.get("error", "")))
                return fail(f"certificate issuance failed: {res.get('error')}")
            steps.append(RunStep(STEP_CERT, "Issue the certificate",
                                 detail=f"issued {res.get('name')}"))
            # Deliberately NOT compensated on a later failure — see the module
            # docstring. Named so the operator can decide.
            keep_notes.append(
                f"certificate {res.get('name')} was issued and is NOT revoked "
                "automatically")

    # -- 4. the device objects -------------------------------------------
    payload = object_payload(plan, vip)
    if dry_run:
        steps.append(RunStep(STEP_OBJECTS, "Create the policy objects",
                             detail=f"{len(payload['steps'])} objects: "
                                    + ", ".join(s[0] for s in payload["steps"])))
        return {"ok": True, "dry_run": True,
                "steps": [s.as_dict() for s in steps],
                "objects": [{"label": l, "endpoint": ep, "body": {"data": b}}
                            for l, ep, b, _ in payload["steps"]],
                "compensated": [], "stranded": []}

    from .fortiweb_ops import FortiWebOps
    ops = FortiWebOps(appliance)
    made: list[str] = []
    for label, ep, body, child_of in payload["steps"]:
        full = ep
        if child_of:
            from urllib.parse import quote
            full = "%s%smkey=%s" % (ep, "&" if "?" in ep else "?",
                                    quote(child_of, safe=""))
        res = ops.create(full, {"data": body}, dry_run=False)
        if not res.ok:
            steps.append(RunStep(STEP_OBJECTS, label, ok=False,
                                 detail=res.get("error", "")))
            # Objects already written to the device are named, not deleted:
            # deleting a policy object a human may already have bound
            # elsewhere is a destructive guess.
            if made:
                stranded.append("already created on the device: "
                                + ", ".join(made))
            return fail(f"{label} failed: {res.get('error', '')}")
        made.append(label)
    steps.append(RunStep(STEP_OBJECTS, "Create the policy objects",
                         detail=", ".join(made)))
    return {"ok": True, "dry_run": False,
            "steps": [s.as_dict() for s in steps],
            "compensated": [], "stranded": stranded}


def object_payload(plan: SpoPlan, vip: str) -> dict:
    """The ordered device writes, built from the plan.

    Endpoints come from ``views.workspace._CREATE_EPS`` rather than a second
    copy: two lists of FortiWeb endpoints is two things to keep correct.
    """
    from ..views.workspace import _CREATE_EPS
    n = plan.names
    vserver = n["virtual_server"]
    # The PLAN decides the pool, not the naming scheme: an existing or a
    # shared pool carries a name nobody derived from this web address.
    pool = plan.pool_name or n["server_pool"]
    seg = plan.segment or {}
    steps: list[tuple] = [
        ("Virtual Server", _CREATE_EPS["vserver"], {"name": vserver}, None),
        ("VIP", _CREATE_EPS["vip"],
         {"name": n["vip"], "vip": vip,
          "interface": seg.get("interface") or ""}, vserver),
    ]
    # ONLY a "new" pool is created. Re-creating one that already exists fails
    # on the device; re-creating a SHARED one races the sibling plan that owns
    # it and duplicates its members.
    if plan.pool_mode == POOL_NEW:
        steps.append(("Server Pool", _CREATE_EPS["pool"], {"name": pool}, None))
        for i, b in enumerate(plan.backends, 1):
            steps.append((f"Pool member {i}", _CREATE_EPS["pserver"],
                          {"ip": str(b.get("ip") or ""),
                           "port": str(b.get("port") or "80")}, pool))
    policy = {"name": n["server_policy"], "vserver": vserver,
              "server-pool": pool}
    if plan.wpp_template_name:
        policy["web-protection-profile"] = plan.wpp_template_name
    steps.append(("Server Policy", _CREATE_EPS["policy"], policy, None))
    return {"steps": steps}


# --------------------------------------------------------------------------- #
#  batch — several web addresses, ONE server pool                              #
# --------------------------------------------------------------------------- #
def build_batch(appliance, *, rows, existing_pool: str = "",
                pool_mode: str = POOL_NEW, pool_from: str = "",
                **common) -> list[SpoPlan]:
    """One plan per web address, all binding the SAME server pool.

    That single pool is the whole point: "several policies with the same
    backend" is one pool with N policies bound to it, not N identical pools
    that then drift apart the first time somebody edits one of them.

    Which pool it is:

    * ``pool_mode=POOL_EXISTING`` — every plan binds ``existing_pool``,
      nothing is created. The mode is passed EXPLICITLY and not inferred from
      a non-empty name: "the operator asked for an existing pool and named
      none" is a refusal (``no_pool_name``), and inferring the mode from the
      name would silently turn it into "build a new one" — a different pool
      from the one they were looking at;
    * otherwise the FIRST row's derived pool — row 1 creates it
      (``POOL_NEW``), every later row binds it (``POOL_SHARED``).

    Order is therefore load-bearing, not cosmetic: the creator has to run
    first. It is returned first and :func:`apply_batch` preserves the order.
    """
    rows = [r for r in (rows or [])
            if str((r or {}).get("web_address") or "").strip()]
    plans: list[SpoPlan] = []
    if not rows:
        return plans

    shared = (existing_pool or "").strip()
    # A bare ``existing_pool`` with no mode still means "existing": that is
    # what every caller written before the mode existed sends.
    want_existing = pool_mode == POOL_EXISTING or bool(shared)
    seen_web: dict[str, int] = {}
    seen_policy: dict[str, int] = {}
    seen_addr: dict[str, int] = {}

    for i, row in enumerate(rows):
        web = str(row.get("web_address") or "").strip()
        if want_existing:
            mode, name = POOL_EXISTING, shared
        elif not plans:
            mode, name = POOL_NEW, ""
        else:
            mode, name = POOL_SHARED, plans[0].pool_name
        plan = build_plan(appliance, web_address=web,
                          hostname=str(row.get("hostname") or ""),
                          address=str(row.get("address") or ""),
                          pool_name=name, pool_mode=mode,
                          pool_from=pool_from, **common)

        # -- rows that collide with each other ----------------------------
        # Checked HERE and not only against the device: two rows of the same
        # batch clash before either exists, so the live name check cannot see
        # it. It would surface as "the second one failed" halfway through a
        # run that had already published DNS for the first.
        key = web.lower()
        if key in seen_web:
            plan.blockers.append(Blocker(
                "duplicate_web_address",
                f"{web} is already row {seen_web[key] + 1} of this batch"))
        else:
            seen_web[key] = i

        policy_name = (plan.names.get("server_policy") or "").strip()
        if policy_name:
            if policy_name in seen_policy:
                plan.blockers.append(Blocker(
                    "duplicate_policy_name",
                    f"row {seen_policy[policy_name] + 1} derives the same "
                    f"policy name {policy_name!r} — two rows cannot build the "
                    "same object, even from different-looking addresses"))
            else:
                seen_policy[policy_name] = i

        addr = (plan.address or "").strip()
        if addr and not plan.use_ipam:
            if addr in seen_addr:
                # A WARNING and not a blocker: each row builds its own virtual
                # server, and whether this device accepts two VIP objects on
                # one address is a property of the device, not something this
                # module knows. Stating it is honest; refusing it would be a
                # guess dressed as a rule.
                plan.warnings.append(
                    f"row {seen_addr[addr] + 1} uses the same VIP {addr} — "
                    "each row builds its OWN virtual server, so the device "
                    "would get two VIP objects on one address")
            else:
                seen_addr[addr] = i

        plans.append(plan)
    return plans


def apply_batch(appliance, plans, *, dry_run: bool = True,
                actor: str = "") -> dict:
    """Run a batch in order. Refuses ENTIRELY if ANY plan is blocked.

    Not per-plan, and not "skip the bad ones": half a batch is the worst
    outcome available — a shared pool plus some of the policies, some DNS
    published, and no single place that says which domains are live. Every
    blocker in the batch is reported at once so they get fixed in one pass.

    Returns ``{ok, dry_run, runs, built}``. ``runs`` carries one entry per
    domain in the order they ran; ``built`` names the domains that completed.
    """
    plans = list(plans or [])
    if not plans:
        return {"ok": False, "dry_run": dry_run, "runs": [], "built": [],
                "error": "no web address was given"}

    blocked = [(p.web_address, b.detail) for p in plans for b in p.blockers]
    if blocked:
        return {"ok": False, "dry_run": dry_run, "runs": [], "built": [],
                "error": "this batch is blocked: "
                         + "; ".join("%s: %s" % (w or "(no address)", d)
                                     for w, d in blocked)}

    runs: list[dict] = []
    built: list[str] = []
    for plan in plans:
        res = apply_plan(appliance, plan, dry_run=dry_run, actor=actor)
        runs.append({"web_address": plan.web_address,
                     "pool_name": plan.pool_name,
                     "pool_mode": plan.pool_mode, "result": res})
        if not res.get("ok"):
            if built and not dry_run:
                # NAMED, never deleted. The earlier domains are real, working
                # policies; tearing them down because a LATER row failed would
                # destroy work nobody asked to undo — the same rule that keeps
                # a certificate from being revoked on a failed run.
                res.setdefault("stranded", []).append(
                    "already built and NOT undone: " + ", ".join(built))
            return {"ok": False, "dry_run": dry_run, "runs": runs,
                    "built": built,
                    "error": f"{plan.web_address}: "
                             f"{res.get('error') or 'failed'}"}
        built.append(plan.web_address)
    return {"ok": True, "dry_run": dry_run, "runs": runs, "built": built}
