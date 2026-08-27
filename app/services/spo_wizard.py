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
    pool: str = ""
    use_ipam: bool = False
    address: str = ""                 # operator-supplied when not using IPAM
    cert_class: str = ""
    issue_cert: bool = False
    wpp_template_id: int | None = None
    wpp_template_name: str = ""
    backends: list = field(default_factory=list)
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
            "names": self.names, "segment": self.segment, "pool": self.pool,
            "use_ipam": self.use_ipam, "address": self.address,
            "cert_class": self.cert_class, "issue_cert": self.issue_cert,
            "wpp_template_id": self.wpp_template_id,
            "wpp_template_name": self.wpp_template_name,
            "backends": self.backends, "ok": self.ok,
            "blockers": [b.as_dict() for b in self.blockers],
            "warnings": list(self.warnings),
        }


# --------------------------------------------------------------------------- #
#  plan — pure inspection                                                      #
# --------------------------------------------------------------------------- #
def build_plan(appliance, *, line: str, web_address: str,
               segment_name: str = "", hostname: str = "",
               use_ipam: bool = False, address: str = "",
               issue_cert: bool = False, backends=None,
               product: str = "") -> SpoPlan:
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
    available = {(s.get("name") or ""): s for s in lplan.segments}
    if segment_name:
        seg = available.get(segment_name)
        if seg is None:
            plan.blockers.append(Blocker(
                "segment_not_on_line",
                f"segment {segment_name!r} is not one of the segments line "
                f"{plan.line!r} receives ({', '.join(sorted(available)) or 'none'})"))
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
        caps = _dns_caps()
        if caps is None:
            plan.blockers.append(Blocker(
                "no_ipam_provider", "IPAM allocation was requested but no "
                                    "DNS/IPAM provider is configured"))
        elif not caps.can_allocate:
            plan.blockers.append(Blocker(
                "ipam_cannot_allocate",
                f"{caps.label} does not hand out addresses"))
    elif not plan.address:
        plan.blockers.append(Blocker(
            "no_address", "no VIP address given and IPAM allocation was not "
                          "requested"))

    # -- DNS --------------------------------------------------------------
    # Same honesty rule as the provisioning DNS step (§130): a configured
    # backend that cannot write records, plus a requested hostname, is a
    # refusal — not a step that reports success and publishes nothing.
    if plan.hostname:
        caps = _dns_caps()
        if caps is None:
            plan.warnings.append(
                f"no DNS provider is configured — {plan.hostname} will NOT be "
                "published; create the record by hand")
        elif not caps.can_write:
            plan.blockers.append(Blocker(
                "dns_cannot_write",
                f"{caps.label} cannot create DNS records, but this policy asks "
                f"for the hostname {plan.hostname}"))

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
    if not plan.backends:
        plan.blockers.append(Blocker(
            "no_backends", "a server pool with no members is a policy that "
                           "answers nothing — add at least one real server"))

    # -- name collision, read from the LIVE device ------------------------
    _collision_check(appliance, plan)
    return plan


def _dns_caps():
    from . import dns_providers
    return dns_providers.capabilities()


def _collision_check(appliance, plan: SpoPlan) -> None:
    """Refuse a name the device already has, before anything is created.

    Reading this costs one call and turns a half-built policy into a clean
    refusal. An unreachable device is itself a blocker: applying against a box
    we cannot read is how a run discovers at step four that step one was
    impossible.
    """
    from .policy_ops import EP_POLICY
    want = (plan.names.get("server_policy") or "").strip()
    if not want:
        return
    try:
        names = set(appliance.build_client(timeout=15.0)
                    .cmdb_names(EP_POLICY) or [])
    except Exception as exc:  # noqa: BLE001 — a probe must not 500 the page
        plan.blockers.append(Blocker(
            "device_unreachable",
            f"cannot read the existing policies to check for a name clash: "
            f"{type(exc).__name__}: {exc}"))
        return
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
    dns_record_id = ""

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
                                            rtype="A")
                compensated.append(f"removed the DNS record for {plan.hostname}")
            except Exception as exc:  # noqa: BLE001
                stranded.append(f"DNS record {plan.hostname} could not be "
                                f"removed: {exc}")
        if took_address:
            try:
                dns_providers.release_address(took_address, ref=address_ref)
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
                    hostname=plan.hostname or plan.web_address, pool=plan.pool)
            except Exception as exc:  # noqa: BLE001
                steps.append(RunStep(STEP_ADDRESS, "Reserve an address",
                                     ok=False, detail=str(exc)))
                return fail(f"IPAM refused to allocate: {exc}")
            vip = addr.address
            took_address, address_ref = addr.address, addr.ref
            steps.append(RunStep(STEP_ADDRESS, "Reserve an address",
                                 detail=f"{addr.address} from "
                                        f"{addr.pool or plan.pool}"))
    else:
        steps.append(RunStep(STEP_ADDRESS, "Address",
                             detail=f"using the supplied {vip}"))

    # -- 2. DNS -----------------------------------------------------------
    if plan.hostname:
        caps = dns_providers.capabilities()
        if caps is None:
            # Said plainly, and it is NOT recorded as a creation.
            steps.append(RunStep(
                STEP_DNS, "Publish the hostname",
                detail=f"NO DNS PROVIDER IS CONFIGURED — no record was created "
                       f"for {plan.hostname}; publish {plan.hostname} A {vip} "
                       "by hand"))
        elif dry_run:
            steps.append(RunStep(STEP_DNS, "Publish the hostname",
                                 detail=f"would create {plan.hostname} A {vip}"))
        else:
            try:
                rec = dns_providers.create_record(
                    name=plan.hostname, rtype="A", value=vip)
                dns_record_id = str(rec.id or "")
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
    pool = n["server_pool"]
    seg = plan.segment or {}
    steps: list[tuple] = [
        ("Virtual Server", _CREATE_EPS["vserver"], {"name": vserver}, None),
        ("VIP", _CREATE_EPS["vip"],
         {"name": n["vip"], "vip": vip,
          "interface": seg.get("interface") or ""}, vserver),
        ("Server Pool", _CREATE_EPS["pool"], {"name": pool}, None),
    ]
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
