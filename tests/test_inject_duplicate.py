"""Guards for how an injected carve-out reports FortiWeb's ``-5`` duplicate.

What went wrong (fortiweb08, 2026-08-08). ``apply_injection`` writes in two
steps — create the named container, then create the row — and reported
``ok = all(steps)``. The container step POSTed unconditionally even though its
checkbox says "create the container if it does not exist", so on a box where
``am-exc`` already existed it ALWAYS came back ``errcode -5``. That dragged
down a result whose second step had genuinely just written the exception, and
the operator was shown "The appliance rejected the write" for a carve-out that
was live. They pressed the button again — and the second attempt's ``-5`` on
the ENTRY step, the honest one, looked identical to the first.

So there are two distinct things to get right, and neither is cosmetic:

* a ``-5`` means "already there", which is the DESIRED state, not a refusal;
* "already there" must still be told apart from "I wrote it", or the operator
  cannot tell an idempotent retry from a real change.
"""
from app.services import exception_inject as inj


class Res(dict):
    @property
    def ok(self):
        return bool(self.get("ok"))


def _err(code, msg="A duplicate entry has already existed.", http=None):
    text = ("HTTP %s — errcode %s: %s" % (http, code, msg) if http
            else "errcode %s: %s" % (code, msg))
    return Res(ok=False, error=text, request={"method": "POST"})


def _ok():
    return Res(ok=True, error="", request={"method": "POST"})


# --------------------------------------------------------------------------- #
#  errcode parsing                                                              #
# --------------------------------------------------------------------------- #
def test_errcode_is_parsed_from_both_renderings():
    """``fortiweb_ops`` renders a logical error one way and an HTTP-500 error
    another; both have to reduce to the same code."""
    assert inj.errcode_of("errcode -5: A duplicate entry has already existed.") == "-5"
    assert inj.errcode_of("HTTP 500 — errcode -5: A duplicate entry has "
                          "already existed.") == "-5"
    assert inj.errcode_of("errcode -56: Empty value isn't allowed.") == "-56"
    assert inj.errcode_of("") == ""
    assert inj.errcode_of(None) == ""


def test_duplicate_is_matched_on_the_code_not_the_sentence():
    """The message is the localisable half of the answer."""
    assert inj.is_duplicate(_err("-5", msg="")) is True
    assert inj.is_duplicate(_err("-5", msg="Ya existe una entrada duplicada.")) is True
    assert inj.is_duplicate(_err("-56")) is False
    assert inj.is_duplicate(Res(ok=False, error="A duplicate entry has already "
                                                "existed.")) is False


def test_a_successful_write_is_never_a_duplicate():
    assert inj.is_duplicate(_ok()) is False


# --------------------------------------------------------------------------- #
#  Fake ops                                                                     #
# --------------------------------------------------------------------------- #
class FakeOps:
    """Records every write and answers with scripted results."""

    def __init__(self, *, container=None, entry=None, exists=None):
        self.calls = []
        self._container = container
        self._entry = entry
        self._exists = exists

    class _Client:
        def __init__(self, outer):
            self.outer = outer

        def get(self, path):
            self.outer.calls.append(("GET", path))
            if self.outer._exists is None:
                raise RuntimeError("device unreachable")

            class R:
                def __init__(self, payload):
                    self._p = payload

                def json(self):
                    return self._p
            return R({"results": [{"name": "am-exc"}] if self.outer._exists else []})

    @property
    def client(self):
        return FakeOps._Client(self)

    def create(self, endpoint, data, *, mkey=None, dry_run=True):
        self.calls.append(("POST", endpoint, dry_run))
        if "exception-list" in endpoint or "?" in endpoint:
            return self._entry or _ok()
        return self._container or _ok()

    def update(self, endpoint, mkey, data, *, dry_run=True, sub_mkey=None):
        self.calls.append(("PUT", endpoint, dry_run))
        return self._entry or _ok()


_KW = dict(exc_type="allow_method_exception_item",
           payload={"allow-request": "get", "request-file": "/"},
           target="am-exc")


# --------------------------------------------------------------------------- #
#  The reported failure                                                         #
# --------------------------------------------------------------------------- #
def test_a_duplicate_container_does_not_sink_a_successful_entry():
    """THE bug: the entry landed and the operator was told it was rejected."""
    ops = FakeOps(container=_err("-5"), entry=_ok(), exists=False)
    res = inj.apply_injection(ops, dry_run=False, create_container=True, **_KW)
    assert res["ok"] is True
    container = next(s for s in res["steps"] if s["step"] == "container")
    assert container["ok"] is True and container["duplicate"] is True
    assert container["note"] == "already-present"
    assert res["already_present"] is False, "the ENTRY was newly written"


def test_an_existing_container_is_not_posted_at_all():
    """The checkbox says 'if it does not exist'. It POSTed regardless, which is
    why the ``-5`` was there to be misread in the first place."""
    ops = FakeOps(exists=True)
    res = inj.apply_injection(ops, dry_run=False, create_container=True, **_KW)
    posts = [c for c in ops.calls if c[0] == "POST"]
    assert len(posts) == 1, "only the entry should have been written"
    assert next(s for s in res["steps"] if s["step"] == "container")["note"] \
        == "already-present"


def test_an_unreadable_box_still_attempts_the_container():
    """Three states, not two: a read failure is not 'absent', but it is also not
    a reason to skip a create the operator asked for. Falling back to the POST
    keeps the old behaviour, and its ``-5`` is now harmless."""
    ops = FakeOps(container=_err("-5"), exists=None)   # GET raises
    res = inj.apply_injection(ops, dry_run=False, create_container=True, **_KW)
    assert len([c for c in ops.calls if c[0] == "POST"]) == 2
    assert res["ok"] is True


def test_a_duplicate_entry_is_reported_as_already_present_not_rejected():
    ops = FakeOps(entry=_err("-5"), exists=True)
    res = inj.apply_injection(ops, dry_run=False, create_container=True, **_KW)
    assert res["ok"] is True
    assert res["already_present"] is True, (
        "the caller has to be able to say 'nothing to do' — 'created' and "
        "'rejected' are both false here")


def test_a_real_rejection_is_still_a_failure():
    """The point is not to make errors disappear."""
    ops = FakeOps(entry=_err("-56", msg="Empty value isn't allowed."), exists=True)
    res = inj.apply_injection(ops, dry_run=False, create_container=True, **_KW)
    assert res["ok"] is False
    assert res["already_present"] is False
    assert next(s for s in res["steps"] if s["step"] == "entry")["duplicate"] is False


def test_dry_run_never_touches_the_device():
    """``FortiWebOps.preview`` is contractually device-free; a probe smuggled
    into the preview path would break that for every other caller."""
    ops = FakeOps(exists=True)
    inj.apply_injection(ops, dry_run=True, create_container=True, **_KW)
    assert not [c for c in ops.calls if c[0] == "GET"]


def test_a_plan_that_is_not_ready_writes_nothing():
    ops = FakeOps()
    res = inj.apply_injection(ops, exc_type="allow_method_exception_item",
                              payload={}, target="", dry_run=False,
                              create_container=True)
    assert res["ok"] is False and res["steps"] == [] and ops.calls == []
    assert res["already_present"] is False
