#!/usr/bin/env bash
# =============================================================================
# run_test_shards.sh — run the SATOM pytest suite split across N parallel shards.
#
#   usage:  scripts/run_test_shards.sh [N]          # N = 1..4  (default 3)
#           DRY_RUN=1 scripts/run_test_shards.sh 3  # print the plan, launch nothing
#
#   Run it detached so an SSH drop cannot kill it:
#           nohup scripts/run_test_shards.sh 3 > /var/tmp/shard_suite.out 2>&1 &
#
# Why this is safe to parallelise: tests/conftest.py builds its temp root with
# tempfile.mkdtemp() at IMPORT time (one per pytest PROCESS) and the `app`
# fixture takes tmp_path (one sqlite DB per TEST). The SATOM_JOBS_DIR /
# SATOM_SOT_DIR / SATOM_TRUST_DIR / FORTINET_DIAG_DIR / FORTINET_REPORTS_DIR
# redirects all hang off that per-process root. Nothing global is shared, so
# the only things this script has to get right are the balancing and the
# bookkeeping.
#
# Splits are by FILE, never within a file, so any intra-file ordering
# dependency survives untouched.
#
# Measured on a 4 vCPU / 4 GB node: one pytest leaves 80-96% of the CPU idle
# at 1-3% iowait — the suite is serialised on syscall latency, not on CPU or
# disk throughput, which is exactly the profile that parallelises well.
# =============================================================================

set -u

# Derived from the script's own location, never from cwd — the same rule the
# offline-bundle builders follow, so this works from anywhere and in a checkout
# that is not /opt/satom.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SATOM_REPO_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"

# ${1-3}, not ${1:-3}: with :- an explicitly EMPTY argument silently
# becomes 3, which both hides a caller bug (an unset variable expanded
# into the argument list) and leaves the "must be an integer" branch
# below permanently dead code. Only a genuinely absent argument defaults.
SHARDS="${1-3}"
APP_USER="${SATOM_TEST_USER:-satom}"
WORK_DIR="${SATOM_SHARD_WORK_DIR:-/var/tmp/satom-shards}"
VENV_PY="${SATOM_VENV_PY:-$APP_DIR/venv/bin/python3}"
DRY_RUN="${DRY_RUN:-0}"

# Argument validation comes FIRST, before the privilege check: rejecting a
# nonsense shard count needs no privilege, and putting the root check ahead of
# it would make every unprivileged invocation exit 2 for the same reason —
# which is indistinguishable from "the argument was fine", including to a test.
case "$SHARDS" in
    ''|*[!0-9]*) echo "FATAL: shard count must be an integer, got '$SHARDS'" >&2; exit 2 ;;
esac
if [ "$SHARDS" -lt 1 ] || [ "$SHARDS" -gt 4 ]; then
    # 4 vCPU box. Measured Pss is ~97% of Rss, so there is no copy-on-write
    # discount: N shards cost N x full RSS. At 4 shards the worst case is
    # ~3.4 GB of 4 GB with a workload that writes ~10 GB — rc 137 territory.
    echo "FATAL: shard count must be 1..4 (4 vCPU box). Got $SHARDS." >&2
    exit 2
fi

# Must run as root: dropping to the app user is done with runuser, and runuser
# refuses to work for non-root callers. (DRY_RUN still needs it, because the
# manifest-readability preflight also uses runuser.)
if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: run this as root - it uses runuser to drop each shard to '$APP_USER'," >&2
    echo "       and runuser may not be used by non-root users." >&2
    exit 2
fi

[ -x "$VENV_PY" ] || { echo "FATAL: no python at $VENV_PY" >&2; exit 2; }

MANIFEST_DIR="${WORK_DIR}/n${SHARDS}"

# -----------------------------------------------------------------------------
# Guard: refuse to start if a pytest is already running.
#
# The self-match trap: a naive `pgrep -f pytest` matches (a) pgrep's own argv
# and (b) any shell in our own tree whose command line carries the word
# "pytest" — e.g. this script invoked from a wrapper. That has already produced
# a false "suite already running" abort on this node.
#
# Three defences, and all three are needed:
#   1. The bracket trick '[p]ytest'. The literal pattern text is "[p]ytest",
#      which the regex itself does not match.
#   2. Drop our own PID, our parent, and every PID sharing our process group —
#      those processes ARE this script, by definition.
#   3. is_real_pytest(): confirm the candidate really IS pytest by parsing its
#      argv, not by substring-matching it. Observed LIVE on this node: pgrep
#      happily returned the PID of a shell whose command line merely contained
#      the WORD pytest (an echo, a comment, a log path). The bracket trick only
#      stops the pattern from matching itself; it does nothing about third
#      parties who legitimately mention the word.
#
# The guard deliberately CAN still see shards launched by a previous invocation
# of this script: setsid puts each shard in a fresh session/process group, so
# rule 2 does not shield them. Running this script twice concurrently is
# exactly what must be blocked — two suites contend and invalidate both.
# -----------------------------------------------------------------------------
MYPID=$$
MYPGID="$(ps -o pgid= -p "$MYPID" 2>/dev/null | tr -d ' ')"

is_real_pytest() {
    local pid="$1"
    local -a argv=()
    mapfile -t -d '' argv < "/proc/${pid}/cmdline" 2>/dev/null || return 1
    [ "${#argv[@]}" -gt 0 ] || return 1
    case "${argv[0]##*/}" in
        pytest|py.test) return 0 ;;
    esac
    local i
    for (( i = 0; i < ${#argv[@]} - 1; i++ )); do
        if [ "${argv[i]}" = "-m" ] && [ "${argv[i+1]}" = "pytest" ]; then
            return 0
        fi
    done
    return 1
}

foreign_pytest_pids() {
    local pid pgid
    for pid in $(pgrep -f -- '[p]ytest' 2>/dev/null); do
        [ "$pid" = "$MYPID" ]  && continue
        [ "$pid" = "$PPID" ]   && continue
        pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')"
        [ -n "$pgid" ] && [ "$pgid" = "$MYPGID" ] && continue
        is_real_pytest "$pid" || continue
        printf '%s\n' "$pid"
    done
}

# DRY_RUN launches nothing, so it neither needs the guard nor may it truncate
# the logs of a run that is currently in flight. It is deliberately safe to
# invoke while the suite is busy — that is the point of having it.
BUSY="$(foreign_pytest_pids)"
if [ "$DRY_RUN" = "1" ]; then
    if [ -n "$BUSY" ]; then
        # shellcheck disable=SC2086
        echo "[dry-run] guard WOULD BLOCK - foreign pytest pid(s):" $BUSY
    else
        echo "[dry-run] guard clear - no foreign pytest is running"
    fi
else
    if [ -n "$BUSY" ]; then
        echo "FATAL: pytest is already running on this node - refusing to start." >&2
        echo "       a second suite contends for CPU/disk and invalidates BOTH runs." >&2
        # shellcheck disable=SC2086
        ps -o pid,etime,rss,args -p $(echo "$BUSY" | tr '\n' ',' | sed 's/,$//') >&2
        exit 3
    fi

    # -------------------------------------------------------------------------
    # Preflight: every log must be creatable BY the app user. If a root-owned
    # shard log is left over from an earlier run, that user cannot truncate it
    # (/var/tmp is sticky, mode 1777, so it cannot unlink it either) — the
    # redirect would fail and bash would exit 1, which we would then misreport
    # as "tests failed". Catch it here, where the message is honest.
    # -------------------------------------------------------------------------
    for i in $(seq 1 "$SHARDS"); do
        LOG="${WORK_DIR}/shard${i}.log"
        if ! runuser -u "$APP_USER" -- /bin/bash -c ': > "$1"' _ "$LOG" 2>/dev/null; then
            echo "FATAL: user '$APP_USER' cannot write $LOG" >&2
            ls -l "$LOG" >&2 2>/dev/null
            echo "       remove it as root, then re-run: rm -f $LOG" >&2
            exit 2
        fi
    done
fi

# -----------------------------------------------------------------------------
# Plan: (re)build the manifests unless they already exist. Generated as the app
# user so nothing root-owned lands in the work dir.
# -----------------------------------------------------------------------------
install -d -o "$APP_USER" -g "$APP_USER" -m 755 "$WORK_DIR" || exit 2
if [ ! -s "${MANIFEST_DIR}/shard${SHARDS}.txt" ]; then
    echo "planning ${SHARDS} shard(s) -> ${MANIFEST_DIR}"
    runuser -u "$APP_USER" -- "$VENV_PY" "$SCRIPT_DIR/test_shard_plan.py" \
        -n "$SHARDS" --tests-dir "$APP_DIR/tests" --out "$MANIFEST_DIR" || exit 2
    echo
fi

for i in $(seq 1 "$SHARDS"); do
    M="${MANIFEST_DIR}/shard${i}.txt"
    if ! runuser -u "$APP_USER" -- /bin/bash -c '[ -r "$1" ] && [ -s "$1" ]' _ "$M"; then
        echo "FATAL: manifest $M is missing, empty, or unreadable by $APP_USER" >&2
        exit 2
    fi
done

# -----------------------------------------------------------------------------
# Launch
# -----------------------------------------------------------------------------
echo "=========================================================="
echo " SATOM sharded suite - $SHARDS shard(s)"
echo " repo      : $APP_DIR"
echo " manifests : $MANIFEST_DIR"
echo " started   : $(date -Is)"
echo "=========================================================="
for i in $(seq 1 "$SHARDS"); do
    printf '  shard%d: %4d files  ->  %s/shard%d.log\n' \
        "$i" "$(wc -l < "${MANIFEST_DIR}/shard${i}.txt")" "$WORK_DIR" "$i"
done
echo

# pytest flags, and why each one is here:
#
#   -p no:warnings   matches how the reference single-process suite is invoked,
#                    so the sharded numbers stay comparable to that baseline.
#   -q               same reason.
#   --durations=0    reports the wall time of EVERY test. This is what lets the
#                    NEXT run be balanced on measured seconds instead of the
#                    static AST proxy, which counts tests rather than time and
#                    is blind to sleeps, retry/backoff loops and fsync churn.
#                    Feed the logs back: test_shard_plan.py --durations ...
#   -p no:cacheprovider
#                    parallel shards would otherwise all write the same
#                    <repo>/.pytest_cache (lastfailed, nodeids) and race. It
#                    also keeps the run from writing anything into the repo.
#                    Verified safe: no test uses the `cache` fixture and
#                    nothing passes --lf/--ff.
PYTEST_FLAGS=(-p no:warnings -p no:cacheprovider -q --durations=0)

declare -a SHARD_PID
declare -a SHARD_RC

for i in $(seq 1 "$SHARDS"); do
    MANIFEST="${MANIFEST_DIR}/shard${i}.txt"
    LOG="${WORK_DIR}/shard${i}.log"

    if [ "$DRY_RUN" = "1" ]; then
        echo "[dry-run] shard$i: runuser -u $APP_USER -- $VENV_PY -m pytest ${PYTEST_FLAGS[*]} \$(< $MANIFEST)  > $LOG"
        continue
    fi

    # setsid -w : each shard gets its own session (survives a hangup on the
    #             controlling terminal) but setsid still WAITS and propagates
    #             the child's exit status, so `wait` below sees the real pytest
    #             return code rather than setsid's.
    # The redirect happens INSIDE the runuser payload, so the log file is
    # created by the app user, not by root. Root-owned scratch is a documented
    # incident on this node.
    setsid -w runuser -u "$APP_USER" -- /bin/bash -c '
        exec > "$2" 2>&1
        cd "$3" || exit 4
        mapfile -t FILES < "$1"
        [ "${#FILES[@]}" -gt 0 ] || exit 5
        echo "### shard manifest: $1  (${#FILES[@]} files)"
        echo "### started: $(date -Is)"
        shift 3
        exec "$@" "${FILES[@]}"
    ' _ "$MANIFEST" "$LOG" "$APP_DIR" "$VENV_PY" -m pytest "${PYTEST_FLAGS[@]}" &

    SHARD_PID[$i]=$!
    echo "launched shard$i  (wrapper pid ${SHARD_PID[$i]})"
done

if [ "$DRY_RUN" = "1" ]; then
    echo
    echo "[dry-run] nothing launched."
    exit 0
fi

START="$(date +%s)"
echo
echo "waiting for $SHARDS shard(s)..."

for i in $(seq 1 "$SHARDS"); do
    wait "${SHARD_PID[$i]}"
    SHARD_RC[$i]=$?
done

ELAPSED=$(( $(date +%s) - START ))

# -----------------------------------------------------------------------------
# Aggregate result — from EXIT CODES, never from grepping the log text.
# Grepping for "passed"/"failed" is unreliable: -q output can be truncated, a
# crashed shard prints no summary line at all, and "0 failed" appears inside
# perfectly failing output. The exit code is the only authoritative signal.
#
# pytest exit codes:
#   0 all collected tests passed
#   1 tests were collected and run, some FAILED
#   2 interrupted (Ctrl-C / KeyboardInterrupt)
#   3 internal error
#   4 pytest USAGE ERROR  -> an error, NOT a pass
#   5 NO TESTS COLLECTED  -> an error, NOT a pass (a shard ran nothing: bad
#                            manifest, renamed files, broken collection)
#   anything else: killed by a signal (128+n), OOM killer, etc.
# -----------------------------------------------------------------------------
rc_label() {
    case "$1" in
        0) echo "PASS          all tests passed" ;;
        1) echo "FAIL          tests failed" ;;
        2) echo "ERROR         interrupted" ;;
        3) echo "ERROR         pytest internal error" ;;
        4) echo "ERROR         pytest usage error (bad args/manifest)" ;;
        5) echo "ERROR         no tests collected" ;;
        137) echo "ERROR         killed (SIGKILL - suspect the OOM killer)" ;;
        *) echo "ERROR         unexpected exit code" ;;
    esac
}

OVERALL=0
echo
echo "=========================================================="
echo " SATOM sharded suite - results"
echo " finished : $(date -Is)"
printf ' wall     : %dm %02ds\n' $(( ELAPSED / 60 )) $(( ELAPSED % 60 ))
echo "----------------------------------------------------------"
for i in $(seq 1 "$SHARDS"); do
    rc="${SHARD_RC[$i]}"
    printf ' shard%-2d  rc=%-4d %s\n' "$i" "$rc" "$(rc_label "$rc")"
    [ "$rc" -ne 0 ] && OVERALL=1
done
echo "----------------------------------------------------------"
if [ "$OVERALL" -eq 0 ]; then
    echo " AGGREGATE: PASS  ($SHARDS/$SHARDS shards exited 0)"
else
    BAD=0
    for i in $(seq 1 "$SHARDS"); do
        [ "${SHARD_RC[$i]}" -ne 0 ] && BAD=$(( BAD + 1 ))
    done
    echo " AGGREGATE: FAIL  ($BAD/$SHARDS shards did not exit 0)"
    echo " logs: ${WORK_DIR}/shard1.log .. ${WORK_DIR}/shard${SHARDS}.log"
fi
echo "=========================================================="
echo
echo "Next run: rebalance on measured time, not on the AST proxy -"
echo "  $SCRIPT_DIR/test_shard_plan.py -n $SHARDS --durations ${WORK_DIR}/shard*.log"

exit "$OVERALL"
