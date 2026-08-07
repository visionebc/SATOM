"""Flask application factory."""
from __future__ import annotations

import ipaddress
import os
from datetime import datetime

import click
from flask import Flask, g, request

from .config import get_config
from .extensions import csrf, db, limiter, login_manager, migrate


from .extensions import real_client_ip as _client_ip  # single source of truth


def _ip_allowed(ip: str, whitelist: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return True  # never lock out local/curl access
    for row in whitelist:
        try:
            if addr in ipaddress.ip_network((row or {}).get("ip", ""), strict=False):
                return True
        except ValueError:
            continue
    return False


def widen_plan(tables, live_widths):
    """Return [(table, column, want)] for VARCHAR columns narrower than the model.

    Pure so the decision can be tested with data instead of a live database.
    ``tables`` is SQLAlchemy metadata's sorted_tables; ``live_widths`` maps
    ``table -> {column: length_or_None}`` as reported by the database.

    Only ever widens.  Narrowing can truncate committed rows, so a model that
    shrinks is deliberately ignored — a schema that is wider than declared is
    harmless, a schema that is narrower than the data is not recoverable.
    A column absent from ``live_widths`` is left to :func:`_ensure_columns`;
    guessing here would emit DDL for a column that does not exist yet.
    """
    from sqlalchemy.types import String

    plan = []
    for table in tables:
        live = live_widths.get(table.name)
        if live is None:
            continue
        for col in table.columns:
            if not isinstance(col.type, String):
                continue
            want = getattr(col.type, 'length', None)
            if not want:
                continue
            have = live.get(col.name)
            if have is None or have >= want:
                continue
            plan.append((table.name, col.name, want))
    return plan


def create_app(config_override: object | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)

    # -- configuration ----------------------------------------------------
    app.config.from_object(get_config())
    if config_override is not None:
        app.config.from_object(config_override)

    # propagate FERNET_KEY into environment so models.py can pick it up
    if app.config.get("FERNET_KEY"):
        os.environ.setdefault("FERNET_KEY", app.config["FERNET_KEY"])

    # -- extensions -------------------------------------------------------
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id: str):
        from .models import User
        return User.query.get(int(user_id))

    # -- blueprints -------------------------------------------------------
    _register_blueprints(app)

    @app.route('/')
    def index():
        """The GLOBAL ADOM — fleet-wide dashboard spanning FortiWeb + FortiADC.
        Visiting '/' always enters Global (like FortiManager's Global ADOM)."""
        from flask import redirect, url_for, session
        from flask_login import current_user
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        session['product'] = 'global'
        session.permanent = True
        from .views.global_home import dashboard
        return dashboard()

    @app.route('/web/')
    def fortiweb_home():
        """FortiWeb ADOM entry — the old '/' fortiweb landing, now at /web/."""
        from flask import redirect, url_for, session
        from flask_login import current_user
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        session['product'] = 'fortiweb'
        session.permanent = True
        from .services import device_context
        if device_context.current_appliance() is not None:
            return redirect(url_for('workspace.index'))
        return redirect(url_for('architecture.index'))

    # -- service worker (root scope) — powers resilient background uploads
    #    (Background Fetch API): the transfer is owned by the browser, so it
    #    survives navigation / refresh / tab close. Served at '/' so its scope
    #    is the whole app; no auth (the script is not sensitive) and exempt from
    #    the product/access gates below so registration never gets a redirect.
    @app.route('/sw.js')
    def service_worker():
        from flask import Response
        sw_path = os.path.join(app.static_folder, 'js', 'sw.js')
        try:
            with open(sw_path, 'r', encoding='utf-8') as fh:
                body = fh.read()
        except OSError:
            return ('', 404)
        resp = Response(body, mimetype='application/javascript')
        resp.headers['Service-Worker-Allowed'] = '/'
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    # -- shared worker — owns firmware upload TRANSFERS so they survive a
    #    full-page navigation. A SharedWorker persists across same-origin page
    #    loads, so an XHR upload started inside it keeps going when the user
    #    changes page (unlike an in-page XHR, which the navigation aborts). It
    #    broadcasts progress to whatever page is open and answers a "query" so a
    #    freshly-loaded page reconnects to the in-flight transfer. Same-origin
    #    JS, gate-exempt like the service worker so it always loads.
    @app.route('/upload-worker.js')
    def upload_worker():
        from flask import Response
        w_path = os.path.join(app.static_folder, 'js', 'upload-worker.js')
        try:
            with open(w_path, 'r', encoding='utf-8') as fh:
                body = fh.read()
        except OSError:
            return ('', 404)
        resp = Response(body, mimetype='application/javascript')
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    # -- diagnostic breadcrumb sink (temporary). GET so it never trips CSRF;
    #    the page + upload worker ping it at each decision point so the server
    #    log shows EXACTLY which transfer path ran and whether it survived a
    #    navigation. Logs only (no storage), capped, gate-exempt.
    @app.route('/_updiag')
    def updiag():
        from flask import Response
        from flask_login import current_user
        try:
            if not current_user.is_authenticated:
                return Response('', status=204)  # never log unauthenticated input
            who = getattr(current_user, 'username', '') or '-'
            args = dict(request.args)
            app.logger.warning('UPDIAG user=%s ip=%s %s', who, _client_ip(),
                               str(args)[:400])
        except Exception:
            pass
        return Response('', status=204)

    # -- product selection gate ------------------------------------------
    # PER-TAB ADOM (2026-07-07): the ADOM a request runs in is resolved PER
    # REQUEST into ``g.product`` — URL scope > X-ADOM header (each browser
    # tab's sessionStorage, sent by turbo-boot.js/main.js) > ``_adom`` form
    # field (native form posts can't carry headers) > session cookie. The
    # session is only the DEFAULT for header-less full loads / brand-new
    # tabs; NAVIGATION NEVER MUTATES IT anymore (the old ADOM-jump wrote
    # session['product'], so switching ADOM in one tab flipped every other
    # tab). Only the explicit switches (product.enter / product.set_product
    # and the '/' + '/web/' homes) still write the session.
    @app.before_request
    def _product_gate():
        from flask import g, session, redirect, url_for
        from flask_login import current_user
        if not current_user.is_authenticated:
            return None
        ep = request.endpoint or ''
        bp_name = ep.split('.', 1)[0]
        from .branding import PRODUCTS as _BRAND_PRODUCTS
        valid = tuple(_BRAND_PRODUCTS.keys())
        sess_prod = session.get('product')
        if sess_prod not in valid:
            # No product chosen yet (fresh login / deep link) — default to the
            # Global ADOM instead of bouncing to the selector: every page is
            # reachable from Global and the ADOM switcher is one click away.
            session['product'] = sess_prod = 'global'
            session.permanent = True
        # NOTE: 'classification' is a Global-ADOM admin page (2026-07-07) and
        # 'templates'/'naming'/'capacity' are product-aware shared pages
        # linked from BOTH product ADOMs — none of them are URL-scoped.
        fortiweb_scoped = {
            'workspace', 'objedit', 'regex_lab', 'server_objects',
            'web_protection', 'exceptions', 'backups', 'logs',
            'import_backup', 'section_config', 'section_catalog',
            'signatures', 'structure',
            'segments', 'scheduled_actions', 'change_requests',
            'provisioning', 'registry', 'api_explorer',
        }
        hdr = (request.headers.get('X-ADOM') or '').strip().lower()
        # Explicit per-navigation ADOM pin via query string. Hard links /
        # non-Turbo navigations cannot send the X-ADOM header, so a shared
        # non-URL-scoped page (e.g. Firmware reached from the FAZ menu) would
        # fall back to the session cookie (often 'global') and lose its ADOM.
        # A '?_adom=<product>' on the link makes the scope deterministic.
        _qadom = (request.args.get('_adom') or '').strip().lower()
        if _qadom in valid:
            hdr = _qadom
        if hdr not in valid and request.method == 'POST' \
                and request.mimetype == 'application/x-www-form-urlencoded':
            # Native (non-Turbo) form posts carry the tab's ADOM as a hidden
            # field. urlencoded only — parsing multipart here would consume
            # the stream of large uploads before the view sees it.
            hdr = (request.form.get('_adom') or '').strip().lower()
        eff = hdr if hdr in valid else sess_prod
        if ep == 'index':
            eff = 'global'
        elif ep == 'fortiweb_home':
            eff = 'fortiweb'
        elif eff == 'global':
            # The Global ADOM sees EVERYTHING (both products). Opening a
            # product-scoped page is an ADOM jump for THIS TAB ONLY
            # (FortiManager-style); a concrete ADOM still bounces off the
            # other product's pages (the fortiadc branch below).
            if bp_name in fortiweb_scoped:
                eff = 'fortiweb'
            elif bp_name in ('adc', 'adc_api'):
                eff = 'fortiadc'
        elif eff == 'fortiweb' and bp_name in ('adc', 'adc_api'):
            # Entering the ADC area is always an explicit ADOM jump.
            eff = 'fortiadc'
        if bp_name in ('faz', 'faz_api'):
            # Entering the FortiAnalyzer area is always an explicit ADOM jump.
            eff = 'fortianalyzer'
        if bp_name in ('fac', 'fac_api'):
            # Same for FortiAuthenticator.
            eff = 'fortiauthenticator'
        g.product = eff
        always = {
            'static', 'index', 'fortiweb_home', 'service_worker',
            'upload_worker', 'updiag', 'healthz', 'healthz_primary',
            'healthz_backups', 'healthz_cert_renewals',
            'product.select', 'product.set_product', 'product.switch',
            'product.enter', 'product.fortiadc_home',
            'product.placeholder_home',
        }
        if ep in always or ep.startswith('auth.'):
            return None
        if eff == 'fortiadc':
            # FortiADC sessions get the ADC area + the product-neutral shared
            # pages (fleet admin, audit, jobs, notifications, own profile) +
            # the fleet-wide sections that are product-neutral or ADC-aware:
            # the ADC API console (adc_api), Certificate Manager, and
            # the DB browser. 'cert_manager'/'database' are product-scoped;
            # 'adc_api' is the ADC-scoped API hub. RBAC still gates each write.
            adc_bps = {'adc', 'adc_api', 'appliances', 'settings', 'audit',
                       'jobs', 'notifications', 'profiles', 'users', 'docs',
                       'database', 'locks',
                       # Firmware is product-scoped by row (2026-08-06): each
                       # ADOM sees and uploads only its own images. It used to
                       # be reachable from FortiAnalyzer only, which is why the
                       # FAZ ADOM could see FortiWeb images.
                       'firmware', 'device_provision',
                       # Custom Views: Plugin Studio + Lua Studio are
                       # product-scoped (records stamped per ADOM), so the
                       # ADC ADOM reaches them and sees only its own.
                       'plugins', 'lua_studio',
                       # Product-scoped Fleet pages mirrored into the ADC ADOM
                       # (visible_appliances / product_scope keep them ADC-only).
                       # Monitoring, Metrics and Deep monitors are mirrored into
                       # every ADOM as of 2026-07-28 (reversing the 2026-07-07
                       # Global-only restructure): all three already scope their
                       # rows through visible_appliances(), so an ADOM sees only
                       # its own devices and probes, and anything added from the
                       # Global ADOM for a device of this product shows up here
                       # automatically. Certificate Manager stays Global-only.
                       'architecture', 'metrics', 'search', 'analysis',
                       'fleet_objects', 'dns_tool',
                       'monitoring', 'deep_monitor', 'service_monitor',
                       'monitor_analytics', 'monitor_reports',
                       'metrics_admin',
                       # Backup vault (per-appliance; the ADC transport is the
                       # SSH config dump — services/backup.py kind branch).
                       'backups',
                       # Product-aware admin pages shared with FortiWeb.
                       # Release Notes: product-scoped harvester/browser
                       # (corpus filtered by g.product); reached from the
                       # ADC ADOM top-banner modal (2026-07-12).
                       'release_notes',
                       'templates', 'naming', 'capacity', 'api_tokens', 'api_v1'}
            adc_eps = {'product.fortiadc_home'}
            if bp_name not in adc_bps and ep not in adc_eps:
                return redirect(url_for('adc.index'))
        if eff == 'fortianalyzer':
            # FortiAnalyzer sessions get the FAZ area + the product-neutral
            # shared pages + the product-scoped Fleet/Administration pages
            # (Firmware, Network segment, Appliances, Audit). The
            # Configuration/Operation/Automation sections are faz-blueprint
            # scaffolds. RBAC still gates each write.
            faz_bps = {'faz', 'faz_api', 'appliances', 'settings', 'audit', 'jobs',
                       'notifications', 'profiles', 'users', 'docs',
                       'database', 'locks', 'firmware', 'segments',
                       'device_provision',
                       'architecture', 'metrics', 'search', 'analysis',
                       'fleet_objects', 'dns_tool', 'backups',
                       # Mirrored per-ADOM monitoring (2026-07-28) — see the
                       # ADC note above; scoping is by device kind.
                       'monitoring', 'deep_monitor', 'service_monitor',
                       'monitor_analytics', 'monitor_reports',
                       'metrics_admin',
                       'release_notes', 'templates', 'naming', 'capacity',
                       'api_tokens', 'api_explorer', 'api_v1',
                       'plugins', 'lua_studio'}
            if bp_name not in faz_bps:
                return redirect(url_for('faz.index'))
        elif eff == 'fortiauthenticator':
            # Shared pages + the product-scoped Fleet/Administration pages.
            # The Authentication/Certificate/Logging sections are fac-blueprint
            # pages. RBAC still gates each write.
            fac_bps = {'fac', 'fac_api', 'appliances', 'settings', 'audit', 'jobs',
                       'notifications', 'profiles', 'users', 'docs',
                       'database', 'locks', 'segments', 'firmware',
                       'device_provision',
                       'architecture', 'metrics', 'search', 'analysis',
                       'fleet_objects', 'dns_tool', 'backups',
                       # Mirrored per-ADOM monitoring (2026-07-28) — scoping is
                       # by device kind, so a FAC session sees only FAC boxes.
                       'monitoring', 'deep_monitor', 'service_monitor',
                       'monitor_analytics', 'monitor_reports',
                       'metrics_admin',
                       'templates', 'capacity',
                       'api_tokens', 'api_v1',
                       # NOT lua_studio: FortiAuthenticator has no scripting
                       # object (endpoints_fortiauthenticator.yaml declares
                       # none) and LuaScript.TARGETS therefore cannot list it.
                       # Letting the ADOM reach the studio only produced an
                       # editor with zero valid targets.
                       'plugins'}
            if bp_name not in fac_bps:
                return redirect(url_for('fac.index'))
        return None

    # -- access control gate (IP whitelist + allowed users) --------------
    # Lockout-safe by design: empty lists = no restriction, loopback always
    # allowed, admins are NEVER restricted (so a typo can't lock out the people
    # who manage this), and auth/static endpoints stay reachable.
    @app.before_request
    def _access_gate():
        from flask import abort
        from flask_login import current_user
        if not current_user.is_authenticated:
            return None
        ep = request.endpoint or ''
        if ep in ('static', 'service_worker', 'upload_worker', 'updiag') \
                or ep.startswith('auth.'):
            return None
        from .models import Permission
        if current_user.can(Permission.USER_MANAGE):
            return None  # admins are exempt
        from .services import settings_store as _store
        # An UNREADABLE allowlist is not an empty one. Both lists decode to []
        # on a parse failure, and [] is the most permissive value here — a
        # restored backup, a replica mid-write or a hand-edited psql row would
        # otherwise admit every non-admin from every source IP, silently,
        # because the ACCESS_DENY lines below are the only telemetry there is.
        # Refuse to serve instead: 503, not 403 — this is the service being
        # unable to evaluate the policy, not the user failing it. Admins
        # returned above, so whoever must fix the row can still reach the UI.
        _cfg_err = _store.access_config_error()
        if _cfg_err:
            app.logger.error('ACCESS_DENY reason=access_config_unreadable '
                             'user=%s ip=%s endpoint=%s detail=%s',
                             current_user.username, _client_ip(), ep, _cfg_err)
            abort(503)
        allowed = _store.allowed_users()
        if allowed and current_user.username not in allowed:
            app.logger.warning('ACCESS_DENY reason=user_not_allowed user=%s '
                               'ip=%s endpoint=%s', current_user.username,
                               _client_ip(), ep)
            abort(403)
        wl = _store.ip_whitelist()
        if wl and not _ip_allowed(_client_ip(), wl):
            app.logger.warning('ACCESS_DENY reason=ip_not_whitelisted user=%s '
                               'ip=%s endpoint=%s', current_user.username,
                               _client_ip(), ep)
            abort(403)
        return None

    # -- device-first gate: per-device pages need a selected device ------
    @app.before_request
    def _device_gate():
        from flask import g, session, redirect, url_for
        from flask_login import current_user
        if not current_user.is_authenticated:
            return None
        if getattr(g, 'product', session.get('product')) != 'fortiweb':
            return None
        ep = request.endpoint or ''
        # Pure-metadata JSON endpoints need no device context — gating them
        # only breaks the forms (and tests) that fetch field specs.
        if ep in ('exceptions.type_fields',):
            return None
        bp_name = ep.split('.', 1)[0]
        device_bps = {'workspace', 'server_objects', 'web_protection',
                      'exceptions', 'backups'}
        if bp_name not in device_bps:
            return None
        from .services import device_context
        va = request.view_args or {}
        did = va.get('appliance_id', va.get('id'))
        if did is not None:
            try:
                device_context.set_current(did)
            except Exception:
                pass
            return None
        if device_context.current_appliance() is None:
            return redirect(url_for('architecture.index'))
        return None

    # -- template globals -------------------------------------------------
    # Cache-busting for app-owned static: ?v=<mtime> so a deploy invalidates
    # the edge /static/ proxy cache (which otherwise serves stale JS/CSS).
    @app.template_global()
    def asset(filename):
        import os as _os
        from flask import url_for
        try:
            _v = int(_os.path.getmtime(_os.path.join(app.static_folder, filename)))
        except OSError:
            _v = 0
        return url_for('static', filename=filename) + ('?v=%d' % _v)

    @app.context_processor
    def _inject_branding():
        from flask import session
        from flask_login import current_user
        from .branding import get_product, PRODUCTS
        from .services import settings_store as _store
        from .services import user_settings_store as _ustore
        from flask import g as _g
        prod = get_product(getattr(_g, 'product', None) or session.get('product'))
        try:
            # Per-user banner (DB-backed) for a logged-in user; global/default
            # otherwise. No cookie is involved.
            if getattr(current_user, 'is_authenticated', False):
                _bg = _ustore.banner_bg(current_user.id, prod['key'])
            else:
                _bg = _store.banner_bg(prod['key'])
        except Exception:
            _bg = '#162940'
        # FortiWeb config sections for the sidebar (live browsers only). Sourced
        # from the catalog so it stays in sync; server_objects (own page) and the
        # read-only Monitor have no menu → excluded.
        try:
            from .services import config_catalog as _cc
            from .services import config_sections as _cs
            # These 5 WAF protection areas were promoted to the top-level
            # WAF group in the sidebar, so exclude them here to avoid showing
            # them twice (WAF group + admin Configuration submenu).
            _promoted = {'application_delivery', 'api_protection',
                         'bot_mitigation', 'dos_protection', 'ip_protection'}
            # server_objects has its OWN dedicated collapsible sidebar item
            # (fw-so-parent), so it is excluded here to avoid a duplicate tree.
            _cfg_skip = _promoted | {'server_objects'}
            # Each section carries its GUI-faithful curated menu (groups → object
            # types) so the sidebar expands it into a collapsible tree, exactly
            # like Server Objects. complete=False = curated groups only (no giant
            # "everything else" bucket — that stays on the section page).
            _cfg_nav = [
                {'key': s.key, 'label': s.label, 'emoji': s.emoji,
                 'menu': _cs.section_menu(s.key, complete=False)}
                for s in _cc.CONFIG_SECTIONS
                if _cs.has_menu(s.key) and s.key not in _cfg_skip
            ]
        except Exception:
            _cfg_nav = []
        # Server Objects menu (groups → object types) for the sidebar submenu.
        # The GUI-faithful menu lives in services.server_objects; each leaf links
        # to server_objects.overview(?type=…) under the selected device.
        try:
            from .services import server_objects as _so
            _so_nav = _so.server_objects_menu()
        except Exception:
            _so_nav = []
        # Web Protection menu (FortiWeb 7.6 GUI mirror: groups → items) for the
        # sidebar submenu — the SAME tree the in-page card used, now collapsible
        # under the sidebar "Web Protection" item. Each leaf links to
        # web_protection.menu_page under the selected device.
        try:
            from .services import wp_menu as _wp
            _wp_nav = _wp.menu()
        except Exception:
            _wp_nav = []
        # The 5 WAF protection areas promoted to the sidebar WAF group: each the
        # FortiWeb GUI menu (services.config_sections, GUI-faithful) rendered as
        # a collapsible accordion (like Web Protection / Server Objects). Each
        # leaf links into section_config with ?type=<logical>. complete=False =
        # curated GUI groups only (the "everything else" bucket stays on the page).
        try:
            from .services import config_sections as _cs2
            _WAF_AREAS = (
                ('application_delivery', 'Application Delivery', 'bi-rocket-takeoff'),
                ('api_protection', 'API Protection', 'bi-plug'),
                ('bot_mitigation', 'Bot Mitigation', 'bi-robot'),
                ('dos_protection', 'DoS Protection', 'bi-shield-fill-exclamation'),
                ('ip_protection', 'IP Protection', 'bi-signpost-split'),
            )
            _waf_nav = [
                {'key': _k, 'label': _lbl, 'icon': _ic,
                 'menu': _cs2.section_menu(_k, complete=False)}
                for _k, _lbl, _ic in _WAF_AREAS
            ]
        except Exception:
            _waf_nav = []
        try:
            from .services import device_context as _dc
            _cur_appl = _dc.current_appliance()
            if _cur_appl is None:
                # Display-only fallback: a single-device product (FortiADC,
                # FortiAnalyzer, FortiAuthenticator) shows its sole device in
                # the topbar/menu without a manual pick. Views still resolve
                # their own device context via device_context.
                # The ADOM key IS the appliance kind, so this is derived from
                # the registry — the old literal map left every ADOM added
                # later without the fallback. FortiWeb is excluded on purpose:
                # it is the multi-device product and owns an explicit picker.
                from .services.product_scope import (session_product,
                                                     concrete_products,
                                                     FORTIWEB)
                from .models import Appliance as _ApplFB
                _p = session_product()
                _kfb = _p if (_p != FORTIWEB and _p in concrete_products()) else None
                if _kfb:
                    _cands = _ApplFB.query.filter_by(kind=_kfb).all()
                    if len(_cands) == 1:
                        _cur_appl = _cands[0]
        except Exception:
            _cur_appl = None
        try:
            from flask_login import current_user as _cu
            from .models import Template as _Tpl
            if getattr(_cu, 'is_authenticated', False) and _cu.can('user_manage'):
                _pending = _Tpl.query.filter_by(status=_Tpl.STATUS_PENDING).count()
            else:
                _pending = 0
        except Exception:
            _pending = 0
        # --- bug-report counts for the top-bar bell ---
        _open_reports = 0
        _my_resolved = 0
        _bug_notify = False
        try:
            from flask_login import current_user as _cu2
            if getattr(_cu2, "is_authenticated", False):
                from .services import bug_reports as _br
                if _cu2.can("user_manage"):
                    _bug_notify = _br.is_opted_in(_cu2.id)
                    # In-app badge/inbox is available to every admin;
                    # the opt-in flag governs EMAIL delivery only.
                    _open_reports = _br.open_count()
                _my_resolved = _br.unseen_resolved_count(_cu2.id)
        except Exception:
            _open_reports = 0
            _my_resolved = 0
            _bug_notify = False
        # --- unread notifications for the top-bar bell (the bell's ONLY count) ---
        _unread_notif = 0
        _notif_preview = []
        try:
            from flask_login import current_user as _cu3
            if getattr(_cu3, "is_authenticated", False):
                from .services import notifications as _notify
                _unread_notif = _notify.unread_count(_cu3.id)
                _notif_preview = _notify.recent(_cu3.id, limit=8)
        except Exception:
            _unread_notif = 0
            _notif_preview = []
        # FortiADC sidebar menu (only built for fortiadc sessions; pure data,
        # registry-resolved, cached per process — see services.adc_menu).
        try:
            if prod.get('key') == 'fortiadc':
                from .services import adc_menu as _adcm
                _adc_nav = _adcm.menu()
            else:
                _adc_nav = ()
        except Exception:
            _adc_nav = ()
        # FortiAnalyzer sidebar menu (only built for fortianalyzer sessions;
        # static curated menu — no backend yet, see services.faz_menu).
        try:
            if prod.get("key") == "fortianalyzer":
                from .services import faz_menu as _fazm
                _faz_nav = _fazm.visible_menu()
            else:
                _faz_nav = ()
        except Exception:
            _faz_nav = ()
        # FortiAuthenticator sidebar menu (only built for fortiauthenticator
        # sessions; mirrors the unit's own nav_menu_definition, see
        # services.fac_menu).
        try:
            if prod.get("key") == "fortiauthenticator":
                from .services import fac_menu as _facm
                _fac_nav = _facm.visible_menu()
            else:
                _fac_nav = ()
        except Exception:
            _fac_nav = ()
        try:
            _env_mode = _store.env_mode()
        except Exception:
            _env_mode = 'development'
        try:
            from .services import self_update as _su
            _ha_mode = _su.ha_mode()
            _node_role = _su.node_role()
            _node_name = _su.this_node_name()
        except Exception:
            _ha_mode, _node_role, _node_name = 'standalone', 'unknown', ''
        return {
            'product': prod,
            'products': PRODUCTS,
            'env_mode': _env_mode,
            'ha_mode': _ha_mode,
            'node_role': _node_role,
            'node_name': _node_name,
            'adc_nav': _adc_nav,
            'faz_nav': _faz_nav,
            'fac_nav': _fac_nav,
            'current_appliance': _cur_appl,
            'banner_bg': _bg,
            'now': datetime.utcnow(),
            'config_sections_nav': _cfg_nav,
            'server_objects_nav': _so_nav,
            'web_protection_nav': _wp_nav,
            'waf_sections_nav': _waf_nav,
            'pending_template_count': _pending,
            'open_report_count': _open_reports,
            'bug_reports_notify': _bug_notify,
            'my_resolved_unseen_count': _my_resolved,
            'unread_notification_count': _unread_notif,
            'notification_preview': _notif_preview,
        }

    # -- timezone-aware timestamp filter ---------------------------------
    @app.template_filter('localtime')
    def _localtime(dt, fmt='%Y-%m-%d %H:%M:%S'):
        # Single conversion path: delegate to settings_store.to_local so the
        # filter and every server-side formatter (git_service/monitoring) share
        # one timezone source (general.timezone in app_settings).
        from .services import settings_store as _store
        return _store.to_local(dt, fmt)

    # -- self-healing CSRF errors ----------------------------------------
    # A stale/expired login (or any) form submitted with an old token used to
    # dead-end on a raw 400 "CSRF tokens do not match". Instead, flash a hint
    # and bounce back to the same form page, which re-renders a fresh token so
    # the resubmit succeeds. (2026-06-27)
    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def _handle_csrf_error(exc):  # noqa: ANN001
        from flask import flash, redirect, request, url_for, jsonify
        # JSON/XHR callers (the editor save/inject fetch calls) must get a JSON
        # error, not a 302 redirect they can't parse (which silently aborts the
        # save). Browsers carry the token via the global fetch wrapper; this is
        # the defense-in-depth so a miss surfaces loudly. (2026-06-28)
        wants_json = (request.is_json
                      or "application/json" in (request.headers.get("Accept") or "")
                      or request.headers.get("X-Requested-With") == "XMLHttpRequest")
        if wants_json:
            return jsonify(ok=False, error="CSRF token missing or expired \u2014 reload the page and retry"), 400
        flash("Your session expired or the form was stale \u2014 please try again.", "warning")
        ref = request.referrer or ""
        if ref.startswith(request.host_url):
            return redirect(ref)
        return redirect(url_for("auth.login"))

    # -- security headers -------------------------------------------------
    # CSP hardening (2026-07-03, round 2): every inline <script> AND <style>
    # block in the templates carries nonce="{{ csp_nonce }}".
    #  * script-src-attr is 'none' — the ~163 inline on*= handlers were
    #    refactored into addEventListener bindings inside nonced script blocks
    #    (data-js/data-* hooks, delegation for Jinja loops); JS-generated
    #    markup no longer emits handler attributes either (lock.js, audit,
    #    api_explorer, settings, segments, exceptions detect).
    #  * script-src drops 'unsafe-inline' and carries the nonce as the
    #    legacy fallback for browsers without -elem/-attr support.
    #  * style-src-elem is nonce-gated, so an INJECTED <style> is refused;
    #    dynamic injectors stamp the meta[name=csp-nonce] (turbo.min.js does
    #    natively, jobs.js patched, and the two fragment re-executors —
    #    base.html device picker + section_config editor — re-nonce style
    #    elements alongside scripts).
    #  * style-src-attr stays 'unsafe-inline': ~827 style="..." attributes
    #    remain in the templates; converting them to classes is a separate
    #    incremental round. The plain style-src line is the legacy fallback.
    import secrets as _secrets

    @app.before_request
    def _csp_nonce():
        # STABLE per session, NOT per request. CSP is enforced from the ORIGINAL
        # document response HEADER and is immutable for that document's lifetime.
        # Turbo Drive navigations are fetch+swap: the active document (and the
        # nonce its header enforces) never changes, yet Turbo re-inserts each
        # fetched page's inline <script>/<style> carrying THAT response nonce. A
        # per-request nonce therefore never matches the enforced one after any
        # Turbo visit -> every inline script/style is CSP-blocked until a full
        # refresh. Pinning the nonce to the session makes every response (full
        # load + Turbo fetch) share the one nonce enforced on first load.
        from flask import session
        nonce = session.get("_csp_nonce")
        if not nonce:
            nonce = _secrets.token_urlsafe(16)
            session["_csp_nonce"] = nonce
        g.csp_nonce = nonce

    @app.context_processor
    def _inject_version():
        """The running version, from the repo-root VERSION file.

        Templates must never carry a version literal -- see app/version.py
        for why (the footer said v1.0 through four releases).
        """
        from .version import app_version
        return {"app_version": app_version()}

    @app.context_processor
    def _inject_docs_url():
        """The manual is published, not served. One address, one definition."""
        from app.services.doc_publication import site_url
        return {"docs_url": site_url}

    @app.context_processor
    def _inject_csp_nonce():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    @app.context_processor
    def _inject_theme():
        """Active UI theme (Settings -> Appearance): the ``:root`` override
        block plus optional brand overrides.

        Emitted as a nonced <style> in base.html rather than a stylesheet file
        because it is per-install DB state, not an asset: a file would have to
        be regenerated on every node after every edit and would drift on the
        standby, whose Postgres is a read-only replica.

        Failure here degrades to the shipped stylesheet; theming must never be
        able to take a page down.
        """
        try:
            from .services import theme_service as _theme
            t = _theme.active_theme()
        except Exception:
            return {"theme_css": "", "theme_logo_url": "",
                    "theme_favicon_url": "", "theme_name": ""}
        from flask import url_for as _url_for
        logo = favicon = ""
        try:
            if t.get("logo"):
                logo = _url_for("settings.theme_asset", theme_id=t["id"],
                                kind="logo")
            if t.get("favicon"):
                favicon = _url_for("settings.theme_asset", theme_id=t["id"],
                                   kind="favicon")
        except Exception:
            logo = favicon = ""
        return {"theme_css": t.get("css", ""), "theme_logo_url": logo,
                "theme_favicon_url": favicon, "theme_name": t.get("name", "")}

    @app.route('/favicon.ico')
    def favicon_ico():
        """Serve the bare-root favicon the browser requests implicitly.

        Browsers ask for /favicon.ico regardless of any <link rel="icon"> tag
        and cache the ANSWER — a 404 included — so a missing route is exactly
        why a stale icon survives a rebrand. The active theme's favicon wins;
        the shipped product mark is the fallback, so a fresh install with no
        theme asset still gets the product icon and never a vendor logo.
        """
        from flask import redirect as _redirect, url_for as _url_for
        from flask import send_from_directory as _send
        try:
            from .services import theme_service as _theme
            t = _theme.active_theme()
            if t.get("favicon"):
                return _redirect(_url_for("settings.theme_asset",
                                          theme_id=t["id"], kind="favicon"))
        except Exception:
            pass
        return _send(os.path.join(app.root_path, "static", "img"),
                     "favicon.ico", max_age=300)

    @app.after_request
    def set_security_headers(response):
        # Plugin frame route (views/plugins.py) sets SAMEORIGIN so it can be
        # embedded in its own sandboxed iframe; don't clobber it with DENY.
        if "X-Frame-Options" not in response.headers:
            response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        nonce = getattr(g, "csp_nonce", "")
        # Plugin sandbox routes (views/plugins.py: frame()/preview()) set their
        # own relaxed CSP for author-supplied HTML/CSS/JS inside a sandboxed
        # iframe. Don't clobber it with the app-wide strict/nonce-based policy.
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
                f"script-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
                "script-src-attr 'none'; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                f"style-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
                "style-src-attr 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data: https://cdn.jsdelivr.net;"
            )
        # Never serve authenticated HTML (e.g. the nav menu) from a stale
        # browser cache after a deploy. Static assets stay cacheable.
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    # -- centralised logging + global error handlers ---------------------
    from .errors import (configure_logging, register_error_handlers,
                         register_selftest_routes)
    configure_logging(app)
    register_error_handlers(app)
    register_selftest_routes(app)

    # -- health probe (unauthenticated; used by the self-update runner) --
    @app.route('/healthz')
    def healthz():
        from flask import jsonify
        rev = {}
        try:
            from .services import self_update as _su
            rev = _su.current_revision()
        except Exception:
            pass
        db_state = None
        try:
            from .services import cluster as _cluster
            db_state = _cluster.db_summary()
        except Exception:
            pass
        host = None
        try:
            from .services import system_health as _sh
            host = _sh.host_stats()
        except Exception:
            pass
        peer_auth = None
        try:
            from flask import request as _rq
            from .services import node_security as _nsec
            peer_auth = _nsec.verify_request(_rq.headers)
        except Exception:
            peer_auth = None
        return jsonify({'ok': True, 'revision': rev.get('short'),
                        'sha': rev.get('sha'), 'branch': rev.get('branch'),
                        'db': db_state, 'host': host,
                        'peer_authenticated': peer_auth}), 200

    # -- primary-aware probe (for a load balancer health check) -----------
    # Returns 200 ONLY when the local Postgres is the PRIMARY. A standby
    # answers 503 so the LB keeps it out of rotation; after promotion
    # (pg_is_in_recovery() -> false) it flips to 200 and the LB routes to it.
    @app.route('/healthz/primary')
    def healthz_primary():
        from flask import jsonify
        from sqlalchemy import text
        try:
            in_recovery = db.session.execute(
                text('SELECT pg_is_in_recovery()')).scalar()
        except Exception as exc:
            db.session.rollback()
            return jsonify({'ok': False, 'role': 'unknown',
                            'error': str(exc)}), 503
        if in_recovery:
            return jsonify({'ok': False, 'role': 'standby'}), 503
        return jsonify({'ok': True, 'role': 'primary'}), 200

    # -- off-box backup inventory probe (unauthenticated, like /healthz) ---
    # The PEER's System Backup page calls this to render a side-by-side
    # local-vs-backup-server comparison without any SSH between nodes.
    # Exposes only bundle names/sizes/dates + vault entry count — no content.
    @app.route('/healthz/backups')
    def healthz_backups():
        from flask import jsonify
        try:
            from .services import system_backup as _sb
            inv = _sb.local_inventory()
            return jsonify({'ok': True, 'bundles': inv['bundles'],
                            'vault': inv['vault']}), 200
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500

    # -- renewal-journal probe (same pattern as /healthz/backups) ---------
    # The PEER's Renewals page calls this so one page shows BOTH nodes without
    # any SSH between them. The journal is node-local on purpose: a standby's
    # Postgres is read-only and data/ is wiped by the rsync --delete datasync,
    # so the node that fails to renew could not otherwise record that failure.
    @app.route('/healthz/cert-renewals')
    def healthz_cert_renewals():
        from flask import jsonify, request as _rq
        try:
            from .services import cert_renew_log as _jrn
            from .services import cert_service as _cs
            limit = min(int(_rq.args.get('limit', 100) or 100), 400)
            cert = {}
            try:
                cur = _cs.current()
                cert = {k: cur.get(k) for k in
                        ('source', 'days_left', 'not_after', 'subject', 'hostname',
                         'installed_at', 'can_issue_internal')}
                cert['renew_mode'] = _cs.renew_mode()
            except Exception as exc:  # noqa: BLE001
                cert = {'error': str(exc)}
            return jsonify({'ok': True, 'cert': cert,
                            'summary': _jrn.summary(),
                            'runs': _jrn.history(limit=limit)}), 200
        except Exception as exc:  # noqa: BLE001
            return jsonify({'ok': False, 'error': str(exc)}), 500

    # -- CLI commands -----------------------------------------------------
    @app.cli.command('cert-renew')
    def cert_renew_cmd():
        """Auto-renew the node's CA-issued service cert if within threshold.
        Invoked by the satom-cert-renew.timer. No-op for imported/bootstrap certs."""
        from .services import cert_service as _cs
        from .services import cert_renew_log as _jrn
        try:
            res = _cs.renew_if_needed(by='timer')
            print('cert-renew:', res)
        except Exception as exc:  # noqa: BLE001
            # renew_if_needed journals its own failures; this catches anything
            # that blew up BEFORE it could (import error, unreadable pki/, ...)
            # so the Renewals page never shows a silent gap for a night.
            _jrn.record(_jrn.CH_TIMER, _jrn.OK_ERROR, 'nightly cert-renew aborted',
                        error='%s: %s' % (type(exc).__name__, exc), by='timer')
            print('cert-renew error:', exc)
        # Imported certs (e.g. the fleet wildcard) don't re-mint here; if the
        # operator chose the 'autopull' renewal mode, fetch+install the renewed
        # cert from the configured source in the SAME nightly pass.
        try:
            if _cs.renew_mode() == 'autopull':
                print('cert-autopull:', _cs.autopull(by='timer'))
        except Exception as exc:  # noqa: BLE001
            _jrn.record(_jrn.CH_TIMER, _jrn.OK_ERROR, 'nightly cert-autopull aborted',
                        error='%s: %s' % (type(exc).__name__, exc), by='timer')
            print('cert-autopull error:', exc)

        # [SATOM-SHARED-CERT] The served cert is the one PKI artefact both
        # nodes legitimately share: a fleet wildcard covers every node name, is
        # renewed OFF these nodes, and until now was copied to each one by
        # hand. Hand-copying is why the pair drifts -- and the wildcard on this
        # estate expires without any automatic path to replace it.
        #
        # Publish then install, in that order and on EVERY node: publish puts
        # this node's served cert into data/pki-shared/ (which the datasync
        # carries), install picks up a cert a peer published. Running both
        # everywhere is self-correcting rather than role-gated -- the standby
        # pulls data/ from the primary with --delete, so the primary's copy is
        # authoritative within one sync interval no matter who wrote last.
        #
        # Both calls are gated inside cert_service on source == "imported" and
        # on the cert actually covering this node's served names. A CA-ISSUED
        # cert is per-node by construction (its SAN is this node's hostname),
        # and sharing one would hand every node a certificate that names
        # somebody else -- the same class of bug as sharing the node leaf.
        try:
            pub = _cs.publish_shared_cert()
            if pub.get('published'):
                print('cert-share publish:', pub.get('reason', 'ok'))
            ins = _cs.install_shared_cert()
            if ins.get('installed'):
                print('cert-share install:', ins.get('reason', 'ok'))
        except Exception as exc:  # noqa: BLE001
            # Never let cert sharing break the nightly pass that renews the
            # node's OWN certificate -- that one is load-bearing, this is
            # convenience. But say so: a share that silently stops working
            # leaves the pair drifting with both nodes reporting healthy.
            _jrn.record(_jrn.CH_TIMER, _jrn.OK_ERROR, 'nightly cert-share aborted',
                        error='%s: %s' % (type(exc).__name__, exc), by='timer')
            print('cert-share error:', exc)

        # [SATOM-RENEW-ARCHIVE] Pull the peer's renewal journal into a
        # primary-owned archive under data/.
        #
        # The journal is node-local for a reason that has not changed: the
        # standby's database is a read-only replica, so the node that fails to
        # renew is exactly the node that cannot write a row about its own
        # failure, and data/ is no good for the standby either because the
        # datasync pulls it with --delete. What that leaves is a journal with
        # no copy anywhere -- and on this estate the usual consolation ("the
        # other node still has it") is false, because both nodes and the
        # external backup host share a hypervisor.
        #
        # Direction is what makes this work: the standby pulls data/ FROM the
        # primary, so a file the PRIMARY writes propagates instead of being
        # deleted. archive_refresh() is inert on a standby by design.
        #
        # Wired here rather than left to a page render: an archive that only
        # updates when somebody opens the Renewals page is an archive that is
        # empty on the day the node it protects is gone.
        try:
            arch = _jrn.archive_refresh()
            if arch:
                print('cert-renew archive:', arch)
        except Exception as exc:  # noqa: BLE001
            print('cert-renew archive error:', exc)

    @app.cli.command('cert-autopull')
    def cert_autopull_cmd():
        """Force a one-off autopull of the imported cert from the configured
        source (ignores the mode gate). For testing the 'autopull' renewal path."""
        from .services import cert_service as _cs
        try:
            print('cert-autopull:', _cs.autopull(by='manual', force=True))
        except Exception as exc:  # noqa: BLE001
            print('cert-autopull error:', exc)

    @app.cli.command('alerts-run')
    @click.option('--dry-run', is_flag=True, help='Evaluate only; send nothing.')
    @click.option('--force', is_flag=True, help='Ignore the per-alert cooldown.')
    def alerts_run_cmd(dry_run, force):
        """Evaluate the proactive health checks and dispatch new alerts by email +
        in-app bell. Invoked by satom-alerts.timer; runs on every node."""
        from .services import alerts as _al
        try:
            res = _al.run(force=force, dry_run=dry_run)
            print('alerts-run:', res)
        except Exception as exc:  # noqa: BLE001
            print('alerts-run error:', exc)

    @app.cli.command('preflight')
    @click.option('--label', default='', help='Free-text label for the snapshot.')
    @click.option('--out', default=None, help='Write the snapshot JSON here '
                  '(default: data/flight/last-preflight.json).')
    def preflight_cmd(label, out):
        """Capture a health baseline BEFORE a risky change (upgrade / restore).
        Saves it so 'postflight' can diff against it."""
        from .services import preflight as _pf
        import json as _json
        snap = _pf.snapshot(label or 'preflight')
        path = _pf.save(snap, out)
        print('preflight saved:', path)
        print(_json.dumps({'health': snap['health'], 'git': snap['git'].get('head'),
                           'devices': {k: v.get('reachable') for k, v in snap['devices'].items()}
                           if isinstance(snap['devices'], dict) and 'error' not in snap['devices']
                           else snap['devices']}, indent=2))

    @app.cli.command('postflight')
    @click.option('--baseline', default=None, help='Baseline snapshot path '
                  '(default: the last preflight).')
    @click.option('--label', default='', help='Free-text label for the after-snapshot.')
    def postflight_cmd(baseline, label):
        """Capture a health snapshot AFTER a risky change and diff it against the
        preflight baseline. Exits non-zero if a regression is detected."""
        from .services import preflight as _pf
        import json as _json, sys as _sys
        try:
            before = _pf.load(baseline)
        except Exception as exc:  # noqa: BLE001
            print('postflight: cannot load baseline:', exc)
            _sys.exit(2)
        after = _pf.snapshot(label or 'postflight')
        verdict = _pf.compare(before, after)
        print(_json.dumps(verdict, indent=2))
        if not verdict['passed']:
            print('POSTFLIGHT FAILED — regressions detected.')
            _sys.exit(1)
        print('postflight OK — no regressions.')

    @app.cli.command('canary-restore')
    @click.option('--device', required=True, help='Appliance name (e.g. fw7).')
    @click.option('--apply', 'do_apply', is_flag=True, default=False,
                  help='ACTUALLY upload+apply (DESTRUCTIVE — device reboots). '
                       'Omit for a safe dry-run.')
    @click.option('--method', default='ssh',
                  help='Safety-backup capture transport: ssh|rest|auto (default ssh — '
                       'plaintext, diffable).')
    def canary_restore_cmd(device, do_apply, method):
        """Config-restore canary, wrapped in the preflight/postflight harness.

        SAFE steps (always run): preflight snapshot → capture a FRESH on-box
        backup (the rollback artifact) → restore DRY-RUN (resolves the endpoint,
        sends nothing). With --apply it additionally uploads that SAME just-taken
        config back (a neutral re-apply) and the box reboots; then it waits for
        the device to return and runs a postflight comparison.

        The default (no --apply) is non-destructive end-to-end. Fire --apply only
        in a maintenance window: the multipart field name is still unconfirmed and
        a real restore reboots the appliance."""
        import sys as _sys, time as _time, socket as _socket
        from .services import preflight as _pf, backup as _bk
        from .models import Appliance
        appl = Appliance.query.filter_by(name=device).first()
        if not appl:
            print('canary: no appliance named %r' % device); _sys.exit(2)

        pre = _pf.snapshot('canary-%s' % device)
        _pf.save(pre)
        devs = pre.get('devices') or {}
        reachable = devs.get(device, {}).get('reachable') if isinstance(devs, dict) else None
        print('preflight: %s reachable=%s | health_ok=%s' % (
            device, reachable, pre.get('health', {}).get('ok')))
        if not reachable:
            print('canary: %s is not reachable — aborting before any change.' % device)
            _sys.exit(1)

        cb = _bk.fetch_device_backup_auto(appl, created_by='canary', method=method)
        print('safety backup (ROLLBACK ARTIFACT): %s (%s bytes)' % (
            cb.stored_path, getattr(cb, 'size_bytes', '?')))
        with open(cb.stored_path, 'rb') as fh:
            data = fh.read()

        client = appl.build_client(timeout=60)
        plan = _bk.restore(client, data, cb.filename, dry_run=not do_apply)
        print('restore plan: dry_run=%s endpoint=%s size=%s ok=%s' % (
            plan.get('dry_run'), plan.get('endpoint'), plan.get('size'), plan.get('ok')))
        print('  ' + str(plan.get('message', '')))

        if not do_apply:
            print('DRY-RUN complete — nothing was sent. To fire for real (device '
                  'REBOOTS), re-run in a maintenance window with --apply.')
            return

        # ---- destructive path (maintenance window only) ----
        print('APPLY: uploaded — device is applying config and rebooting. '
              'Waiting for it to return...')
        host, port = appl.host, int(appl.port or 443)
        deadline = _time.time() + 600
        back = False
        while _time.time() < deadline:
            try:
                with _socket.create_connection((host, port), timeout=5):
                    back = True
                    break
            except Exception:  # noqa: BLE001
                _time.sleep(10)
        if not back:
            print('canary: %s did NOT return within 600s — restore the rollback '
                  'artifact from the console: %s' % (device, cb.stored_path))
            _sys.exit(1)
        _time.sleep(15)  # let services settle past TCP-up
        post = _pf.snapshot('canary-%s-after' % device)
        verdict = _pf.compare(pre, post)
        print('postflight passed=%s' % verdict['passed'])
        for r in verdict['regressions']:
            print('  REGRESSION:', r)
        print('rollback artifact retained at %s' % cb.stored_path)
        _sys.exit(0 if verdict['passed'] else 1)

    @app.cli.command('create-db')
    def create_db_cmd():
        """Initialise database tables and seed the default admin user."""
        db.create_all()
        from .models import User
        if User.query.count() == 0:
            admin = User(username='admin', role='admin', is_active=True)
            admin.set_password('Sopas123.-')
            db.session.add(admin)
            db.session.commit()
            print('Admin user created: admin / Sopas123.-')
        else:
            print('Database already contains users — skipping seed.')

    def _ensure_widths():
        """Widen VARCHAR columns that the models grew after the table existed.

        ``db.create_all()`` never ALTERs an existing table, and
        :func:`_ensure_columns` only ADDs — so a column whose model declaration
        grew (``String(16)`` -> ``String(32)``) stays narrow forever on an
        installation that predates the change.  That is not cosmetic: the ADOM
        key ``fortiauthenticator`` is 18 characters, so the first row written
        for the fourth product fails with ``StringDataRightTruncation`` on a
        column the model believes is wide enough.  The failures land late — an
        audit row, an alert, an API token — long after the operator registered
        the appliance and concluded it worked.

        Derived from the model metadata rather than a hand-written list, so a
        future widening needs no second edit here.  **Only ever widens**:
        narrowing can truncate real data, so a model that shrinks is ignored.
        Widening a ``varchar`` in PostgreSQL is a catalog-only change (no table
        rewrite) and replicates to the standby through WAL like any other DDL.
        SQLite does not enforce ``VARCHAR`` length at all, so it is skipped.
        """
        from sqlalchemy import inspect, text

        # SQLite does not enforce VARCHAR length, so there is nothing to widen
        # and ALTER COLUMN TYPE is not supported there either.
        if db.engine.dialect.name == 'sqlite':
            return
        insp = inspect(db.engine)
        live_widths = {}
        try:
            for name in insp.get_table_names():
                live_widths[name] = {
                    c['name']: getattr(c.get('type'), 'length', None)
                    for c in insp.get_columns(name)
                }
        except Exception:  # noqa: BLE001 — never block boot on a migration
            return

        for table, col, want in widen_plan(db.metadata.sorted_tables,
                                           live_widths):
            try:
                db.session.execute(text(
                    'ALTER TABLE %s ALTER COLUMN %s TYPE VARCHAR(%d)'
                    % (table, col, want)))
                db.session.commit()
            except Exception:  # noqa: BLE001
                db.session.rollback()

    def _ensure_columns():
        """Idempotently add columns introduced after a table already existed.

        ``db.create_all()`` never ALTERs existing tables, so a new column on a
        pre-existing table (e.g. ``templates.exceptions``) must be added here.
        Safe on every boot — a column that is already present is a no-op.
        """
        from sqlalchemy import inspect, text
        adds = {
            'templates': [
                ('exceptions', 'TEXT'),
                ('status', "VARCHAR(16) DEFAULT 'pending'"),
                ('reject_reason', 'TEXT'),
                ('reviewed_by', 'VARCHAR(64)'),
                ('reviewed_at', 'DATETIME'),
                ('product', "VARCHAR(32) DEFAULT 'fortiweb'"),
            ],
            'users': [
                ('profile_id', 'INTEGER'),
                ('auth_source', "VARCHAR(16) DEFAULT 'local'"),
                ('totp_secret', 'VARCHAR(512)'),
                ('totp_enabled', 'BOOLEAN DEFAULT FALSE'),
                ('recovery_email', 'VARCHAR(256)'),
                ('backup_codes', 'TEXT'),
                ('failed_logins', 'INTEGER DEFAULT 0'),
                ('locked_until', 'TIMESTAMP'),
            ],
            # Install-vs-upgrade split (see models_firmware.FirmwareImage).
            # Additive with a default, so every pre-existing row keeps meaning
            # exactly what it meant: an upgrade image.
            'firmware_images': [
                ('image_kind', "VARCHAR(16) DEFAULT 'upgrade'"),
                ('hypervisor', "VARCHAR(16) DEFAULT ''"),
            ],
            'appliances': [
                ('hw_type', "VARCHAR(16) DEFAULT 'unknown'"),
                ('model', 'VARCHAR(128)'),
                ('datasheet_filename', 'VARCHAR(256)'),
                ('firmware', 'VARCHAR(64)'),
                ('maintenance', 'BOOLEAN DEFAULT FALSE'),
            ],
            'managed_certificate': [
                ('superseded_at', 'TIMESTAMP'),
                ('revoked_at', 'TIMESTAMP'),
            ],
            'wpp_exceptions': [
                ('stale', 'BOOLEAN DEFAULT FALSE'),
                ('stale_reason', 'TEXT'),
            ],
            # --- product/ADOM separation (2026-07-07) ---
            'audit_logs': [
                ('product', "VARCHAR(32) DEFAULT ''"),
            ],
            'notifications': [
                ('product', "VARCHAR(32) DEFAULT ''"),
            ],
            'baselines': [
                ('product', "VARCHAR(32) DEFAULT 'fortiweb'"),
            ],
            'scheduled_action': [
                ('product', "VARCHAR(32) DEFAULT 'fortiweb'"),
            ],
            'db_reports': [
                ('builtin', 'BOOLEAN DEFAULT FALSE'),
            ],
            # --- Plugin Studio input parameters (selectors) ---
            'plugins': [
                ('params', "TEXT DEFAULT '[]'"),
            ],
            # --- Analytics: dashboard variables (one board, whole fleet) ---
            'monitor_dashboard': [
                ('variables', "TEXT DEFAULT ''"),
            ],
            # --- Deep monitors: box CPU / memory split out of the proxyd probe ---
            'monitor_panel': [
                ('vm_expr', 'VARCHAR(500)'),
                ('vm_legend', 'VARCHAR(120)'),
                ('vm_unit', 'VARCHAR(24)'),
            ],
            'monitor_probe': [
                ('warn_pct', 'INTEGER DEFAULT 80'),
                ('crit_pct', 'INTEGER DEFAULT 95'),
                # --- REST monitor API probes (sessions / throughput) ---
                ('warn_num', 'DOUBLE PRECISION DEFAULT 0'),
                ('crit_num', 'DOUBLE PRECISION DEFAULT 0'),
                # --- targeted, expiring suppression (2026-08-06) ---
                ('suppress_until', 'TIMESTAMP'),
                ('suppress_reason', "VARCHAR(200) DEFAULT ''"),
            ],
            # --- AppID-scoped API tokens (Phase 2 enforcement) ---
            'api_tokens': [
                ('capabilities', "TEXT DEFAULT '[]'"),
                ('app_ids', "TEXT DEFAULT '[]'"),
            ],
        }
        insp = inspect(db.engine)
        added: set[tuple[str, str]] = set()
        for table, cols in adds.items():
            try:
                if not insp.has_table(table):
                    continue
                existing = {c['name'] for c in insp.get_columns(table)}
                for col, ddl in cols:
                    if col not in existing:
                        db.session.execute(text(f'ALTER TABLE {table} ADD COLUMN {col} {ddl}'))
                        db.session.commit()
                        added.add((table, col))
            except Exception:  # noqa: BLE001 — never block boot on a migration
                db.session.rollback()

        # When the approval column is first introduced, existing templates
        # predate the workflow (admin-authored) -> treat them as APPROVED so the
        # fleet keeps working; new saves still default to 'pending'.
        if ('users', 'auth_source') in added:
            try:
                db.session.execute(text(
                    "UPDATE users SET auth_source='local' "
                    "WHERE auth_source IS NULL OR auth_source=''"))
                db.session.commit()
            except Exception:  # noqa: BLE001
                db.session.rollback()

        if ('templates', 'status') in added:
            try:
                db.session.execute(text(
                    "UPDATE templates SET status='approved' "
                    "WHERE status IS NULL OR status='' OR status='pending'"))
                db.session.commit()
            except Exception:  # noqa: BLE001
                db.session.rollback()

        # --- AppID goes GLOBAL (cross-product) 2026-07-09 ---
        # The catalog was keyed (product, app_id) with product='fortiweb'. AppIDs
        # now span FortiWeb + FortiADC, so the key is app_id alone and product is
        # the constant 'global'. Drop the old composite unique, collapse product,
        # add a name-only unique INDEX (distinct name so a fresh DB's model-level
        # UniqueConstraint never clashes). Best-effort; never blocks boot.
        try:
            if insp.has_table('app_ids'):
                db.session.execute(text(
                    'ALTER TABLE app_ids DROP CONSTRAINT IF EXISTS uq_appid_product_key'))
                db.session.execute(text(
                    "UPDATE app_ids SET product='global' WHERE product <> 'global'"))
                db.session.execute(text(
                    'CREATE UNIQUE INDEX IF NOT EXISTS ix_appid_uq ON app_ids (app_id)'))
                db.session.commit()
        except Exception:  # noqa: BLE001 — never block boot on a migration
            db.session.rollback()


    def _relax_probe_thresholds():
        """Let a probe say "inherit", and hand the never-chosen rows back.

        Two steps, both one-shot and both guarded, because they are the only
        migration in this file that CHANGES EXISTING DATA.

        1. ``warn_ms`` / ``tls_warn_days`` / ``stale_after_h`` were NOT NULL, so
           the column could not express "inherit" at all. (``warn_pct`` and the
           two ``*_num`` columns were already nullable in the database even
           though the model claimed otherwise.)

        2. Every probe created before 2026-08-06 was stamped with the discovery
           literal. Blanking a column that still holds EXACTLY that literal
           hands the row back to the scope default -- which is seeded to the
           same number, so behaviour is unchanged on the day of the migration
           and tunable from then on. A column holding anything else is a value
           somebody chose and is left alone; in particular a ``0`` means "never
           page me for this level" and inheriting over it would start paging.

        Guarded by a marker setting: without it, an operator who later sets a
        threshold back to exactly 80 would have it silently blanked on the next
        boot.
        """
        from sqlalchemy import inspect, text
        from .models import AppSetting, db as _db

        MARK = "thresholds.inherit_migrated"
        insp = inspect(_db.engine)
        if not insp.has_table("monitor_probe"):
            return
        for col in ("warn_ms", "tls_warn_days", "stale_after_h"):
            try:
                _db.session.execute(text(
                    "ALTER TABLE monitor_probe ALTER COLUMN %s DROP NOT NULL" % col))
                _db.session.commit()
            except Exception:  # noqa: BLE001 -- SQLite has no DROP NOT NULL
                _db.session.rollback()
        try:
            if AppSetting.get(MARK, "") == "1":
                return
        except Exception:  # noqa: BLE001
            return
        # (column, historical literal, kinds it applies to or None for all)
        plan = [
            ("warn_pct", "80", None), ("crit_pct", "95", None),
            ("warn_ms", "2000", None), ("tls_warn_days", "21", None),
            ("stale_after_h", "6", None),
            ("warn_num", "0", "NOT IN ('licence','tokens')"),
            ("crit_num", "0", "NOT IN ('licence','tokens')"),
            ("warn_num", "80", "IN ('licence','tokens')"),
            ("crit_num", "95", "IN ('licence','tokens')"),
        ]
        blanked = 0
        for col, lit, kinds in plan:
            try:
                sql = ("UPDATE monitor_probe SET %s = NULL WHERE %s = %s"
                       % (col, col, lit))
                if kinds:
                    sql += " AND kind %s" % kinds
                res = _db.session.execute(text(sql))
                blanked += int(res.rowcount or 0)
                _db.session.commit()
            except Exception:  # noqa: BLE001 -- never block boot on a migration
                _db.session.rollback()
        try:
            AppSetting.set(MARK, "1")
            _db.session.commit()
            app.logger.info("thresholds: %d probe threshold(s) handed back to "
                            "scope inheritance", blanked)
        except Exception:  # noqa: BLE001
            _db.session.rollback()

    def _ensure_indexes():
        """Create covering indexes on foreign-key columns that lack one.

        A FK with no index makes every join/lookup on it a sequential scan and
        makes the parent row's DELETE take a full-table lock scan — both bite as
        audit_log / change_history grow. ``CREATE INDEX IF NOT EXISTS`` is safe
        and idempotent on every boot (Postgres + SQLite)."""
        from sqlalchemy import inspect, text
        wanted = {
            'ix_audit_logs_user_id': ('audit_logs', 'user_id'),
            'ix_change_history_appliance_id': ('change_history', 'appliance_id'),
            'ix_bug_reports_resolved_by_id': ('bug_reports', 'resolved_by_id'),
        }
        try:
            insp = inspect(db.engine)
            tables = set(insp.get_table_names())
            for ixname, (table, col) in wanted.items():
                if table not in tables:
                    continue
                cols = {c['name'] for c in insp.get_columns(table)}
                if col not in cols:
                    continue
                db.session.execute(text(
                    f'CREATE INDEX IF NOT EXISTS {ixname} ON {table} ({col})'))
            db.session.commit()
        except Exception:  # noqa: BLE001 — never block boot on an index
            db.session.rollback()

    # -- database & seed --------------------------------------------------
    # Skippable so Alembic migration commands (and CI that manages its own
    # schema) can import the app without create_all racing the migration.
    if not os.environ.get("FORTINET_SKIP_DB_BOOTSTRAP"):
        with app.app_context():
            # Imported for its side effect: db.create_all() only creates tables
            # whose model class has been imported.
            from . import models_theme  # noqa: F401
            from . import models_analytics  # noqa: F401
            from . import models_sot  # noqa: F401
            from . import models_metrics  # noqa: F401
            from . import models_trust  # noqa: F401
            # Provisioning tables (hypervisor targets + run state machine).
            # Imported for its side effect: without this the models are dead
            # code, create_all() never makes the tables, and the feature 500s
            # the first time an operator opens it.
            from . import models_provision  # noqa: F401
            from . import models_advisor  # noqa: F401
            db.create_all()
            _ensure_columns()
            # After the additive pass: a column that already existed may be
            # narrower than the model now declares (see _ensure_widths).
            _ensure_widths()
            _relax_probe_thresholds()
            _ensure_indexes()
            _seed_profiles()
            _seed_admin()
            _assign_missing_profiles()
            _seed_registry()
            _seed_acme_providers()
            _seed_adoms()
            _seed_themes()
            _seed_analytics_boards()
            _seed_capacity()
            if not app.config.get("TESTING"):
                _seed_reports()

    # -- orphaned background jobs ------------------------------------------
    # A restart kills job worker threads without touching their state files,
    # leaving forever-"running" ghosts in the Job Manager. Sweep them to a
    # terminal error at boot (idempotent; any booting worker may run it).
    if not app.config.get("TESTING"):
        try:
            from .services import jobs as _jobsvc
            swept = _jobsvc.sweep_orphans()
            if swept:
                app.logger.warning("swept %d orphaned background job(s): %s",
                                   len(swept), [j["id"] for j in swept])
        except Exception:  # noqa: BLE001 — never block boot on housekeeping
            app.logger.exception("orphaned-job sweep failed")

    # -- legacy URL compatibility: the FortiWeb area moved under /web/ ------
    # (2026-07-07 ADOM split). Old deep-links, hardcoded JS fetches and the
    # test suite keep working: the WSGI layer transparently rewrites the old
    # top-level paths onto the /web prefix (no redirect, same endpoints).
    _legacy_web = (
        '/workspace', '/objedit', '/regex-lab', '/server-objects',
        '/web-protection', '/exceptions', '/backups', '/logs',
        '/import-backup', '/configuration', '/section-catalog', '/templates',
        '/signatures', '/structure', '/classification', '/segments',
        '/naming', '/scheduled-actions', '/change-requests', '/provisioning',
        '/firmware', '/release-notes', '/capacity', '/registry',
        '/api-explorer',
    )
    _inner_wsgi = app.wsgi_app

    def _legacy_web_rewrite(environ, start_response):
        path = environ.get('PATH_INFO', '') or ''
        for pref in _legacy_web:
            if path == pref or path.startswith(pref + '/'):
                environ['PATH_INFO'] = '/web' + path
                break
        return _inner_wsgi(environ, start_response)

    app.wsgi_app = _legacy_web_rewrite

    return app


def _register_blueprints(app: Flask) -> None:
    """Import and register all blueprints. Missing blueprint modules are
    skipped with a warning so the core app still starts during scaffolding."""
    import importlib
    import logging

    logger = logging.getLogger(__name__)

    blueprints = [
        ("app.auth", "bp"),
        ("app.views.product", "bp"),
        ("app.views.adc", "bp"),
        ("app.views.adc_api", "bp"),
        ("app.views.faz", "bp"),
        ("app.views.faz_api", "bp"),
        ("app.views.fac", "bp"),
        ("app.views.fac_api", "bp"),
        ("app.views.appliances", "bp"),
        ("app.views.firmware", "bp"),
        ("app.views.jobs", "bp"),
        ("app.views.notifications", "bp"),
        ("app.views.release_notes", "bp"),
        ("app.views.workspace", "bp"),
        ("app.views.objedit", "bp"),
        ("app.views.regex_lab", "bp"),
        ("app.views.server_objects", "bp"),
        ("app.views.web_protection", "bp"),
        ("app.views.exceptions", "bp"),
        ("app.views.architecture", "bp"),
        ("app.views.analysis", "bp"),
        ("app.views.backups", "bp"),
        ("app.views.logs", "bp"),
        ("app.views.search", "bp"),
        ("app.views.dns_tool", "bp"),
        ("app.views.users", "bp"),
        ("app.views.profiles", "bp"),
        ("app.views.metrics", "bp"),
        ("app.views.monitoring", "bp"),
        ("app.views.deep_monitor", "bp"),
        ("app.views.service_monitor", "bp"),
        ("app.views.monitor_analytics", "bp"),
        ("app.views.monitor_reports", "bp"),
        ("app.views.metrics_admin", "bp"),
        ("app.views.capacity", "bp"),
        ("app.views.audit", "bp"),
        ("app.views.registry", "bp"),
        ("app.views.api_explorer", "bp"),
        ("app.views.templates", "bp"),
        ("app.views.signatures", "bp"),
        ("app.views.fleet_objects", "bp"),
        ("app.views.import_backup", "bp"),
        ("app.views.structure", "bp"),
        ("app.views.classification", "bp"),
        ("app.views.segments", "bp"),
        ("app.views.naming", "bp"),
        ("app.views.scheduled_actions", "bp"),
        ("app.views.cert_manager", "bp"),
        ("app.views.change_requests", "bp"),
        ("app.views.provisioning", "bp"),
        ("app.views.device_provision", "bp"),
        ("app.views.section_config", "bp"),
        ("app.views.section_catalog", "bp"),
        ("app.views.settings", "bp"),
        ("app.views.reports", "bp"),
        ("app.views.locks", "bp"),
        ("app.views.database", "bp"),
        ("app.views.system_backup", "bp"),
        ("app.views.self_update", "bp"),
        ("app.views.ha", "bp"),
        ("app.views.plugins", "bp"),
        ("app.views.lua_studio", "bp"),
        ("app.api", "bp"),
        ("app.api_v1", "bp"),
        ("app.views.api_tokens", "bp"),
        ("app.views.appids", "bp"),
        ("app.views.advisor", "bp"),
    ]

    # FortiWeb-scoped areas live under the /web ADOM prefix (2026-07-07).
    # url_for() picks the prefix up automatically; legacy top-level paths are
    # rewritten by the WSGI shim in create_app so old links/tests keep working.
    web_prefixed = {
        "app.views.workspace", "app.views.objedit", "app.views.regex_lab",
        "app.views.server_objects", "app.views.web_protection",
        "app.views.exceptions", "app.views.backups", "app.views.logs",
        "app.views.import_backup", "app.views.section_config",
        "app.views.section_catalog", "app.views.templates",
        "app.views.signatures", "app.views.structure",
        "app.views.classification", "app.views.segments", "app.views.naming",
        "app.views.scheduled_actions", "app.views.change_requests",
        "app.views.provisioning", "app.views.firmware",
        "app.views.release_notes", "app.views.capacity",
        "app.views.registry", "app.views.api_explorer",
        "app.views.appids",
    }
    for module_path, attr in blueprints:
        try:
            module = importlib.import_module(module_path)
            bp = getattr(module, attr)
            if module_path in web_prefixed:
                app.register_blueprint(bp, url_prefix='/web' + (bp.url_prefix or ''))
            else:
                app.register_blueprint(bp)
        except ModuleNotFoundError:
            logger.debug("Blueprint module %r not found — skipping.", module_path)
        except AttributeError:
            logger.warning(
                "Blueprint attribute %r not found in %r — skipping.",
                attr,
                module_path,
            )


def _seed_profiles() -> None:
    """Upsert the three system profiles. Their permission sets are re-synced
    from code on every boot so adding a new granular key automatically extends
    the admin (and, where applicable, operator/readonly) system profiles."""
    from . import permissions as perm
    from .models import Profile

    try:
        for name, keys in perm.SYSTEM_PROFILES.items():
            p = Profile.query.filter_by(name=name).first()
            if p is None:
                p = Profile(name=name, is_system=True)
                db.session.add(p)
            p.is_system = True
            p.description = perm.SYSTEM_PROFILE_META.get(name, "")
            p.permission_set = set(keys)
        db.session.commit()
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()



def _seed_reports() -> None:
    """Insert-only seed of the curated builtin reports (never overwrites an
    existing builtin; operator clones survive). Never blocks boot."""
    import logging
    try:
        from .services import report_builder
        created = report_builder.seed_builtin_reports()
        if created:
            logging.getLogger(__name__).info(
                "Report seed: %d builtin reports imported", created)
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()


def _seed_capacity() -> None:
    """Insert-only seed of published capacity limits from capacity_seed.json
    (admin edits are never touched; see services.capacity.seed_from_json)."""
    import logging
    try:
        from .services import capacity
        added = capacity.seed_from_json()
        if added:
            logging.getLogger(__name__).info(
                "Capacity seed: %d limit rows imported", added)
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()


def _assign_missing_profiles() -> None:
    """Give every user that still has no profile the system profile matching
    their legacy ``role`` (one-time migration; new users get a profile at
    creation time)."""
    from . import permissions as perm
    from .models import Profile, User

    try:
        by_name = {p.name: p for p in Profile.query.filter_by(is_system=True).all()}
        changed = False
        for u in User.query.filter(User.profile_id.is_(None)).all():
            target = by_name.get(perm.role_to_profile_name(u.role))
            if target is not None:
                u.profile_id = target.id
                changed = True
        if changed:
            db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()


def _seed_admin() -> None:
    """Create a default admin user if the users table is empty."""
    from .models import Role, User
    from sqlalchemy.exc import IntegrityError

    if User.query.first() is not None:
        return

    admin = User(
        username="admin",
        role=Role.admin.value,
        created_at=datetime.utcnow(),
        is_active=True,
    )
    admin.set_password("Sopas123.-")
    db.session.add(admin)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return  # Another worker seeded first — that's fine


def _seed_acme_providers() -> None:
    """Insert-only seed of the ACME DNS-01 provider catalog from the
    git-tracked ``acme_providers.yaml``. Operator edits (renamed env vars,
    custom providers, disabled rows) are never overwritten — same contract as
    the endpoint registry."""
    import logging

    try:
        from .services import acme_providers
        added = acme_providers.seed_from_yaml()
        if added:
            logging.getLogger(__name__).info(
                "ACME seed: %d DNS providers imported from acme_providers.yaml",
                added)
        # The catalog is only useful if every `flag` is a code the installed
        # client implements; repair the rows we shipped with a stale one.
        repaired = acme_providers.repair_stale_flags()
        if repaired:
            logging.getLogger(__name__).warning(
                "ACME seed: repaired %d provider flag(s) the client rejects",
                repaired)
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()


def _seed_adoms() -> None:
    """Insert-only seed of the ADOM registry (``adoms`` table) from the
    canonical defaults in ``branding._FALLBACK``. Operator edits are never
    touched (seed is keyed by ADOM ``key``); see ``branding.seed_defaults``."""
    import logging
    try:
        from .branding import seed_defaults
        added = seed_defaults()
        if added:
            logging.getLogger(__name__).info(
                "ADOM seed: %d ADOMs imported into the registry", added)
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()


def _seed_analytics_boards() -> None:
    """Reconcile the built-in analytics boards from code.

    RECONCILED, not insert-only — the opposite of the theme seed, and for a
    reason worth stating. A built-in board carries no operator intent to
    preserve: the UI refuses to edit or delete one, so any difference between
    the row and the code is drift, not a decision. Reconciling means a board
    improved in a release reaches installations that already have it, instead
    of freezing at whatever shipped first. Operator-authored boards (``builtin``
    false) are never touched.

    The panels use RULE selection rather than probe ids so a fresh install with
    no probes yet still gets working boards: the rules resolve to nothing today
    and to every matching probe the moment Discover creates them.
    """
    from .models import db
    from .models_analytics import MonitorDashboard, MonitorPanel

    boards = [
        {
            # The ONLY board that works at fleet scale. Rule panels enumerate
            # probe rows; at 100 devices x 750 policies there are no probe rows
            # to enumerate — the metrics store holds those series and answers
            # by SELECTOR. topk() bounds every panel to what a chart can show.
            "slug": "fleet-metrics", "title": "Fleet metrics (store)",
            "position": 5, "product": "",
            "description": "Selector-driven view of the local metrics store — "
                           "scales to the whole fleet because nothing here "
                           "enumerates series by hand.",
            "default_range": "24h",
            "mode": "metricsql",
            # Only metrics EVERY product with a box collector reports. The
            # throughput and per-policy panels moved to the FortiWeb board on
            # 2026-08-06: a built-in seeded with product "" is visible in every
            # ADOM, so an identity ADOM was rendering four panels whose series
            # its devices can never emit — empty charts that read as "quiet",
            # not as "not applicable".
            "panels": [
                {"title": "CPU used — all devices", "viz": "line", "width": 6,
                 "vm_expr": "satom_box_cpu_pct", "vm_unit": "%",
                 "vm_legend": "device", "show_band": False},
                {"title": "Memory used — all devices", "viz": "line", "width": 6,
                 "vm_expr": "satom_box_mem_pct", "vm_unit": "%",
                 "vm_legend": "device", "show_band": False},
                {"title": "Collectors failing", "viz": "line", "width": 12,
                 "vm_expr": "sum by (collector) (satom_scrape_up == 0)",
                 "vm_unit": "targets", "vm_legend": "collector",
                 "show_band": False},
            ],
        },
        {
            # The panels that left fleet-metrics. Product-scoped, so they show
            # up in the FortiWeb ADOM and nowhere else.
            "slug": "fortiweb-traffic-store",
            "title": "Traffic & policies (store)", "position": 6,
            "product": "fortiweb",
            "description": "Throughput and per-policy load read by SELECTOR "
                           "from the metrics store — the only shape that "
                           "survives a fleet with hundreds of policies.",
            "default_range": "24h",
            "mode": "metricsql",
            "panels": [
                {"title": "Device throughput", "viz": "area", "width": 12,
                 "vm_expr": 'satom_total_throughput_bps{kind="fortiweb"}',
                 "vm_unit": "bit/s", "vm_legend": "device", "show_band": False},
                {"title": "Busiest policies (top 10 by conn/s)", "viz": "line",
                 "width": 12,
                 "vm_expr": 'topk(10, satom_policy_conn_per_sec{kind="fortiweb"})',
                 "vm_unit": "conn/s", "show_band": False},
                {"title": "Policies with every backend down", "viz": "line",
                 "width": 12,
                 "vm_expr": 'sum by (device) (satom_policy_up{kind="fortiweb"} == 0)',
                 "vm_unit": "policies", "vm_legend": "device",
                 "show_band": False},
            ],
        },
        {
            # FortiAuthenticator's equivalent of a traffic board. An identity
            # unit has no throughput to plot; what it runs out of is
            # ENTITLEMENT, and that cliff is invisible on a CPU chart.
            "slug": "fac-entitlement", "title": "Entitlement & tokens",
            "position": 7, "product": "fortiauthenticator",
            "description": "Licence headroom and FortiToken pools — the "
                           "ceilings this product actually hits.",
            "default_range": "7d",
            "mode": "metricsql",
            "panels": [
                {"title": "Licence consumed", "viz": "line", "width": 6,
                 "vm_expr": "satom_fac_licence_pct", "vm_unit": "%",
                 "vm_legend": "resource", "show_band": False},
                {"title": "Licence seats free", "viz": "line", "width": 6,
                 "vm_expr": "satom_fac_licence_total - satom_fac_licence_used",
                 "vm_unit": "seats", "vm_legend": "resource",
                 "show_band": False},
                {"title": "FortiToken pool consumed", "viz": "line", "width": 6,
                 "vm_expr": "satom_fac_token_pct", "vm_unit": "%",
                 "vm_legend": "pool", "show_band": False},
                {"title": "HA peer present", "viz": "line", "width": 6,
                 "vm_expr": "satom_fac_ha_peer", "vm_unit": "peer",
                 "vm_legend": "device", "show_band": False},
                {"title": "Collectors failing", "viz": "line", "width": 12,
                 "vm_expr": 'sum by (collector) (satom_scrape_up{kind="fortiauthenticator"} == 0)',
                 "vm_unit": "targets", "vm_legend": "collector",
                 "show_band": False},
            ],
        },
        {
            # Rule-driven and cross-product: CPU/memory probes exist
            # on every product that has a box, and probe visibility is
            # already ADOM-scoped, so this board is correct anywhere.
            "slug": "fleet-overview", "title": "Fleet overview", "position": 10, "product": "",
            "description": "Processor, memory and availability across every "
                           "monitored appliance.",
            "default_range": "24h",
            "panels": [
                {"title": "CPU used", "viz": "line", "rule_kind": "cpu",
                 "width": 6, "show_band": True},
                {"title": "Memory used", "viz": "line", "rule_kind": "memory",
                 "width": 6, "show_band": True},
                {"title": "Availability by probe", "viz": "heatmap",
                 "rule_kind": "cpu", "width": 12, "height": 240},
                {"title": "Peak CPU", "viz": "stat", "rule_kind": "cpu",
                 "stat_func": "max", "width": 4, "height": 190,
                 "compare_prev": True},
                {"title": "Peak memory", "viz": "stat", "rule_kind": "memory",
                 "stat_func": "max", "width": 4, "height": 190,
                 "compare_prev": True},
                {"title": "Healthy %", "viz": "stat", "rule_kind": "cpu",
                 "stat_func": "healthy_pct", "width": 4, "height": 190,
                 "compare_prev": True},
            ],
        },
        {
            # FortiWeb-only: throughput, per-policy sessions and HTTP
            # transactions all come from the FortiWeb monitor API.
            "slug": "traffic", "title": "Traffic & sessions", "position": 20, "product": "fortiweb",
            "description": "Throughput, concurrent sessions and HTTP "
                           "transactions read from the appliance monitor API.",
            "default_range": "24h",
            "panels": [
                {"title": "Throughput", "viz": "area", "rule_kind": "throughput",
                 "width": 12, "show_band": True, "show_v2": True},
                {"title": "Sessions per policy", "viz": "line",
                 "rule_kind": "policy_sessions", "width": 6},
                {"title": "Box sessions", "viz": "line", "rule_kind": "sessions",
                 "width": 6},
                {"title": "HTTP transactions", "viz": "bar",
                 "rule_kind": "transactions", "width": 12, "height": 240},
            ],
        },
        {
            # FortiWeb-only: proxyd has no counterpart on any other
            # product (no REST endpoint anywhere exposes process
            # state) and interface drift reads the FortiWeb harvest.
            "slug": "service-health", "title": "Service health", "position": 30, "product": "fortiweb",
            "description": "Synthetic response time, the proxyd daemon and "
                           "interface drift.",
            "default_range": "7d",
            "panels": [
                {"title": "Response time", "viz": "line", "rule_kind": "https",
                 "width": 8, "show_band": True},
                {"title": "Slowest response", "viz": "stat", "rule_kind": "https",
                 "stat_func": "max", "width": 4, "height": 190},
                {"title": "proxyd memory", "viz": "line", "rule_kind": "proxyd",
                 "width": 6, "show_v2": True},
                {"title": "Interface drift", "viz": "status",
                 "rule_kind": "interface", "width": 6, "height": 220},
                {"title": "Probe summary", "viz": "table", "rule_kind": "https",
                 "width": 12, "height": 260},
            ],
        },
        {
            # Rule-driven counterpart of fac-entitlement: reads the licence and
            # token PROBES, so it carries their thresholds and their graded
            # verdict rather than a raw series.
            "slug": "fac-identity", "title": "Identity health", "position": 40,
            "product": "fortiauthenticator",
            "description": "Licence and FortiToken probes, with the thresholds "
                           "the operator set on them.",
            "default_range": "7d",
            "panels": [
                {"title": "Licence consumed", "viz": "line",
                 "rule_kind": "licence", "width": 6, "show_band": True},
                {"title": "FortiToken pools", "viz": "line",
                 "rule_kind": "tokens", "width": 6, "show_band": True},
                {"title": "Peak licence use", "viz": "stat",
                 "rule_kind": "licence", "stat_func": "max", "width": 4,
                 "height": 190, "compare_prev": True},
                {"title": "Processor", "viz": "line", "rule_kind": "cpu",
                 "width": 4, "height": 190},
                {"title": "Memory", "viz": "line", "rule_kind": "memory",
                 "width": 4, "height": 190},
                {"title": "Probe summary", "viz": "table",
                 "rule_kind": "licence", "width": 12, "height": 260},
            ],
        },
        {
            # ONE board for every device in the fleet. The device moves out of
            # the panels and into a picker, so fifty appliances are fifty
            # SELECTIONS rather than fifty boards to build and keep in step.
            # Every panel is store-backed and filtered by $device.
            "slug": "device-drilldown", "title": "Device drill-down",
            "position": 7, "product": "",
            "description": "Everything the store knows about ONE appliance. "
                           "Pick the device above — the board is the same for "
                           "all of them, so a newly onboarded appliance needs "
                           "no new board.",
            "default_range": "24h",
            "mode": "metricsql",
            "variables": [
                {"name": "device", "label": "Device", "label_key": "device"},
            ],
            "panels": [
                {"title": "CPU used", "viz": "line", "width": 6,
                 "vm_expr": 'satom_box_cpu_pct{device=~"$device"}',
                 "vm_unit": "%", "vm_legend": "device", "show_band": False},
                {"title": "Memory used", "viz": "line", "width": 6,
                 "vm_expr": 'satom_box_mem_pct{device=~"$device"}',
                 "vm_unit": "%", "vm_legend": "device", "show_band": False},
                {"title": "Concurrent sessions", "viz": "line", "width": 6,
                 "vm_expr": 'satom_box_sessions{device=~"$device"}',
                 "vm_unit": "sessions", "vm_legend": "device",
                 "show_band": False},
                {"title": "New connections / s", "viz": "line", "width": 6,
                 "vm_expr": 'satom_box_conn_per_sec{device=~"$device"}',
                 "vm_unit": "conn/s", "vm_legend": "device",
                 "show_band": False},
                {"title": "Interfaces down", "viz": "line", "width": 6,
                 "vm_expr": 'sum by (device) (satom_iface_up{device=~"$device"} == 0)',
                 "vm_unit": "ports", "vm_legend": "device", "show_band": False},
                {"title": "Published services", "viz": "line", "width": 6,
                 "vm_expr": 'satom_policy_count{device=~"$device"}',
                 "vm_unit": "services", "vm_legend": "device",
                 "show_band": False},
                # Absence is not health: a collector that stops answering has
                # to be visible on the device's own board, not only on Fleet.
                {"title": "Collectors failing", "viz": "line", "width": 12,
                 "vm_expr": 'sum by (collector) (satom_scrape_up{device=~"$device"} == 0)',
                 "vm_unit": "collectors", "vm_legend": "collector",
                 "show_band": False, "height": 220},
            ],
        },
        {
            # The per-service view, and the reason variables CHAIN: $policy is
            # enumerated with a match that already references $device, so the
            # policy picker offers only services that exist on the selected
            # appliance instead of every policy in the fleet.
            "slug": "service-drilldown", "title": "Service drill-down",
            "position": 8, "product": "",
            "description": "One published service — FortiWeb server policy or "
                           "FortiADC virtual server. The policy picker is "
                           "scoped to the device picked above.",
            "default_range": "24h",
            "mode": "metricsql",
            "variables": [
                {"name": "device", "label": "Device", "label_key": "device",
                 "match": 'satom_policy_up'},
                {"name": "policy", "label": "Service", "label_key": "policy",
                 "match": 'satom_policy_up{device=~"$device"}'},
            ],
            "panels": [
                {"title": "Service up", "viz": "status", "width": 12,
                 "height": 200,
                 "vm_expr": 'satom_policy_up{device=~"$device",policy=~"$policy"}',
                 "vm_unit": "up", "vm_legend": "policy", "show_band": False},
                {"title": "Sessions", "viz": "line", "width": 6,
                 "vm_expr": 'satom_policy_sessions{device=~"$device",policy=~"$policy"}',
                 "vm_unit": "sessions", "vm_legend": "policy",
                 "show_band": False},
                {"title": "Connections / s", "viz": "line", "width": 6,
                 "vm_expr": 'satom_policy_conn_per_sec{device=~"$device",policy=~"$policy"}',
                 "vm_unit": "conn/s", "vm_legend": "policy",
                 "show_band": False},
                {"title": "Client RTT", "viz": "line", "width": 4,
                 "vm_expr": 'satom_policy_client_rtt_ms{device=~"$device",policy=~"$policy"}',
                 "vm_unit": "ms", "vm_legend": "policy", "show_band": False},
                {"title": "Server RTT", "viz": "line", "width": 4,
                 "vm_expr": 'satom_policy_server_rtt_ms{device=~"$device",policy=~"$policy"}',
                 "vm_unit": "ms", "vm_legend": "policy", "show_band": False},
                {"title": "App response", "viz": "line", "width": 4,
                 "vm_expr": 'satom_policy_app_response_ms{device=~"$device",policy=~"$policy"}',
                 "vm_unit": "ms", "vm_legend": "policy", "show_band": False},
                {"title": "Throughput", "viz": "area", "width": 12,
                 "vm_expr": 'satom_policy_throughput_bps{device=~"$device",policy=~"$policy"}',
                 "vm_unit": "bps", "vm_legend": "policy", "show_band": False},
            ],
        },
    ]

    changed = False
    for spec in boards:
        panels = spec.pop("panels")
        mode = spec.pop("mode", "rule")
        # Variables are stored as JSON text. Dumping through the parser (rather
        # than json.dumps on the literal) means a malformed built-in definition
        # is caught here, at boot, instead of rendering a picker that changes
        # nothing.
        from .services.dashboard_vars import dump as _dump_vars
        spec["variables"] = _dump_vars(spec.pop("variables", []))
        board = MonitorDashboard.query.filter_by(slug=spec["slug"]).first()
        if board is None:
            board = MonitorDashboard(slug=spec["slug"], builtin=True, product="")
            db.session.add(board)
            changed = True
        elif not board.builtin:
            # An operator board took this slug. Theirs wins; the built-in is
            # simply not reconciled rather than silently overwritten.
            continue
        for key, val in spec.items():
            if getattr(board, key, None) != val:
                setattr(board, key, val)
                changed = True
        board.builtin = True
        db.session.flush()

        # Panels are replaced wholesale. Diffing them would need a stable
        # identity a built-in panel does not have (its title is the only
        # candidate and titles change between releases), and the board is
        # read-only anyway, so there is nothing an operator could lose.
        existing = list(board.panels)
        want = [dict(pos=i * 10, **p) for i, p in enumerate(panels)]
        if len(existing) != len(want) or _panels_differ(existing, want):
            for old in existing:
                db.session.delete(old)
            db.session.flush()
            for item in want:
                item = dict(item)
                pos = item.pop("pos")
                db.session.add(MonitorPanel(
                    dashboard_id=board.id, position=pos,
                    select_mode=mode, **item))
            changed = True
    if changed:
        db.session.commit()


def _panels_differ(existing, want) -> bool:
    """True when a built-in board's panels no longer match the code."""
    for old, new in zip(existing, want):
        for key, val in new.items():
            if key == "pos":
                continue
            if getattr(old, key, None) != val:
                return True
    return False


def _seed_themes() -> None:
    """Insert-only seed of the built-in UI themes (``ui_themes`` table).

    Operator-created themes are never touched (seed is keyed by ``slug``), and
    the built-ins cannot be edited or deleted — they are the recovery path when
    a custom palette makes the console unreadable.
    """
    import logging
    try:
        from .services.theme_service import seed_defaults
        added = seed_defaults()
        if added:
            logging.getLogger(__name__).info(
                "Theme seed: %d built-in themes imported", added)
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()


def _seed_registry() -> None:
    """Insert-only seed of the endpoint registry from the git-tracked
    ``endpoints.yaml`` (rows already in the DB — operator edits, disables —
    are never touched; see ``registry.loader.seed_from_yaml``)."""
    import logging

    try:
        from .registry import loader
        added = loader.seed_from_yaml()
        if added:
            logging.getLogger(__name__).info(
                "Registry seed: %d endpoints imported from endpoints.yaml", added)
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()
    try:
        from .registry import loader
        added = loader.seed_adc_from_yaml()
        if added:
            logging.getLogger(__name__).info(
                "Registry seed: %d FortiADC endpoints imported from "
                "endpoints_fortiadc.yaml", added)
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()
    try:
        from .registry import loader
        added = loader.seed_faz_from_yaml()
        if added:
            logging.getLogger(__name__).info(
                "Registry seed: %d FortiAnalyzer endpoints imported from "
                "endpoints_fortianalyzer.yaml", added)
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()
    try:
        from .registry import loader
        added = loader.seed_fac_from_yaml()
        if added:
            logging.getLogger(__name__).info(
                "Registry seed: %d FortiAuthenticator endpoints imported from "
                "endpoints_fortiauthenticator.yaml", added)
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()
