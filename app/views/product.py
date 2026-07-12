"""Product / ADOM selection gate (Global vs FortiWeb vs FortiADC)."""
from __future__ import annotations

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from ..branding import PRODUCTS, get_product, is_valid

bp = Blueprint('product', __name__, url_prefix='/product')


def _home_for(key: str):
    if key == 'global':
        return redirect(url_for('index'))
    if key == 'fortiadc':
        return redirect(url_for('adc.index'))
    if get_product(key).get('placeholder'):
        # Placeholder ADOMs (FortiAuthenticator / FortiAnalyzer / future) have
        # no backend yet — land on the shared scaffold dashboard.
        return redirect(url_for('product.placeholder_home'))
    return redirect(url_for('fortiweb_home'))


@bp.route('/select')
@login_required
def select():
    """Landing gate shown until a product is chosen for the session."""
    return render_template('product/select.html', products=PRODUCTS)


@bp.route('/select', methods=['POST'])
@login_required
def set_product():
    choice = request.form.get('product', '')
    if not is_valid(choice):
        return redirect(url_for('product.select'))
    session['product'] = choice
    session.permanent = True
    return _home_for(choice)


@bp.route('/enter/<key>')
@login_required
def enter(key):
    """ADOM jump — switch the session product and land on that ADOM's home."""
    if _is_prefetch(request):
        # Turbo/browser link prefetch (hover). A prefetch must never switch
        # the ADOM — respond empty and uncacheable; a real click re-requests.
        return '', 204
    if not is_valid(key):
        return redirect(url_for('product.select'))
    session['product'] = key
    session.permanent = True
    return _home_for(key)


def _is_prefetch(req):
    """True when the request is a speculative prefetch (Turbo sends
    X-Sec-Purpose: prefetch; browsers use Sec-Purpose/Purpose)."""
    vals = (req.headers.get('X-Sec-Purpose', '')
            + ' ' + req.headers.get('Sec-Purpose', '')
            + ' ' + req.headers.get('Purpose', ''))
    return 'prefetch' in vals.lower()


@bp.route('/switch')
@login_required
def switch():
    """Clear the current product and return to the selection gate."""
    session.pop('product', None)
    return redirect(url_for('product.select'))


@bp.route('/fortiadc')
@login_required
def fortiadc_home():
    """Legacy entry point — the ADC area now has a real dashboard."""
    return redirect(url_for('adc.index'))


@bp.route('/home')
@login_required
def placeholder_home():
    """Scaffold dashboard shared by every placeholder ADOM (branding-driven).

    The active product is resolved by the app-factory context processor, so a
    single template renders whichever placeholder ADOM the session is in. A
    concrete ADOM lands on its real home instead."""
    prod = get_product(session.get('product'))
    if not prod.get('placeholder'):
        return _home_for(prod.get('key'))
    return render_template('product/placeholder.html')
