"""Product selection gate (FortiWeb vs FortiADC)."""
from __future__ import annotations

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from ..branding import PRODUCTS, is_valid

bp = Blueprint('product', __name__, url_prefix='/product')


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
    if choice == 'fortiadc':
        return redirect(url_for('product.fortiadc_home'))
    return redirect(url_for('workspace.index'))


@bp.route('/switch')
@login_required
def switch():
    """Clear the current product and return to the selection gate."""
    session.pop('product', None)
    return redirect(url_for('product.select'))


@bp.route('/fortiadc')
@login_required
def fortiadc_home():
    """FortiADC placeholder dashboard — basic structure only."""
    return render_template('product/fortiadc.html')
