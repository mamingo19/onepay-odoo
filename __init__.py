# Part of Odoo. See LICENSE file for full copyright and licensing details.

from . import controllers
from . import models

from odoo.addons.payment import setup_provider, reset_payment_provider


# Define a function to be called after the module is installed
def post_init_hook(env):
    # Setup the payment provider for "vnpay"
    setup_provider(env, "onepay")
    # Search for the "vnpay" provider in the "payment.provider" model
    payment_onepay = env["payment.provider"].search([("code", "=", "onepay")], limit=1)
    # Search for the "vnpay" method in the "payment.method" model
    payment_method_onepay = env["payment.method"].search(
        [("code", "=", "onepay")], limit=1
    )
    # Link the found payment method to the found payment provider
    if payment_method_onepay.id is not False:
        payment_onepay.write(
            {
                "payment_method_ids": [(6, 0, [payment_method_onepay.id])],
            }
        )


# Define a function to be called when the module is uninstalled
def uninstall_hook(env):
    # Reset the payment provider for "vnpay"
    reset_payment_provider(env, "vnpay")