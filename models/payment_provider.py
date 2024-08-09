import logging
import pprint

import requests
import hmac
import hashlib
from werkzeug.utils import redirect
import urllib.parse

from odoo import _, api, fields, models
from odoo.exceptions import ValidationError
from odoo.addons.onepay_payment import const

_logger = logging.getLogger(__name__)

class PaymentProviderOnePay(models.Model):
    _inherit = "payment.provider"

    # Add 'OnePay' as a new payment provider
    code = fields.Selection(
        selection_add=[("onepay", "OnePay")], ondelete={"onepay": "set default"}
    )

    # Define fields for OnePay's Merchant ID, Access Code, and Secret Key
    onepay_merchant_id = fields.Char(
        string="Merchant ID", default="TESTONEPAY", required_if_provider="onepay"
    )
    onepay_access_code = fields.Char(
        string="Access Code",default="6BEB2546", required_if_provider="onepay"
    )
    onepay_secret_key = fields.Char(
        string="Secret Key",default="6D0870CDE5F24F34F3915FB0045120DB", required_if_provider="onepay"
    )

    @api.model
    def _get_compatible_providers(
         self, *args, currency_id=None, is_validation=False, **kwargs
    ):

        providers = super()._get_compatible_providers(
            *args, currency_id=currency_id, is_validation=is_validation, **kwargs
        )

        currency = self.env["res.currency"].browse(currency_id).exists()
       
        if (
            currency and currency.name not in const.SUPPORTED_CURRENCIES
        ) or is_validation:
            providers = providers.filtered(lambda p: p.code != "onepay")

        return providers

    def _get_supported_currencies(self):
        """Override to return the supported currencies."""
        supported_currencies = super()._get_supported_currencies()
        if self.code == "vnpay":
            supported_currencies = supported_currencies.filtered(
                lambda c: c.name in const.SUPPORTED_CURRENCIES
            )
        return supported_currencies

    def _get_payment_url(self, params, secret_key):
        """Generate the payment URL for OnePay"""
        base_url = "https://mtf.onepay.vn/paygate/vpcpay.op?"
        inputData = sorted(params.items())
        queryString = ""
        seq = 0
        for key, val in inputData:
            if seq == 1:
                queryString = queryString + "&" + key + "=" + urllib.parse.quote_plus(str(val))
            else:
                seq = 1
                queryString = key + "=" + urllib.parse.quote_plus(str(val))

        hashValue = self.hmac_sha256(secret_key, queryString)
    # The final URL will be like this:
        return base_url + queryString + "&vpc_SecureHash=" + hashValue

    @staticmethod
    def hmac_sha256(key, data):
        """Generate a HMAC SHA256 hash"""

        byteKey = key.encode("utf-8")
        byteData = data.encode("utf-8")
        return hmac.new(byteKey, byteData, hashlib.sha256).hexdigest()

    def _get_default_payment_method_codes(self):
        """Override of `payment` to return the default payment method codes."""

        default_codes = super()._get_default_payment_method_codes()
        if self.code != "vnpay":
            return default_codes
        return const.DEFAULT_PAYMENT_METHODS_CODES
