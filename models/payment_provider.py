import logging
import requests
import hmac
import hashlib
import urllib.parse
from odoo import _, api, fields, models
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
        string="Access Code", default="6BEB2546", required_if_provider="onepay"
    )
    onepay_secret_key = fields.Char(
        string="Secret Key", default="6D0870CDE5F24F34F3915FB0045120DB", required_if_provider="onepay"
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
        if self.code == "onepay":
            supported_currencies = supported_currencies.filtered(
                lambda c: c.name in const.SUPPORTED_CURRENCIES
            )
        return supported_currencies

    def _get_payment_url(self, params, secret_key):
        """Generate the payment URL for OnePay"""
        params_sorted = self.sort_param(params)
        string_to_hash = self.generate_string_to_hash(params_sorted)
        _logger.debug("merchant's string to hash: %s", string_to_hash)
        secure_hash = self.generate_secure_hash(string_to_hash, secret_key)
        params_sorted['vpc_SecureHash'] = secure_hash

        query_string = urllib.parse.urlencode(params_sorted)
        payment_url = f"https://mtf.onepay.vn/paygate/vpcpay.op?{query_string}"
        
        print(f"Print out this for me: {payment_url}")
        return payment_url

    @staticmethod
    def sort_param(params):
        return dict(sorted(params.items()))

    @staticmethod
    def generate_string_to_hash(params_sorted):
        string_to_hash = ""
        for key, value in params_sorted.items():
            prefix_key = key[0:4]
            if (prefix_key == "vpc_" or prefix_key == "user"):
                if (key != "vpc_SecureHashType" and key != "vpc_SecureHash"):
                    value_str = str(value)
                    if (len(value_str) > 0):
                        if (len(string_to_hash) > 0):
                            string_to_hash += "&"
                        string_to_hash += key + "=" + value_str
        return string_to_hash


    @staticmethod
    def generate_secure_hash(string_to_hash:str, onepay_secret_key:str):
        return PaymentProviderOnePay.vpc_auth(string_to_hash, onepay_secret_key)

    @staticmethod
    def vpc_auth(msg, key):
        vpc_key = bytes.fromhex(key)
        return PaymentProviderOnePay.hmac_sha256(vpc_key, msg).hex().upper()

    @staticmethod
    def hmac_sha256(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def _get_default_payment_method_codes(self):
        """Override of payment to return the default payment method codes."""
        default_codes = super()._get_default_payment_method_codes()
        if self.code != "onepay":
            return default_codes
        return const.DEFAULT_PAYMENT_METHODS_CODES
