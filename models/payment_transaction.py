import logging
import pytz

from werkzeug import urls
from datetime import datetime, timedelta

from odoo import _, models
from odoo.exceptions import ValidationError

from odoo.addons.payment import utils as payment_utils
from odoo.addons.onepay_payment.controllers.main import OnePayController

_logger = logging.getLogger(__name__)

class PaymentTransaction(models.Model):
    _inherit = "payment.transaction"

    def _get_specific_rendering_values(self, processing_values):
        """Override to return OnePay-specific rendering values.

        Note: self.ensure_one() from _get_processing_values

        :param dict processing_values: The generic and specific processing values of the transaction
        :return: The dict of provider-specific processing values.
        :rtype: dict
        """
        self.ensure_one()
        res = super()._get_specific_rendering_values(processing_values)
        if self.provider_code != "onepay":
            return res

        # Initiate the payment and retrieve the payment link data.
        base_url = self.provider_id.get_base_url()
        int_amount = int(self.amount)

        params = {
            "vpc_Version": "2",
            "vpc_Command": "pay",
            "vpc_AccessCode": self.provider_id.onepay_access_code,
            "vpc_Merchant": self.provider_id.onepay_merchant_id,
            "vpc_Amount": int_amount * 100,
            "vpc_CreateDate": datetime.now(pytz.timezone("Etc/GMT-7")).strftime(
                "%Y%m%d%H%M%S"
            ),
            "vpc_Currency": "VND",
            "vpc_ReturnURL": urls.url_join(base_url, OnePayController._return_url),
            "vpc_OrderInfo": f"Order: {self.reference}",
            "vpc_MerchTxnRef": self.reference,
        }

        payment_link_data = self.provider_id._get_payment_url(
            params=params, secret_key=self.provider_id.onepay_secret_key
        )

        # Extract the payment link URL and embed it in the redirect form.
        rendering_values = {
            "api_url": payment_link_data,
        }
        return rendering_values

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        """Override to find the transaction based on OnePay data.

        :param str provider_code: The code of the provider that handled the transaction.
        :param dict notification_data: The notification data sent by the provider.
        :return: The transaction if found.
        :rtype: recordset of payment.transaction
        :raise ValidationError: If inconsistent data were received.
        :raise ValidationError: If the data match no transaction.
        """
        tx = super()._get_tx_from_notification_data(provider_code, notification_data)
        if provider_code != "onepay" or len(tx) == 1:
            return tx

        reference = notification_data.get("vpc_MerchTxnRef")
        if not reference:
            raise ValidationError(
                "OnePay: " + _("Received data with missing reference.")
            )

        tx = self.search(
            [("reference", "=", reference), ("provider_code", "=", "onepay")]
        )
        if not tx:
            raise ValidationError(
                "OnePay: " + _("No transaction found matching reference %s.", reference)
            )
        return tx

    def _process_notification_data(self, notification_data):
        """Override to process the transaction based on OnePay data.

        Note: self.ensure_one()

        :param dict notification_data: The notification data sent by the provider.
        :return: None
        :raise ValidationError: If inconsistent data were received.
        """
        self.ensure_one()
        super()._process_notification_data(notification_data)
        if self.provider_code != "onepay":
            return

        if not notification_data:
            self._set_canceled(state_message=_("The customer left the payment page."))
            return

        amount = notification_data.get("vpc_Amount")
        assert amount, "OnePay: missing amount"
        assert (
            self.currency_id.compare_amounts(float(amount) / 100, self.amount) == 0
        ), "OnePay: mismatching amounts"

        vpc_txn_ref = notification_data.get("vpc_MerchTxnRef")

        if not vpc_txn_ref:
            raise ValidationError(
                "OnePay: " + _("Received data with missing reference.")
            )
        self.provider_reference = vpc_txn_ref

        # Force OnePay as the payment method if it exists.
        self.payment_method_id = (
            self.env["payment.method"].search([("code", "=", "onepay")], limit=1)
            or self.payment_method_id
        )
