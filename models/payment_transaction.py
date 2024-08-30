from odoo import models, _
from odoo.exceptions import ValidationError
from odoo.addons.onepay_payment.controllers.main import OnePayController
from odoo.addons.onepay_payment.models.payment_provider import PaymentProviderOnePay
from odoo import models, fields


import logging
import socket
import requests
from datetime import datetime
from werkzeug import urls
from datetime import timedelta

_logger = logging.getLogger(__name__)

class PaymentTransaction(models.Model):
    _inherit = "payment.transaction"
    BASE_URL = "https://mtf.onepay.vn/paygate/vpcpay.op?"

    onepay_query_status = fields.Boolean(string="OnePay Query Status", default=False)
    onepay_query_start_time = fields.Datetime(string="OnePay Query Start Time")
    
    def _get_specific_rendering_values(self, processing_values):
        """Override to return OnePay-specific rendering values."""
        self.ensure_one()
        res = super()._get_specific_rendering_values(processing_values)
        if self.provider_code != "onepay":
            return res

        # Initiate the payment and retrieve the payment link data.
        base_url = self.provider_id.get_base_url().replace("http://", "https://", 1)
        int_amount = int(self.amount)

        # Generate IP and timestamp for vpc_TicketNo
        ip_address = socket.gethostbyname(socket.gethostname())
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        vpc_ticket_no = f"{ip_address}-{timestamp}"

        params = {
            "vpc_Version": "2",
            "vpc_Command": "pay",
            "vpc_AccessCode": self.provider_id.onepay_access_code,
            "vpc_Merchant": self.provider_id.onepay_merchant_id,
            "vpc_Amount": int_amount * 100,  # Amount in smallest currency unit
            "vpc_Currency": "VND",
            "vpc_ReturnURL": urls.url_join(base_url, OnePayController._return_url),
            "vpc_OrderInfo": f"Order: {self.reference}",
            "vpc_MerchTxnRef": self.reference,
            "vpc_Locale": "en",
            "vpc_TicketNo": vpc_ticket_no,
            "AgainLink": urls.url_join(base_url, "/shop/payment"),
            "Title": "Trip Payment",
            # Construct callback URL with robust handling
            "vpc_CallbackURL": urls.url_join(base_url, OnePayController._callback_url),
        }

        _logger.info(f"Callback URL: {params['vpc_CallbackURL']}")

        payment_link_data = self.provider_id._get_payment_url(
            params=params, secret_key=self.provider_id.onepay_secret_key
        )
       
        rendering_values = {
            'api_url': payment_link_data
        }
        return rendering_values

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        """Override to find the transaction based on OnePay data."""
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
        """Override to process the transaction based on OnePay data."""
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

    def _cron_query_onepay_transaction_status(self):
        # Get the timestamp for one minute ago
        fifteen_minutes_ago = fields.Datetime.now() - timedelta(minutes=15)
        
        # Search for pending OnePay transactions that haven't been queried yet
        transactions = self.search([
            ('provider_code', '=', 'onepay'),
            ('state', '=', 'pending'),
            ('onepay_query_status', '=', False),
            ('onepay_query_start_time', '>=', fifteen_minutes_ago),
        ])
        
        # Query the status of each transaction
        for tx in transactions:
            tx._query_onepay_transaction_status()

    def _query_onepay_transaction_status(self):
        self.ensure_one()
        
        # Define the maximum time to wait for a transaction to finalize (e.g., 15 minutes)
        max_wait_time = timedelta(minutes=15)

        # Check if the current time exceeds the maximum wait time
        if fields.Datetime.now() > self.onepay_query_start_time + max_wait_time:
            # Stop further queries and mark the transaction as timed out or failed
            self._set_error("OnePay: Transaction timed out")
            self.onepay_query_status = True
            return
        
        # Prepare the data for the POST request to OnePay
        params = {
            'vpc_Command': 'queryDR',
            'vpc_Version': '2',
            'vpc_MerchTxnRef': self.reference,
            'vpc_Merchant': self.provider_id.onepay_merchant_id,
            'vpc_AccessCode': self.provider_id.onepay_access_code,
            "vpc_Password": "admin@123456",  # Hardcoded password (for testing purposes, should be securely managed)
            "vpc_User": "Administrator",  # Hardcoded username (for testing purposes, should be securely managed)
        }

        # Sort parameters and generate the secure hash for the request
        params_sorted = PaymentProviderOnePay.sort_param(params)
        string_to_hash = PaymentProviderOnePay.generate_string_to_hash(params_sorted)
        params['vpc_SecureHash'] = PaymentProviderOnePay.generate_secure_hash(string_to_hash, self.provider_id.onepay_secret_key)

        # Send the POST request to OnePay's API
        response = requests.post(
            "https://mtf.onepay.vn/msp/api/v1/vpc/invoices/queries",
            data=params,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        # Process the response from OnePay
        if response.status_code == 200:
            response_data = response.json()
            response_code = response_data.get("vpc_TxnResponseCode")

            if response_code == "0":
                self._set_done()
                self.onepay_query_status = True
            else:
                error_message = self.provider_id._get_error_message(response_code)
                self._set_error(f"OnePay: {error_message}")

        # Schedule another query if the transaction is still pending and within the allowed time
        if fields.Datetime.now() < self.onepay_query_start_time + timedelta(minutes=15) and not self.onepay_query_status:
            self.env['ir.cron'].create({
                'name': f'Query OnePay Transaction Status for {self.reference}',
                'model_id': self.env.ref('payment.model_payment_transaction').id,
                'state': 'code',
                'code': f'model.browse({self.id})._query_onepay_transaction_status()',
                'interval_number': 5,
                'interval_type': 'minutes',
                'numbercall': 1,
                'nextcall': fields.Datetime.now() + timedelta(minutes=15),
            })
