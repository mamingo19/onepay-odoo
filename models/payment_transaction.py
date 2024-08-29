from odoo import models, _
from odoo.exceptions import ValidationError
from odoo.addons.onepay_payment.controllers.main import OnePayController
from odoo import models, fields

import logging
import socket
import requests
from datetime import datetime
from werkzeug import urls

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

    def _cron_query_onepay_transaction_status(self):
        transactions = self.search([
            ('provider_code', '=', 'onepay'),
            ('state', '=', 'pending'),
            ('onepay_query_status', '=', False),
            ('onepay_query_start_time', '>=', fields.Datetime.subtract(fields.Datetime.now(), minutes=15)),
        ])
        for tx in transactions:
            tx._query_onepay_transaction_status()

    def _query_onepay_transaction_status(self):
        self.ensure_one()
        
        # Prepare the data for the POST request
        params = {
            'vpc_Command': 'queryDR',
            'vpc_Version': '2',
            'vpc_MerchTxnRef': self.reference,
            'vpc_Merchant': self.provider_id.onepay_merchant_id,
            'vpc_AccessCode': self.provider_id.onepay_access_code,
            "vpc_Password": "admin@123456",
            "vpc_User": "Administrator",  
        }

        # Generate the secure hash
        params_sorted = self.provider_id.sort_param(params)
        string_to_hash = self.provider_id.generate_string_to_hash(params_sorted)
        params['vpc_SecureHash'] = self.provider_id.generate_secure_hash(string_to_hash, self.provider_id.onepay_secret_key)

        # Make the request to OnePay
        response = requests.post(
            "https://mtf.onepay.vn/msp/api/v1/vpc/invoices/queries",
            data=params,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        if response.status_code == 200:
            response_data = response.json()
            response_code = response_data.get("vpc_TxnResponseCode")

            if response_code == "0":
                self._set_done()
                self.onepay_query_status = True
            else:
                error_message = self.provider_id._get_error_message(response_code)
                self._set_error(f"OnePay: {error_message}")

        # If the transaction is not finalized, schedule the next query
        if fields.Datetime.now() >= self.onepay_query_start_time + datetime.timedelta(minutes=15):
            self.onepay_query_status = True
        else:
            self.env['ir.cron'].create({
                'name': 'Query OnePay Transaction Status',
                'model_id': self.env.ref('payment.model_payment_transaction').id,
                'state': 'code',
                'code': f'model._query_onepay_transaction_status()',
                'interval_number': 5,
                'interval_type': 'minutes',
                'numbercall': 1,
                'nextcall': fields.Datetime.now() + datetime.timedelta(minutes=5),
            })