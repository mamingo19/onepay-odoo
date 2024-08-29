from odoo import models, fields, api
import logging
import requests
import hashlib

_logger = logging.getLogger(__name__)

class OnePayTransactionCron(models.Model):
    _inherit = 'payment.transaction'

    @api.model
    def cron_query_transaction_status(self):
        _logger.info("Running OnePay transaction status query cron job.")
        transactions = self.search([
            ('provider_code', '=', 'onepay'),
            ('state', '=', 'draft'),  # Only query transactions that are still pending
            ('date', '<=', fields.Datetime.now())
        ])

        for tx in transactions:
            elapsed_time = (fields.Datetime.now() - tx.create_date).total_seconds() / 60
            query = False

            if 5 <= elapsed_time < 15:
                query = True
            elif 15 <= elapsed_time < 30:
                query = True
            elif elapsed_time >= 30:
                query = True

            if query:
                self._query_onepay_transaction_status(tx)

    def _generate_secure_hash(self, params, secure_secret):
        """Generate secure hash using the provided parameters and secure secret."""
        hash_data = "&".join([f"{key}={params[key]}" for key in sorted(params)])
        return hashlib.sha256((hash_data + secure_secret).encode('utf-8')).hexdigest().upper()

    def _query_onepay_transaction_status(self, transaction):
        """Query the OnePay transaction status and update the transaction record."""
        base_url = "https://mtf.onepay.vn/msp/api/v1/vpc/invoices/queries"
        
        params = {
            'vpc_Command': 'queryDR',
            'vpc_Version': '2',
            'vpc_MerchTxnRef': transaction.reference,
            'vpc_Merchant': transaction.provider_id.onepay_merchant_id,
            'vpc_AccessCode': transaction.provider_id.onepay_access_code,
            'vpc_User': transaction.provider_id.onepay_user,
            'vpc_Password': transaction.provider_id.onepay_password,
        }
        
        # Generate secure hash
        secure_secret = transaction.provider_id.onepay_secure_secret
        params['vpc_SecureHash'] = self._generate_secure_hash(params, secure_secret)
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        try:
            response = requests.post(base_url, data=params, headers=headers)
            response.raise_for_status()
            data = response.json()

            _logger.info(f"Queried OnePay for transaction {transaction.reference} status. Response: {data}")

            if data['vpc_DRExists'] == 'N':
                transaction._set_error("OnePay: Transaction does not exist.")
            elif data['vpc_TxnResponseCode'] == '0':
                transaction._set_done()
            elif data['vpc_TxnResponseCode'] == '300' or data['vpc_TxnResponseCode'] == '100':
                _logger.info(f"Transaction {transaction.reference} is pending or in progress.")
            else:
                error_message = data.get('vpc_Message', 'Unknown error.')
                transaction._set_error(f"OnePay: {error_message}")

        except requests.exceptions.RequestException as e:
            _logger.error(f"Failed to query OnePay for transaction {transaction.reference}: {e}")


