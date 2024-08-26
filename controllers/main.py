import hashlib
import hmac
import logging
import pprint
from werkzeug.exceptions import Forbidden
from odoo import _, http
from odoo.exceptions import ValidationError
from odoo.http import request

_logger = logging.getLogger(__name__)

class OnePayController(http.Controller):
    _return_url = "/payment/onepay/return"
    _callback_url = "/payment/onepay/callback"

    @http.route(
        _return_url,
        type="http",
        methods=["GET"],
        auth="public",
        csrf=False,
        save_session=False,
    )
    def onepay_return_from_checkout(self, **data):
        """No need to handle the data from the return URL because the IPN already handled it."""
        _logger.info("Handling redirection from OnePay.")
        # Redirect user to the status page.
        return request.redirect("/payment/status")
    
    @http.route(
        _callback_url,
        type="http",
        methods=["GET"],  # Adjust this if OnePay uses POST
        auth="public",
        csrf=False,
        save_session=False,
    )
    def onepay_callback(self, **data):
        """Process the callback data sent by OnePay to the specified URL."""
        _logger.info("Callback received from OnePay with data:\n%s", pprint.pformat(data))

        try:
            # Fetch the transaction using the provided data
            tx_sudo = request.env["payment.transaction"].sudo()._get_tx_from_notification_data("onepay", data)

            # Verify the signature
            self._verify_notification_signature(data)

            # Handle the notification data
            tx_sudo._process_notification_data(data)
        except Forbidden:
            _logger.warning("Forbidden error during signature verification", exc_info=True)
            return request.make_json_response({"RspCode": "97", "Message": "Invalid Checksum"})
        except ValidationError:
            _logger.warning("Validation error during callback data processing", exc_info=True)
            return request.make_json_response({"RspCode": "01", "Message": "Order Not Found"})

        if tx_sudo.state in ["done", "cancel", "error"]:
            return request.make_json_response({"RspCode": "02", "Message": "Order already confirmed"})

        response_code = data.get("vpc_TxnResponseCode")
        _logger.info("Transaction response code: %s", response_code)

        if response_code == "0":
            tx_sudo._set_done()
        else:
            error_message = self._get_error_message(response_code)
            tx_sudo._set_error(f"OnePay: {error_message}")

        return request.make_json_response({"RspCode": "00", "Message": "Callback Success"})
    
    @staticmethod
    def _verify_notification_signature(notification_data):
        """Verify the notification signature from OnePay."""
        received_signature = notification_data.get('vpc_SecureHash')
        assert received_signature, "Missing vpc_SecureHash in the notification data"

        # Sort parameters and generate the string to hash
        params_sorted = OnePayController.sort_param(notification_data)
        string_to_hash = OnePayController.generate_string_to_hash(params_sorted)
        
        _logger.debug("String to hash: %s", string_to_hash)

        # Generate the expected signature
        onepay_secret_key = request.env["payment.provider"].sudo().search([('code', '=', 'onepay')], limit=1).onepay_secret_key
        expected_signature = OnePayController.generate_secure_hash(string_to_hash, onepay_secret_key)
        
        _logger.debug("Expected signature: %s", expected_signature)
        _logger.debug("Received signature: %s", received_signature)

        # Compare the received signature with the expected one
        if received_signature != expected_signature:
            _logger.error("Invalid signature! Received: %s, Expected: %s", received_signature, expected_signature)
            return False
        
        return True

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
                    if len(value_str) > 0:
                        if len(string_to_hash) > 0:
                            string_to_hash += "&"
                        string_to_hash += f"{key}={value_str}"
        return string_to_hash
    
    @staticmethod
    def generate_secure_hash(string_to_hash, onepay_secret_key):
        return hmac.new(
            bytes.fromhex(onepay_secret_key), 
            string_to_hash.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest().upper()
    
    @staticmethod
    def _get_error_message(response_code):
        """Provide a friendly error message based on the response code."""
        error_messages = {
            "1": "Transaction was not processed.",
            "2": "Transaction was declined.",
            "3": "Transaction was reversed.",
            "4": "Transaction is being processed.",
            "5": "Transaction is in process.",
            "6": "Transaction is pending.",
            "7": "Transaction was approved.",
        }
        return error_messages.get(response_code, "Unknown error")
