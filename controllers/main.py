import hashlib
import hmac
import logging
import pprint
import urllib.parse
import base64
import time 

from urllib.parse import quote_plus
from werkzeug.exceptions import Forbidden
from odoo import _, http
from odoo.exceptions import ValidationError
from odoo.http import request

_logger = logging.getLogger(__name__)

class OnePayController(http.Controller):
    _return_url = "/payment/onepay/return"
    _ipn_url = "/payment/onepay/webhook"
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
        """Handle the callback from OnePay."""
        _logger.info(f"Received callback data: {data}")

        # Ensure `data` is a dictionary and contains all the necessary information
        notification_data = dict(data)  # Converts the received parameters into a dictionary

        # Find the transaction based on the received data
        tx_sudo = request.env['payment.transaction'].sudo()._get_tx_from_notification_data('onepay', notification_data)

        # Verify the signature
        if not self._verify_notification_signature(notification_data, tx_sudo):
            _logger.error("OnePay: Invalid signature.")
            return request.redirect('/payment/process/failed')
        
        # Process the payment notification
        tx_sudo._process_notification_data(notification_data)
        return request.redirect('/payment/process/success')
    
    @staticmethod
    def _verify_notification_signature(self, notification_data, tx):
        """Verify the notification signature from OnePay."""
        # Extract the received signature from the notification data dictionary
        received_signature = notification_data.get('vpc_SecureHash')
        if not received_signature:
            _logger.error("OnePay: Missing vpc_SecureHash in the notification data")
            return False

        # Sort parameters and generate the string to hash
        params_sorted = tx.sort_param(notification_data)
        string_to_hash = tx.generate_string_to_hash(params_sorted)

        _logger.debug("String to hash: %s", string_to_hash)

        # Generate the expected signature
        expected_signature = tx.generate_secure_hash(string_to_hash, tx.provider_id.onepay_secret_key)

        _logger.debug("Expected signature: %s", expected_signature)
        _logger.debug("Received signature: %s", received_signature)

        # Compare the received signature with the expected one
        if received_signature != expected_signature:
            _logger.error("OnePay: Invalid signature! Received: %s, Expected: %s", received_signature, expected_signature)
            return False

        return True
        
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
        return OnePayController.vpc_auth(string_to_hash, onepay_secret_key)
    
    @staticmethod
    def vpc_auth(msg, key):
        vpc_key = bytes.fromhex(key)
        return OnePayController.hmac_sha256(vpc_key, msg).hex().upper()
    
    @staticmethod
    def hmac_sha256(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
    
    @staticmethod
    def _get_error_message(response_code):
        error_messages = {
            "1": _("Unspecified failure in authorization."),
            "2": _("Card Issuer declined to authorize the transaction."),
            # Add other error codes and their corresponding messages as needed
        }
        return error_messages.get(response_code, _("Unspecified failure."))
    
    @http.route(
        _ipn_url,
        type="http",
        auth="public",
        methods=["GET"],
        csrf=False,
        save_session=False,
    )
    def onepay_webhook(self, **data):
        """Process the notification data (IPN) sent by OnePay to the webhook.

        The "Instant Payment Notification" is a classical webhook notification.

        :param dict data: The notification data
        :return: The response to give to OnePay and acknowledge the notification
        """

        _logger.info(
            "Notification received from OnePay with data:\n%s", pprint.pformat(data)
        )
        try:
            tx_sudo = (
                request.env["payment.transaction"]
                .sudo()
                ._get_tx_from_notification_data("onepay", data)
            )
            # Verify the signature of the notification data.
            self._verify_notification_signature(data, tx_sudo)
            # Handle the notification data
            tx_sudo._handle_notification_data("onepay", data)
        except Forbidden:
            _logger.warning(
                "Forbidden error during signature verification",
                exc_info=True,
            )
            # Set the transaction to error due to invalid signature
            tx_sudo._set_error("OnePay: " + _("Received data with invalid signature."))
            return request.make_json_response(
                {"RspCode": "97", "Message": "Invalid Checksum"}
            )

        except AssertionError:
            _logger.warning(
                "Assertion error during notification handling",
                exc_info=True,
            )
            tx_sudo._set_error("OnePay: " + _("Received data with invalid amount."))
            return request.make_json_response(
                {"RspCode": "04", "Message": "Invalid amount"}
            )

        except ValidationError:
            _logger.warning(
                "Unable to handle the notification data",
                exc_info=True,
            )
            return request.make_json_response(
                {"RspCode": "01", "Message": "Order Not Found"}
            )

        # Check if the transaction has already been processed.
        if tx_sudo.state in ["done", "cancel", "error"]:
            return request.make_json_response(
                {"RspCode": "02", "Message": "Order already confirmed"}
            )

        response_code = data.get("vpc_TxnResponseCode")
        _logger.info("Transaction response code: %s", response_code)

        error_messages = {
            "1": _("Unspecified failure in authorization."),
            "2": _("Card Issuer declined to authorize the transaction."),
            "3": _("No response from Card Issuer."),
            "4": _("Invalid Expiration Date or your card is expired."),
            "5": _("Insufficient funds."),
            "6": _("No response from Card Issuer."),
            "7": _("System error while processing transaction."),
            "8": _("Card Issuer does not support online payment."),
            "9": _("Invalid Cardholder Name."),
            "10": _("Your card is expired or deactivated."),
            "11": _("Your card/account is not registered for online payment."),
            "12": _("Invalid Issue Date or Expiration Date."),
            "13": _("Transaction exceeded online payment limit."),
            "14": _("Invalid card number."),
            "21": _("Insufficient funds in your account."),
            "22": _("Invalid Account Information."),
            "23": _("Your card/account is blocked or not activated."),
            "24": _("Invalid Card/Account Information."),
            "25": _("Invalid OTP."),
            "26": _("OTP has expired."),
            "98": _("Authentication was cancelled."),
            "99": _("The customer canceled the payment."),
            "B": _("Authentication failed."),
            "D": _("Authentication failed."),
            "F": _("Transaction authentication was not successful."),
            "U": _("CSC authentication was not successful."),
            "Z": _("Your transaction was declined."),
            "253": _("Your session has expired."),
        }

        if response_code == "0":
            tx_sudo._set_done()

        elif response_code in error_messages:
            tx_sudo._set_error(f"OnePay: {error_messages[response_code]}")
        else:
            tx_sudo._set_error(_("OnePay: Unspecified failure."))

        return request.make_json_response(
            {"RspCode": "00", "Message": "Confirm Success"}
        )
