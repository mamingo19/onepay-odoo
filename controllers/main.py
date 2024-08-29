import hashlib
import hmac
import logging
import pprint
import urllib.parse
import base64
import datetime
import time
import requests

from urllib.parse import quote_plus
from werkzeug.exceptions import Forbidden
from odoo import _, http
from odoo.exceptions import ValidationError
from odoo.http import request
from odoo.addons.onepay_payment.models.payment_provider import PaymentProviderOnePay

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
            self._verify_notification_signature(data, tx_sudo)

            # Handle the notification data
            tx_sudo._handle_notification_data("onepay", data)
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
    def _verify_notification_signature(data, tx_sudo):
        """Verify the notification signature sent by OnePay."""
        received_signature = data.pop("vpc_SecureHash", None)
        if not received_signature:
            _logger.warning("Received notification with missing signature.")
            raise Forbidden()
        
        merchant_hash_code = tx_sudo.provider_id.onepay_secret_key

        sorted_data = PaymentProviderOnePay.sort_param(data)
        signing_string = PaymentProviderOnePay.generate_string_to_hash(sorted_data)

        # Generate the expected signature
        expected_signature = PaymentProviderOnePay.generate_secure_hash(signing_string, merchant_hash_code)

        # Log the received and expected signatures for debugging
        _logger.info("Received signature: %s", received_signature)
        _logger.info("Expected signature: %s", expected_signature)
        _logger.info("Signing string: %s", signing_string)
        _logger.info("Merchant hash code: %s", merchant_hash_code)

        # Compare the received signature with the expected signature
        if not hmac.compare_digest(received_signature.upper(), expected_signature):
            _logger.warning("Received notification with invalid signature.")
            raise Forbidden()
        
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
        _logger.info("Notification received from OnePay with data:\n%s", pprint.pformat(data))

        try:
            tx_sudo = request.env["payment.transaction"].sudo()._get_tx_from_notification_data("onepay", data)
            # Verify the signature of the notification data.
            self._verify_notification_signature(data, tx_sudo)
            # Handle the notification data
            tx_sudo._handle_notification_data("onepay", data)
        except Forbidden:
            _logger.warning("Forbidden error during signature verification", exc_info=True)
            # Set the transaction to error due to invalid signature
            tx_sudo._set_error("OnePay: " + _("Received data with invalid signature."))
            return request.make_json_response({"RspCode": "97", "Message": "Invalid Checksum"})
        except AssertionError:
            _logger.warning("Assertion error during notification handling", exc_info=True)
            tx_sudo._set_error("OnePay: " + _("Received data with invalid amount."))
            return request.make_json_response({"RspCode": "04", "Message": "Invalid amount"})
        except ValidationError:
            _logger.warning("Unable to handle the notification data", exc_info=True)
            return request.make_json_response({"RspCode": "01", "Message": "Order Not Found"})

        # Check if the transaction has already been processed.
        if tx_sudo.state in ["done", "cancel", "error"]:
            return request.make_json_response({"RspCode": "02", "Message": "Order already confirmed"})

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
            # Add additional error messages as necessary
        }

        if response_code == "0":
            tx_sudo._set_done()
        else:
            error_message = error_messages.get(response_code, "Unknown error.")
            tx_sudo._set_error(f"OnePay: {error_message}")

        return request.make_json_response({"RspCode": "00", "Message": "Callback Success"})
