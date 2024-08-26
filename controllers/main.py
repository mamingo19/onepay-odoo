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
    methods=["POST"],
    auth="public",
    csrf=False,
    save_session=False,
    )
    def onepay_callback(self, **data):
        """Process the callback data sent by OnePay to the specified URL.
        
        This function handles the callback URL processing for OnePay payments.
        
        :param dict data: The callback data received from OnePay.
        :return: A response to acknowledge receipt of the callback.
        """
        
        _logger.info("Callback received from OnePay with data:\n%s", pprint.pformat(data))
        
        try:
            # Fetch the transaction related to the callback
            tx_sudo = request.env["payment.transaction"].sudo()._get_tx_from_notification_data("onepay", data)
            
            # Verify the signature
            self._verify_notification_signature(data, tx_sudo)
            
            # Handle the callback data
            tx_sudo._handle_notification_data("onepay", data)
        
        except Forbidden:
            _logger.warning("Forbidden error during signature verification", exc_info=True)
            if tx_sudo:
                tx_sudo._set_error("OnePay: " + _("Invalid signature in callback data."))
            return request.make_json_response({"RspCode": "97", "Message": "Invalid Checksum"})
        
        except ValidationError:
            _logger.warning("Validation error during callback data processing", exc_info=True)
            return request.make_json_response({"RspCode": "01", "Message": "Order Not Found"})
        
        # Check the transaction state and proceed accordingly
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
    def _get_error_message(response_code):
        error_messages = {
            "1": _("Unspecified failure in authorization."),
            "2": _("Card Issuer declined to authorize the transaction."),
            # Add other error codes and their corresponding messages as needed
        }
        return error_messages.get(response_code, _("Unspecified failure."))
    @staticmethod
    def _verify_notification_signature(self, data, tx_sudo):
        """Verify the notification signature sent by OnePay.

        This function compares the received signature with the one generated using the
        same logic as `create_request_signature_ita`.

        :param dict data: The notification data received.
        :param recordset tx_sudo: The sudoed transaction referenced by the notification data.
        :return: None
        :raise Forbidden: If the signatures don't match.
        """
        # Extract and remove the signature from the data to verify
        received_signature = data.pop("vpc_SecureHash", None)
        if not received_signature:
            _logger.warning("Received notification with missing signature.")
            raise Forbidden()

        # Sort the data by key to generate the expected signature string
        sorted_data = sorted(data.items())
        signing_string = ""
        for key, value in sorted_data:
            if key.startswith("vpc_"):
                signing_string += f"{key}={quote_plus(str(value))}&"
        
        # Remove trailing '&' from the signing string
        signing_string = signing_string.rstrip('&')

        # Generate the expected signature
        merchant_hash_code = tx_sudo.provider_id.onepay_hash_secret
        hmac_key = bytes.fromhex(merchant_hash_code)
        expected_signature = hmac.new(hmac_key, signing_string.encode("utf-8"), hashlib.sha512).hexdigest().upper()

        _logger.info("Expected signature: %s", expected_signature)

        # Compare the received signature with the expected signature
        if not hmac.compare_digest(received_signature.upper(), expected_signature):
            _logger.warning("Received notification with invalid signature.")
            raise Forbidden()

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
