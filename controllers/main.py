# Part of Odoo. See LICENSE file for full copyright and licensing details.

import hashlib
import hmac
import logging
import pprint
import urllib.parse

from datetime import datetime
from werkzeug.exceptions import Forbidden
from odoo import _, http
from odoo.exceptions import ValidationError
from odoo.http import request
from odoo.tools.misc import file_open

_logger = logging.getLogger(__name__)

class OnePayController(http.Controller):
    _return_url = "/payment/onepay/return"
    _ipn_url = "/payment/onepay/webhook"

    @http.route(
        _return_url,
        type="http",
        methods=["GET"],
        auth="public",
        csrf=False,
        save_session=False,  # No need to save the session
    )
    def onepay_return_from_checkout(self, **data):
        """No need to handle the data from the return URL because the IPN already handled it."""

        _logger.info("Handling redirection from OnePay.")

        # Redirect user to the status page.
        # After redirection, user will see the payment status once the IPN processing is complete.
        return request.redirect("/payment/status")

    @http.route(
        _ipn_url,
        type="http",
        auth="public",
        methods=["GET"],
        csrf=False,
        save_session=False,  # No need to save the session
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
            # Return OnePay: Invalid Signature
            tx_sudo._set_error("OnePay: " + _("Received data with invalid signature."))
            return request.make_json_response(
                {"RspCode": "97", "Message": "Invalid Checksum"}
            )

        except AssertionError:
            _logger.warning(
                "Assertion error during notification handling: %s",
                exc_info=True,
            )
            tx_sudo._set_error("OnePay: " + _("Received data with invalid amount."))
            # Return OnePay: Invalid amount
            return request.make_json_response(
                {"RspCode": "04", "Message": "Invalid amount"}
            )

        except ValidationError:
            _logger.warning(
                "Unable to handle the notification data",
                exc_info=True,
            )
            # Return OnePay: Order Not Found
            return request.make_json_response(
                {"RspCode": "01", "Message": "Order Not Found"}
            )

        # Check if the transaction has already been processed.
        if tx_sudo.state in ["done", "cancel", "error"]:
            # Return OnePay: Already update
            return request.make_json_response(
                {"RspCode": "02", "Message": "Order already confirmed"}
            )

        response_code = data.get("vpc_TxnResponseCode")

        if response_code == "0":
            # Confirm the transaction if the payment was successful.
            tx_sudo._set_done()
        elif response_code == "24":
            # Cancel the transaction if the payment was canceled by the user.
            tx_sudo._set_canceled(state_message=_("The customer canceled the payment."))
        else:
            # Notify the user that the payment failed.
            tx_sudo._set_error(
                "OnePay: "
                + _("Received data with invalid response code: %s", response_code)
            )
        # Return OnePay: Merchant update success
        return request.make_json_response(
            {"RspCode": "00", "Message": "Confirm Success"}
        )

    @staticmethod
    def _verify_notification_signature(data, tx_sudo):
        """Check that the received signature matches the expected one.
        * The signature in the payment link and the signature in the notification data are different.

        :param dict data: The notification data received from OnePay.
        :param recordset tx_sudo: The sudoed transaction referenced by the notification data, as a
                                    `payment.transaction` record.

        :return: None
        :raise Forbidden: If the signatures don't match.
        """
        # Check if data is empty.
        if not data:
            _logger.warning("Received notification with missing data.")
            raise Forbidden("Missing data in notification")

        received_signature = data.get("vnp_SecureHash")

        if not received_signature:
            _logger.warning("Received notification with missing signature.")
            raise Forbidden("Missing signature in notification")

        # Remove the signature-related fields from the data before generating the expected signature.
        data_to_verify = data.copy()
        data_to_verify.pop("vnp_SecureHash", None)
        data_to_verify.pop("vnp_SecureHashType", None)

        # Sort the data by key to generate the expected signature.
        sorted_data = sorted(data_to_verify.items())
        has_data = ""
        for key, value in sorted_data:
            if str(key).startswith("vnp_"):
                if has_data:
                    has_data += "&"
                has_data += f"{key}={urllib.parse.quote_plus(str(value))}"

        # Generate the expected signature using HMAC-SHA256.
        expected_signature = OnePayController.__hmacsha256(
            tx_sudo.acquirer_id.onepay_hash_secret, has_data
        )

        # Log the expected and received signatures to Docker logs for debugging.
        _logger.info("Expected signature: %s", expected_signature)
        _logger.info("Received signature: %s", received_signature)

        # Compare the received signature with the expected signature.
        if not hmac.compare_digest(received_signature.upper(), expected_signature.upper()):
            _logger.warning("Received notification with invalid signature.")
            raise Forbidden("Invalid signature in notification")

        _logger.info("Notification signature verified successfully.")

    @staticmethod
    def __hmacsha256(key, data):
        """Generate a HMAC SHA256 hash"""
        byte_key = key.encode("utf-8")
        byte_data = data.encode("utf-8")
        return hmac.new(byte_key, byte_data, hashlib.sha256).hexdigest()

    

