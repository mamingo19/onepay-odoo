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
from odoo.addons.onepay_payment.models.payment_provider import PaymentProviderOnePay

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
        """Verify the notification signature received from OnePay.

        :param dict data: The notification data
        :param payment.transaction tx_sudo: The payment transaction record
        :raises: Forbidden if the signature is invalid
        """

        # Step 1: Sort the received data by keys
        params_sorted = dict(sorted(data.items()))

        # Step 2: Generate the string to hash
        string_to_hash = PaymentProviderOnePay.generate_string_to_hash(params_sorted)

        # Step 3: Generate the secure hash using the OnePay secret key
        onepay_secret_key = tx_sudo.acquirer_id.onepay_secret_key
        generated_secure_hash = PaymentProviderOnePay.generate_secure_hash(
            string_to_hash, onepay_secret_key
        )

        # Step 4: Compare the generated secure hash with the provided hash in the notification data
        received_secure_hash = data.get("vpc_SecureHash")
        if received_secure_hash != generated_secure_hash:
            _logger.warning("Invalid signature: expected %s, received %s",
                            generated_secure_hash, received_secure_hash)
            raise Forbidden("Invalid signature")

        _logger.info("Signature verified successfully.")

    @staticmethod
    def hmac_sha256(key, data):
        """Generate a HMAC SHA256 hash"""

        byte_key = key.encode("utf-8")
        byte_data = data.encode("utf-8")
        return hmac.new(byte_key, byte_data, hashlib.sha256).hexdigest()
