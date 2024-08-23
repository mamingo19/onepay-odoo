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
    _callback_url = "/payment/onepay/callback"  # New callback route

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

    @http.route(
        _callback_url,
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,  # No need to save the session
    )
    def onepay_callback(self, **data):
        """Process the callback notification data sent by OnePay to the callback URL.

        This callback is used to confirm the payment status asynchronously.

        :param dict data: The callback notification data
        :return: The response to give to OnePay and acknowledge the callback
        """
        _logger.info(
            "Callback received from OnePay with data:\n%s", pprint.pformat(data)
        )

        try:
            tx_sudo = (
                request.env["payment.transaction"]
                .sudo()
                ._get_tx_from_notification_data("onepay", data)
            )
            # Verify the signature of the callback data.
            self._verify_notification_signature(data, tx_sudo)

            # Process the callback data.
            tx_sudo._process_notification_data(data)
        except Forbidden:
            _logger.warning(
                "Forbidden error during callback signature verification",
                exc_info=True,
            )
            # Return OnePay: Invalid Signature
            tx_sudo._set_error("OnePay: " + _("Received callback data with invalid signature."))
            return request.make_json_response(
                {"RspCode": "97", "Message": "Invalid Checksum"}
            )
        except ValidationError:
            _logger.warning(
                "Unable to handle the callback data",
                exc_info=True,
            )
            # Return OnePay: Order Not Found
            return request.make_json_response(
                {"RspCode": "01", "Message": "Order Not Found"}
            )

        # Return OnePay: Callback processed successfully
        return request.make_json_response(
            {"RspCode": "00", "Message": "Callback Success"}
        )

    def _verify_notification_signature(self, data, tx_sudo):
        """Verify the signature of the notification/callback data.

        :param dict data: The data received from OnePay.
        :param record tx_sudo: The transaction record.
        :raises Forbidden: If the signature is invalid.
        """
        received_secure_hash = data.get("vpc_SecureHash")
        if not received_secure_hash:
            raise Forbidden("OnePay: Missing secure hash in the notification data.")

        params_sorted = self._sort_param(data)
        string_to_hash = self._generate_string_to_hash(params_sorted)
        generated_secure_hash = self._generate_secure_hash(
            string_to_hash, tx_sudo.provider_id.onepay_secret_key
        )

        if received_secure_hash != generated_secure_hash:
            _logger.error(
                "OnePay: Invalid signature. Received %s, expected %s.",
                received_secure_hash,
                generated_secure_hash,
            )
            raise Forbidden("OnePay: Invalid signature in the notification data.")

    @staticmethod
    def _sort_param(params):
        return dict(sorted(params.items()))

    @staticmethod
    def _generate_string_to_hash(params_sorted):
        string_to_hash = ""
        for key, value in params_sorted.items():
            prefix_key = key[0:4]
            if prefix_key == "vpc_" or prefix_key == "user":
                if key != "vpc_SecureHashType" and key != "vpc_SecureHash":
                    value_str = str(value)
                    if len(value_str) > 0:
                        if len(string_to_hash) > 0:
                            string_to_hash += "&"
                        string_to_hash += key + "=" + value_str
        return string_to_hash

    @staticmethod
    def _generate_secure_hash(string_to_hash, secret_key):
        return OnePayController._vpc_auth(string_to_hash, secret_key)

    @staticmethod
    def _vpc_auth(msg, key):
        vpc_key = bytes.fromhex(key)
        return OnePayController._hmac_sha256(vpc_key, msg).hex().upper()

    @staticmethod
    def _hmac_sha256(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
