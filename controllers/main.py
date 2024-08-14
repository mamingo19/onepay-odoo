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
            # Return OnePay: Already updated
            return request.make_json_response(
                {"RspCode": "02", "Message": "Order already confirmed"}
            )

        response_code = data.get("vpc_TxnResponseCode")

        if response_code == "0":
            # Confirm the transaction if the payment was successful.
            tx_sudo._set_done()
        elif response_code == "1":
            tx_sudo._set_error(_("OnePay: Unspecified failure in authorization."))
        elif response_code == "2":
            tx_sudo._set_error(_("OnePay: Card Issuer declined to authorize the transaction."))
        elif response_code == "3":
            tx_sudo._set_error(_("OnePay: No response from Card Issuer."))
        elif response_code == "4":
            tx_sudo._set_error(_("OnePay: Invalid Expiration Date or your card is expired."))
        elif response_code == "5":
            tx_sudo._set_error(_("OnePay: Insufficient funds."))
        elif response_code == "6":
            tx_sudo._set_error(_("OnePay: No response from Card Issuer."))
        elif response_code == "7":
            tx_sudo._set_error(_("OnePay: System error while processing transaction."))
        elif response_code == "8":
            tx_sudo._set_error(_("OnePay: Card Issuer does not support online payment."))
        elif response_code == "9":
            tx_sudo._set_error(_("OnePay: Invalid Cardholder Name."))
        elif response_code == "10":
            tx_sudo._set_error(_("OnePay: Your card is expired or deactivated."))
        elif response_code == "11":
            tx_sudo._set_error(_("OnePay: Your card/account is not registered for online payment."))
        elif response_code == "12":
            tx_sudo._set_error(_("OnePay: Invalid Issue Date or Expiration Date."))
        elif response_code == "13":
            tx_sudo._set_error(_("OnePay: Transaction exceeded online payment limit."))
        elif response_code == "14":
            tx_sudo._set_error(_("OnePay: Invalid card number."))
        elif response_code == "21":
            tx_sudo._set_error(_("OnePay: Insufficient funds in your account."))
        elif response_code == "22":
            tx_sudo._set_error(_("OnePay: Invalid Account Information."))
        elif response_code == "23":
            tx_sudo._set_error(_("OnePay: Your card/account is blocked or not activated."))
        elif response_code == "24":
            tx_sudo._set_error(_("OnePay: Invalid Card/Account Information."))
        elif response_code == "25":
            tx_sudo._set_error(_("OnePay: Invalid OTP."))
        elif response_code == "26":
            tx_sudo._set_error(_("OnePay: OTP has expired."))
        elif response_code == "98":
            tx_sudo._set_error(_("OnePay: Authentication was cancelled."))
        elif response_code == "99":
            tx_sudo._set_canceled(state_message=_("The customer canceled the payment."))
        elif response_code == "B":
            tx_sudo._set_error(_("OnePay: Authentication failed."))
        elif response_code == "D":
            tx_sudo._set_error(_("OnePay: Authentication failed."))
        elif response_code == "F":
            tx_sudo._set_error(_("OnePay: Transaction authentication was not successful."))
        elif response_code == "U":
            tx_sudo._set_error(_("OnePay: CSC authentication was not successful."))
        elif response_code == "Z":
            tx_sudo._set_error(_("OnePay: Your transaction was declined."))
        elif response_code == "253":
            tx_sudo._set_error(_("OnePay: Your session has expired."))
        else:
            tx_sudo._set_error(_("OnePay: Unspecified failure."))

        # Return OnePay: Merchant update success
        return request.make_json_response(
            {"RspCode": "00", "Message": "Confirm Success"}
        )

    @staticmethod
    def _verify_notification_signature(data, tx_sudo):
        """Check that the received signature matches the expected one.
        * The signature in the payment link and the signature in the notification data are different.

        :param dict received_signature: The signature received with the notification data.
        :param recordset tx_sudo: The sudoed transaction referenced by the notification data, as a
                                    `payment.transaction` record.

        :return: None
        :raise Forbidden: If the signatures don't match.
        """
        # Check if data is empty.
        if not data:
            _logger.warning("Received notification with missing data.")
            raise Forbidden()

        received_signature = data.get("vpc_SecureHash")

        # Remove the signature from the data to verify.
        if data.get("vpc_SecureHash"):
            data.pop("vpc_SecureHash")
        if data.get("vpc_SecureHashType"):
            data.pop("vpc_SecureHashType")

        # Sort the data by key to generate the expected signature.
        input_data = sorted(data.items())
        has_data = ""
        seq = 0
        for key, val in input_data:
            if str(key).startswith("vpc_"):
                if seq == 1:
                    has_data = (
                        has_data
                        + "&"
                        + str(key)
                        + "="
                        + urllib.parse.quote_plus(str(val))
                    )
                else:
                    seq = 1
                    has_data = str(key) + "=" + urllib.parse.quote_plus(str(val))

        # Generate the expected signature.
        expected_signature = OnePayController.hmac_sha256(
            tx_sudo.provider_id.onepay_secret_key, has_data
        )

        # Compare the received signature with the expected signature.
        if not hmac.compare_digest(received_signature, expected_signature):
            _logger.warning("Received notification with invalid signature.")
            raise Forbidden()

    @staticmethod
    def hmac_sha256(key, data):
        """Generate a HMAC SHA256 hash"""

        byte_key = key.encode("utf-8")
        byte_data = data.encode("utf-8")
        return hmac.new(byte_key, byte_data, hashlib.sha256).hexdigest()
