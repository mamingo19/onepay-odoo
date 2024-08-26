from odoo import http
from odoo.http import request
import logging

_logger = logging.getLogger(__name__)

class OnePayController(http.Controller):
    _return_url = "/payment/onepay/return"
    _callback_url = "/payment/onepay/callback"

    @http.route('/payment/onepay/return', type='http', auth='public', methods=['GET'], website=True)
    def payment_return(self, **kwargs):
        """
        Handle the return URL from OnePay after payment completion.
        """
        _logger.info("OnePay: Handling return URL with params: %s", kwargs)

        # Extract relevant parameters
        vpc_response_code = kwargs.get('vpc_ResponseCode', '')

        # Find the transaction
        tx = request.env['payment.transaction'].sudo()._get_tx_from_notification_data(
            provider_code="onepay", 
            notification_data=kwargs
        )

        if vpc_response_code == '0':  # Assuming 0 is the success code
            tx._set_done(state_message=_("Payment successfully processed."))
        else:
            tx._set_canceled(state_message=_("Payment failed or was canceled."))

        return request.render('onepay_payment.payment_return_page', {})

    @http.route('/payment/onepay/callback', type='http', auth='public', methods=['POST'])
    def payment_callback(self, **kwargs):
        """
        Handle the callback from OnePay for asynchronous notification.
        """
        _logger.info("OnePay: Handling callback with params: %s", kwargs)

        # Extract relevant parameters
        vpc_response_code = kwargs.get('vpc_ResponseCode', '')

        # Find the transaction
        tx = request.env['payment.transaction'].sudo()._get_tx_from_notification_data(
            provider_code="onepay",
            notification_data=kwargs
        )

        if vpc_response_code == '0':  # Assuming 0 is the success code
            tx._set_done(state_message=_("Payment successfully processed."))
        else:
            tx._set_canceled(state_message=_("Payment failed or was canceled."))

        return request.make_response("OK")

