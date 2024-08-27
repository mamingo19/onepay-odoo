# OnePay Integration for Odoo

This repository contains the source code for integrating the OnePay payment gateway into an Odoo system. This integration allows Odoo users to process payments using OnePay, a popular payment provider.

## Features

- **Payment Provider Integration:** Adds OnePay as a payment provider in the Odoo system.
- **Merchant Configuration:** Supports configuration of OnePay Merchant ID, Access Code, and Secret Key.
- **Payment Processing:** Handles payment transactions securely with OnePay.
- **Callback Handling:** Processes callbacks from OnePay to update transaction status.
- **Return URL Handling:** Redirects users to the payment status page after a transaction is completed.

## Files Overview

### `payment_provider.py`

This file extends the Odoo `payment.provider` model to include OnePay-specific configurations and functionality.

- **OnePay Configuration Fields:** Adds fields for `onepay_merchant_id`, `onepay_access_code`, and `onepay_secret_key`.
- **Payment URL Generation:** Generates the OnePay payment URL with secure hash verification.
- **Supported Currencies:** Ensures that only supported currencies are used with OnePay.
- **Compatibility Checks:** Filters the providers based on currency support and other criteria.

### `main.py`

This file contains the main controller (`OnePayController`) responsible for handling the interactions with OnePay.

- **Return URL Handling:** 
  - Route: `/payment/onepay/return`
  - Handles the redirection of users after a payment, usually redirecting to a status page.
- **Callback Handling:** 
  - Route: `/payment/onepay/callback`
  - Processes callbacks from OnePay and updates the transaction status based on the response.
- **Webhook IPN (In Progress):**
  - The IPN (Instant Payment Notification) webhook handler is currently under development.
  - Once implemented, it will listen for notifications from OnePay to automatically update transaction statuses without user intervention.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/odoo-onepay-integration.git
2. **Place the Module in Odoo Addons Directory:**
   Move the cloned repository to your Odoo addons directory.
3. **Install the Module:**
    In your Odoo backend, navigate to the Apps menu and install the OnePay integration module.
4. **Configure OnePay Settings:**
  - Go to the Payment Providers section in Odoo.
  - Select OnePay and enter your Merchant ID, Access Code, and Secret Key.
  - Save the settings.
## Contributing
Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request.
## License

This project is licensed under the MIT License by Darwind. See the [LICENSE](LICENSE) file for details.
