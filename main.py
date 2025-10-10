from flasgger import Swagger
from flask import Flask
from error_handling.error_handler import handle_error
from routes.transactions_route import txn_bp
from routes.user_route import user_bp
from routes.admin_route import admin_bp
from routes.wallet_route import wallet_bp
import os
from dotenv import load_dotenv
from firebase_admin import credentials, initialize_app

from routes.webhook import webhook_bp

app = Flask(__name__)
handle_error(app)

app.register_blueprint(user_bp, url_prefix='/api/user')
app.register_blueprint(admin_bp, url_prefix='/api/admin')
app.register_blueprint(wallet_bp, url_prefix='/api/wallet')
app.register_blueprint(txn_bp, url_prefix='/api/transaction')
app.register_blueprint(webhook_bp)

app.config['SWAGGER'] = {
    'title': 'Digital Wallet API',
    'uiversion': 3,
    'version': '1.0',
    'description': (
        'This is the API documentation for the **Digital Wallet Application**.\n\n'
        'Features include:\n'
        '- Google OAUTH signup and login authentication\n'
        '- User (email/username) signup/login (JWT-based authentication)\n'
        '- Wallet creation and interbank transfers\n'
        '- Notification system\n'
        '- Transactions tracking and monitoring\n'
        '- Transactions history and records\n'
        '- Admin privileges like users management and activities monitoring\n'
        '- Audit logs for easier admin user monitoring\n'
        '- 2FA verification and OTP handling\n'
        '- Webhooks for transaction updates\n\n'
        '**Authentication:** Use Bearer token from `/login` to access protected routes.'
    ),
    'termsOfService': '/terms',
    'contact': {
        'name': 'Dev Support Team',
        'url': 'https://yourportfolio.dev',
        'email': 'support@yourwalletapp.dev'
    },
    'license': {
        'name': 'MIT License',
        'url': 'https://opensource.org/licenses/MIT'
    },
    'securityDefinitions': {
        'BearerAuth': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'Enter your Bearer token in the format: Bearer <token>'
        }
    },
    'security': [
        {'BearerAuth': []}
    ]
}

# Initialize Swagger with custom configuration
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs"
}

swagger = Swagger(app, config=swagger_config)

load_dotenv()

cred = credentials.Certificate(os.getenv("FCM_PATH"))
initialize_app(cred)

if __name__ == "__main__":
    app.run(debug=True)