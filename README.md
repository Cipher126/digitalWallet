# Digital Wallet API 💳

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-development-orange)

A robust and secure digital wallet system built with Flask, providing comprehensive financial services including wallet management, secure transactions, and administrative controls.

## 📑 Table of Contents
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Variables](#environment-variables)
- [API Documentation](#api-documentation)
- [Security Features](#security-features)
- [Testing](#testing)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features <a name="features"></a>

### Authentication & Security
- Multi-factor authentication (2FA)
- JWT-based authentication
- Google OAuth2.0 integration
- OTP verification system
- Rate limiting protection
- Role-based access control

### Wallet Management
- Digital wallet creation and activation
- Secure PIN management
- Internal wallet-to-wallet transfers
- Interbank transfers via Monnify
- Real-time balance updates
- Transaction history tracking

### Administrative Controls
- User account management
- Wallet freeze/unfreeze capabilities
- Activity monitoring
- System-wide audit logs
- User verification management

### Notifications
- Firebase Cloud Messaging integration
- Email notifications
- Login alerts
- Transaction confirmations

## 🛠 Technology Stack <a name="technology-stack"></a>

### Backend
- **Framework**: Flask (Python)
- **Database**: PostgreSQL
- **Authentication**: JWT, OAuth2.0
- **Documentation**: Swagger/OpenAPI (Flasgger)
- **Payment Gateway**: Monnify
- **Push Notifications**: Firebase Cloud Messaging

### Development Tools
- **Version Control**: Git
- **API Testing**: Postman/Swagger UI
- **Logging**: Custom implementation
- **Rate Limiting**: Custom token bucket implementation

## 📁 Project Structure <a name="project-structure"></a>

```
wallet_app/
├── routes/
│   ├── admin_route.py     # Admin management endpoints
│   ├── user_route.py      # User authentication & management
│   ├── wallet_route.py    # Wallet operations
│   ├── transactions_route.py  # Transaction handling
│   └── webhook.py         # Payment webhooks
├── services/
│   ├── auth_services.py   # Authentication logic
│   ├── wallet_services.py # Wallet business logic
│   └── ...
├── models/               # Database models
├── middleware/          # Auth & rate limiting
├── error_handling/      # Custom error handlers
├── tests/              # Unit & integration tests
├── .env               # Environment configuration
├── requirements.txt   # Project dependencies
└── main.py           # Application entry point
```

## 🚀 Getting Started <a name="getting-started"></a>

### Prerequisites <a name="prerequisites"></a>

- Python 3.8 or higher
- PostgreSQL
- Firebase account
- Monnify merchant account

### Installation <a name="installation"></a>

1. Clone the repository
```bash
git clone https://github.com/cipher126/digitalWallet.git
cd wallet_app
```

2. Create and activate virtual environment
```bash
python -m venv venv
.\venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Set up environment variables
```bash
cp .env.example .env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=your_redirect_uri
FCM_PATH=path_to_firebase_credentials
MONNIFY_API_KEY=monnify_api_key
MONNIFY_SECRET=your_monnify_secret
MONNIFY_URL=https://sandbox.monnify.com
CONTRACT_CODE=contract_code
MONNIFY_WALLET_ACCOUNT=monify_account
DB_HOST=db_host
DB_NAME=db_name
DB_USER=db_user
DB_PASSWORD=db_password

SECRET_KEY=jwt_secret
OTP_SECRET=pyotp_secret

REDIS_HOST=host
REDIS_PORT=port
REDIS_USER=username
REDIS_PASSWORD=redis_password

EMAIL_HOST='smtp.gmail.com'
EMAIL_PORT=587
EMAIL_ADDRESS=your_email_for_email_sending
EMAIL_PASSWORD=email_password
```

5. Run the application
```bash
python main.py
```

### Environment Variables <a name="environment-variables"></a>

```env
# Authentication
JWT_SECRET_KEY=your_jwt_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=your_redirect_uri

# Firebase
FCM_PATH=path_to_firebase_credentials.json

# Monnify
MONNIFY_API_KEY=your_monnify_api_key
MONNIFY_SECRET=your_monnify_secret
MONNIFY_CONTRACT_CODE=your_contract_code

# Database
DATABASE_URL=your_database_url
```

## 📚 API Documentation <a name="api-documentation"></a>

Comprehensive API documentation is available via Swagger UI at `/docs` endpoint after starting the application. The documentation includes:

- Detailed endpoint descriptions
- Request/Response examples
- Authentication requirements
- Error scenarios

## 🔒 Security Features <a name="security-features"></a>

- JWT-based authentication
- Rate limiting on sensitive endpoints
- Input validation and sanitization
- Error handling and logging
- Secure headers implementation
- Transaction signing
- Activity audit logging


## 📦 Deployment <a name="deployment"></a>

1. Set up production environment variables
2. Configure PostgreSQL database
3. Set up Firebase credentials
4. Configure Monnify production credentials
5. Deploy using your preferred hosting service (e.g., AWS, Heroku)

## 🤝 Contributing <a name="contributing"></a>

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License <a name="license"></a>

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.