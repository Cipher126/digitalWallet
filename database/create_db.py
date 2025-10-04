from connection import conn

with conn.cursor() as cursor:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id VARCHAR(20) PRIMARY KEY NOT NULL,
            username VARCHAR(50) UNIQUE NOT NULL,
            full_name VARCHAR(255),
            email VARCHAR(255) UNIQUE NOT NULL,
            phone VARCHAR(20) UNIQUE,
            password TEXT,
            oauth_provider VARCHAR(50),
            oauth_id VARCHAR(255),
            is_oauth_only BOOLEAN DEFAULT FALSE,
            otp_secret TEXT,
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            is_active BOOLEAN DEFAULT TRUE,
            is_verified BOOLEAN DEFAULT FALSE,
            role VARCHAR(20) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT NOW(),
            fcm_token VARCHAR(255)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            wallet_id VARCHAR(50) PRIMARY KEY NOT NULL,
            user_id VARCHAR(20) REFERENCES users(user_id) ON DELETE CASCADE,
            account_number VARCHAR(20) UNIQUE NOT NULL,
            balance NUMERIC(20, 2) DEFAULT 0.00,
            txn_pin TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            txn_id VARCHAR(50)PRIMARY KEY NOT NULL,
            wallet_id VARCHAR(20) REFERENCES wallets(wallet_id) ON DELETE CASCADE,
            user_id VARCHAR(20) REFERENCES users(user_id) ON DELETE CASCADE,
            txn_type VARCHAR(50) CHECK (txn_type IN ('credit', 'debit', 'transfer', 'external_inbound', 'external_outbound')),
            amount NUMERIC(20, 2) NOT NULL,
            status VARCHAR(20) CHECK (status IN ('pending', 'success', 'failed')) DEFAULT 'pending',
            reference VARCHAR(255) UNIQUE NOT NULL,
            metadata JSONB,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS beneficiaries (
            beneficiary_id VARCHAR(20) PRIMARY KEY,
            user_id VARCHAR(20) REFERENCES users(user_id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            account_number VARCHAR(20) NOT NULL,
            bank_name VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
             token_id VARCHAR(50) PRIMARY KEY,
             user_id VARCHAR(20) REFERENCES users(user_id) ON DELETE CASCADE,
             token TEXT NOT NULL,
             is_revoked BOOLEAN DEFAULT FALSE,
             expires_at TIMESTAMP NOT NULL,
             created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id VARCHAR(20) PRIMARY KEY,
            user_id VARCHAR(20) REFERENCES users(user_id) ON DELETE CASCADE,
            action VARCHAR(255) NOT NULL,
            metadata JSONB,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS webhook_logs (
            webhook_id VARCHAR(20) PRIMARY KEY,
            event_type VARCHAR(100) NOT NULL,
            payload JSONB NOT NULL,
            status VARCHAR(20) CHECK (status IN ('pending', 'delivered', 'failed')) DEFAULT 'pending',
            attempts INT DEFAULT 0,
            last_attempt_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    conn.commit()