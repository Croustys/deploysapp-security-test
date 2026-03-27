-- Intentional: creates a table with fake PII data for testing data exposure
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100),
    email       VARCHAR(200),
    ssn         VARCHAR(20),     -- fake SSNs
    credit_card VARCHAR(20),     -- fake credit card numbers
    password    VARCHAR(200)     -- plaintext passwords (intentional misconfiguration)
);

INSERT INTO users (name, email, ssn, credit_card, password) VALUES
    ('Alice Smith',   'alice@example.com',  '111-11-1111', '4111111111111111', 'password123'),
    ('Bob Jones',     'bob@example.com',    '222-22-2222', '4222222222222222', 'qwerty'),
    ('Carol White',   'carol@example.com',  '333-33-3333', '4333333333333333', 'letmein'),
    ('Dan Brown',     'dan@example.com',    '444-44-4444', '4444444444444444', 'admin'),
    ('Eve Davis',     'eve@example.com',    '555-55-5555', '4555555555555555', '123456');

-- Internal billing records
CREATE TABLE IF NOT EXISTS billing (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES users(id),
    plan        VARCHAR(50),
    amount      DECIMAL(10,2),
    card_token  VARCHAR(100)
);

INSERT INTO billing (user_id, plan, amount, card_token) VALUES
    (1, 'enterprise', 999.00, 'tok_enterprise_alice'),
    (2, 'pro',        49.00,  'tok_pro_bob'),
    (3, 'free',       0.00,   NULL);
