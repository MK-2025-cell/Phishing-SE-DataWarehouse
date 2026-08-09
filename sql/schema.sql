-- ============================================================
-- Star Schema DDL: Cybersecurity Phishing/SE Data Warehouse
-- ============================================================

DROP TABLE IF EXISTS fact_incident CASCADE;
DROP TABLE IF EXISTS dim_time CASCADE;
DROP TABLE IF EXISTS dim_attack_type CASCADE;
DROP TABLE IF EXISTS dim_source CASCADE;
DROP TABLE IF EXISTS dim_target CASCADE;
DROP TABLE IF EXISTS dim_severity CASCADE;
DROP TABLE IF EXISTS dim_detection_method CASCADE;

-- ---------------- Dimension Tables ----------------

CREATE TABLE dim_time (
    time_key        SERIAL PRIMARY KEY,
    full_date       DATE NOT NULL UNIQUE,
    day             INT NOT NULL,
    month           INT NOT NULL,
    quarter         INT NOT NULL,
    year            INT NOT NULL,
    day_of_week     VARCHAR(10) NOT NULL,
    is_weekend      BOOLEAN NOT NULL
);

CREATE TABLE dim_attack_type (
    attack_type_key SERIAL PRIMARY KEY,
    attack_category VARCHAR(50) NOT NULL,   -- phishing, social_engineering
    attack_subtype  VARCHAR(100),           -- brand_impersonation, dga_pattern, pretext_internship, etc.
    vector          VARCHAR(30) NOT NULL,   -- url, email, calendar_invite, sms
    UNIQUE (attack_category, attack_subtype, vector)
);

CREATE TABLE dim_source (
    source_key       SERIAL PRIMARY KEY,
    source_domain    VARCHAR(255),
    hosting_platform VARCHAR(100),          -- e.g. netlify.app, self-hosted, unknown
    source_country   VARCHAR(100),
    reputation_score FLOAT,
    UNIQUE (source_domain)
);

CREATE TABLE dim_target (
    target_key       SERIAL PRIMARY KEY,
    target_brand     VARCHAR(150),          -- e.g. facebook, amazon.com, other, unknown
    target_sector    VARCHAR(50),           -- finance/crypto, social_media, retail, tech/telecom, campus, other
    target_audience  VARCHAR(100),          -- for SE data: Faculty/Staff/Students; null for phishing-URL data
    UNIQUE (target_brand, target_sector, target_audience)
);

CREATE TABLE dim_severity (
    severity_key    SERIAL PRIMARY KEY,
    severity_level  VARCHAR(20) NOT NULL UNIQUE,  -- low, medium, high, critical, unknown
    severity_score  INT
);

CREATE TABLE dim_detection_method (
    detection_method_key SERIAL PRIMARY KEY,
    method_name           VARCHAR(100) NOT NULL,
    tool_used             VARCHAR(100),
    UNIQUE (method_name, tool_used)
);

-- ---------------- Fact Table ----------------

CREATE TABLE fact_incident (
    incident_key          SERIAL PRIMARY KEY,
    time_key              INT NOT NULL REFERENCES dim_time(time_key),
    attack_type_key       INT NOT NULL REFERENCES dim_attack_type(attack_type_key),
    source_key            INT REFERENCES dim_source(source_key),
    target_key            INT REFERENCES dim_target(target_key),
    severity_key          INT NOT NULL REFERENCES dim_severity(severity_key),
    detection_method_key  INT NOT NULL REFERENCES dim_detection_method(detection_method_key),
    incident_id           VARCHAR(150) NOT NULL,   -- natural key / source identifier
    data_source           VARCHAR(50) NOT NULL,    -- phreshphish, openphish_kaggle, berkeley_se
    label                 VARCHAR(20),              -- phish / benign (nullable for SE-only rows)
    detection_score       FLOAT,
    response_time_sec     INT,
    financial_loss_est     DECIMAL(12,2),
    is_confirmed          BOOLEAN DEFAULT TRUE,
    url_or_reference       TEXT,
    UNIQUE (incident_id, data_source)
);

-- Indexes for OLAP-style query performance
CREATE INDEX idx_fact_time ON fact_incident(time_key);
CREATE INDEX idx_fact_attack_type ON fact_incident(attack_type_key);
CREATE INDEX idx_fact_source ON fact_incident(source_key);
CREATE INDEX idx_fact_target ON fact_incident(target_key);
CREATE INDEX idx_fact_severity ON fact_incident(severity_key);
CREATE INDEX idx_fact_detection_method ON fact_incident(detection_method_key);
