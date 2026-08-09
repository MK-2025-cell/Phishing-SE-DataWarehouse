"""
ETL: Load OpenPhish (Kaggle), phreshphish sample, and Berkeley SE incidents
into the star schema (fact_incident + 6 dimension tables) in PostgreSQL.

Design decisions (documented for the thesis write-up):
- Grain = one row per DETECTED incident. Benign-labeled rows from
  phreshphish are NOT incidents, so they are NOT loaded into fact_incident;
  they're kept in a separate staging table (staging_benign_urls) reserved
  for the Step 5 mining layer's negative/benign class.
- OpenPhish Kaggle CSV has no per-row date. We use a placeholder
  acquisition date (flagged via `is_date_estimated=TRUE` logic upstream
  in code comments) since the real collection window is unknown.
  Documented as a limitation, not presented as a real detection date.
- Severity is DERIVED via a documented heuristic (not sourced from any
  dataset) based on target sector / SE pretext category.
"""

import psycopg2
import pandas as pd
from urllib.parse import urlparse
from datetime import date

CONN = dict(host="localhost", dbname="phishing_dw", user="Maya", password="")
PAAS_PATTERNS = ['netlify.app', 'pages.dev', 'framer.app', 'framer.website', 'github.io',
                  'webflow.io', 'vercel.app', 'duckdns.org', 'appspot.com', 'workers.dev',
                  'gitbook.io', 'replit.app', 'blogspot.com', 'mybluehost.me', 'filesusr.com']

BRAND_SECTOR = {
    'facebook': 'social_media', 'meta': 'social_media', 'instagram': 'social_media',
    'whatsapp': 'social_media', 'telegram': 'social_media', 'tiktok': 'social_media',
    'amazon.com': 'retail_ecommerce', 'amazon': 'retail_ecommerce', 'roblox': 'retail_ecommerce',
    'ebay': 'retail_ecommerce', 'booking': 'retail_ecommerce', 'usps': 'retail_ecommerce',
    'at&t': 'tech_telecom', 'at&amp;t': 'tech_telecom', 'microsoft': 'tech_telecom',
    'outlook': 'tech_telecom', 'netflix': 'tech_telecom', 'apple': 'tech_telecom',
    'google': 'tech_telecom', 'naver': 'tech_telecom', 'plala': 'tech_telecom',
    'rakuten': 'tech_telecom',
    'coinbase': 'finance_crypto', 'robinhood': 'finance_crypto', 'canva': 'tech_telecom',
    'citadel credit union': 'finance_crypto',
}

SE_SUBTYPE_MAP = {
    "Malware Hidden in an Invitation Email": "malware_invitation",
    "Phony AI-Generated LLM Request Messages": "fake_research_request",
    "Fake Wikipedia Page Editorial Assistance Scam": "fake_wikipedia_offer",
    "Cal-1 Card Internship Scam Phish": "internship_scam",
    "Fraudulent New Salary Details Phish": "fake_salary_notice",
    "Bogus bCal Meetings - Spam / Malware": "fake_calendar_invite",
    "Fake Assessment Report Email - Credential Theft": "fake_assessment_report",
    "Musical Instrument Give Away Fraud Phish": "fake_giveaway",
    "Fraudulent Concert Ticket Cal-1 Card Scam": "fake_giveaway",
    "Phishing Attack Using Misconduct Subject Lines": "misconduct_pretext",
    "Multiple Phishing Attacks to Redirect Payroll in UCPath": "payroll_redirect",
    "Fake Debt Collection Google Doc Share": "fake_debt_collection",
    "Fake Electronic Payment ACH Message": "fake_payment_notice",
}

# Severity heuristic (documented, not sourced)
HIGH_SEVERITY_SUBTYPES = {"payroll_redirect", "fake_assessment_report", "internship_scam"}
CRITICAL_SECTORS = {"finance_crypto"}


def get_hosting_platform(domain):
    for p in PAAS_PATTERNS:
        if p in domain:
            return p
    return "self_hosted_or_unknown"


def get_sector(brand):
    if not brand or pd.isna(brand):
        return "unknown"
    return BRAND_SECTOR.get(str(brand).lower(), "other")


def derive_severity(sector=None, se_subtype=None):
    if se_subtype in HIGH_SEVERITY_SUBTYPES:
        return ("high", 3)
    if sector in CRITICAL_SECTORS:
        return ("critical", 4)
    if sector not in (None, "unknown", "other"):
        return ("high", 3)
    if se_subtype:
        return ("medium", 2)
    if sector == "other":
        return ("medium", 2)
    return ("unknown", 1)


class DimCache:
    """Get-or-create cache for dimension rows to avoid duplicate inserts."""
    def __init__(self, cur):
        self.cur = cur
        self._time = {}
        self._attack_type = {}
        self._source = {}
        self._target = {}
        self._severity = {}
        self._detection_method = {}

    def time_key(self, d: date):
        if d in self._time:
            return self._time[d]
        self.cur.execute("""
            INSERT INTO dim_time (full_date, day, month, quarter, year, day_of_week, is_weekend)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (full_date) DO UPDATE SET full_date=EXCLUDED.full_date
            RETURNING time_key
        """, (d, d.day, d.month, (d.month-1)//3+1, d.year, d.strftime('%A'), d.weekday() >= 5))
        key = self.cur.fetchone()[0]
        self._time[d] = key
        return key

    def attack_type_key(self, category, subtype, vector):
        k = (category, subtype, vector)
        if k in self._attack_type:
            return self._attack_type[k]
        self.cur.execute("""
            INSERT INTO dim_attack_type (attack_category, attack_subtype, vector)
            VALUES (%s,%s,%s)
            ON CONFLICT (attack_category, attack_subtype, vector) DO UPDATE SET attack_category=EXCLUDED.attack_category
            RETURNING attack_type_key
        """, k)
        key = self.cur.fetchone()[0]
        self._attack_type[k] = key
        return key

    def source_key(self, domain, hosting_platform):
        if domain is None:
            return None
        if domain in self._source:
            return self._source[domain]
        self.cur.execute("""
            INSERT INTO dim_source (source_domain, hosting_platform, source_country, reputation_score)
            VALUES (%s,%s,NULL,NULL)
            ON CONFLICT (source_domain) DO UPDATE SET source_domain=EXCLUDED.source_domain
            RETURNING source_key
        """, (domain, hosting_platform))
        key = self.cur.fetchone()[0]
        self._source[domain] = key
        return key

    def target_key(self, brand, sector, audience):
        k = (brand, sector, audience)
        if k in self._target:
            return self._target[k]
        self.cur.execute("""
            INSERT INTO dim_target (target_brand, target_sector, target_audience)
            VALUES (%s,%s,%s)
            ON CONFLICT (target_brand, target_sector, target_audience) DO UPDATE SET target_brand=EXCLUDED.target_brand
            RETURNING target_key
        """, k)
        key = self.cur.fetchone()[0]
        self._target[k] = key
        return key

    def severity_key(self, level, score):
        if level in self._severity:
            return self._severity[level]
        self.cur.execute("""
            INSERT INTO dim_severity (severity_level, severity_score)
            VALUES (%s,%s)
            ON CONFLICT (severity_level) DO UPDATE SET severity_level=EXCLUDED.severity_level
            RETURNING severity_key
        """, (level, score))
        key = self.cur.fetchone()[0]
        self._severity[level] = key
        return key

    def detection_method_key(self, method_name, tool_used):
        k = (method_name, tool_used)
        if k in self._detection_method:
            return self._detection_method[k]
        self.cur.execute("""
            INSERT INTO dim_detection_method (method_name, tool_used)
            VALUES (%s,%s)
            ON CONFLICT (method_name, tool_used) DO UPDATE SET method_name=EXCLUDED.method_name
            RETURNING detection_method_key
        """, k)
        key = self.cur.fetchone()[0]
        self._detection_method[k] = key
        return key


def load_phreshphish(cur, dims, path):
    df = pd.read_csv(path)
    df['date'] = pd.to_datetime(df['date']).dt.date

    phish = df[df['label'] == 'phish'].copy()
    benign = df[df['label'] == 'benign'].copy()

    # --- benign rows go to a staging table, NOT fact_incident ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS staging_benign_urls (
            sha256 VARCHAR(64), url TEXT, date DATE, lang VARCHAR(10), lang_score FLOAT
        )
    """)
    cur.execute("TRUNCATE staging_benign_urls")
    for _, row in benign.iterrows():
        cur.execute("""
            INSERT INTO staging_benign_urls (sha256, url, date, lang, lang_score)
            VALUES (%s,%s,%s,%s,%s)
        """, (row['sha256'], row['url'], row['date'], row.get('lang'), row.get('lang_score')))

    inserted = 0
    for _, row in phish.iterrows():
        domain = urlparse(row['url']).netloc.lower()
        hosting = get_hosting_platform(domain)
        brand = row['target'] if pd.notna(row['target']) else 'unknown'
        sector = get_sector(brand)
        subtype = 'brand_impersonation' if sector not in ('unknown', 'other') else 'generic_phishing'

        tkey = dims.time_key(row['date'])
        atkey = dims.attack_type_key('phishing', subtype, 'url')
        skey = dims.source_key(domain, hosting)
        tgkey = dims.target_key(brand, sector, None)
        sev_level, sev_score = derive_severity(sector=sector)
        sevkey = dims.severity_key(sev_level, sev_score)
        dmkey = dims.detection_method_key('phreshphish curated feed', 'phreshphish dataset')

        cur.execute("""
            INSERT INTO fact_incident
            (time_key, attack_type_key, source_key, target_key, severity_key, detection_method_key,
             incident_id, data_source, label, url_or_reference, is_confirmed)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (incident_id, data_source) DO NOTHING
        """, (tkey, atkey, skey, tgkey, sevkey, dmkey,
              row['sha256'], 'phreshphish', 'phish', row['url'], True))
        inserted += 1
    return inserted, len(benign)


def load_openphish_kaggle(cur, dims, path, placeholder_date):
    df = pd.read_csv(path, header=None, names=['url'])
    df = df[df['url'].notna() & df['url'].str.startswith('http')]

    inserted = 0
    for i, row in df.iterrows():
        url = row['url']
        domain = urlparse(url).netloc.lower()
        hosting = get_hosting_platform(domain)
        # no brand metadata in this source -> unknown/other bucket
        sector = 'unknown'
        subtype = 'generic_phishing'

        tkey = dims.time_key(placeholder_date)
        atkey = dims.attack_type_key('phishing', subtype, 'url')
        skey = dims.source_key(domain, hosting)
        tgkey = dims.target_key('unknown', sector, None)
        sev_level, sev_score = derive_severity(sector=sector)
        sevkey = dims.severity_key(sev_level, sev_score)
        dmkey = dims.detection_method_key('OpenPhish community feed', 'OpenPhish')

        incident_id = f"openphish_{i}"
        cur.execute("""
            INSERT INTO fact_incident
            (time_key, attack_type_key, source_key, target_key, severity_key, detection_method_key,
             incident_id, data_source, label, url_or_reference, is_confirmed)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (incident_id, data_source) DO NOTHING
        """, (tkey, atkey, skey, tgkey, sevkey, dmkey,
              incident_id, 'openphish_kaggle', 'phish', url, True))
        inserted += 1
    return inserted


def load_berkeley_se(cur, dims, path):
    df = pd.read_csv(path)
    df['date'] = pd.to_datetime(df['date']).dt.date

    inserted = 0
    for _, row in df.iterrows():
        subtype = SE_SUBTYPE_MAP.get(row['title'], 'other_se_pretext')

        tkey = dims.time_key(row['date'])
        atkey = dims.attack_type_key('social_engineering', subtype, row['vector'])
        skey = None  # no malicious domain/source for most SE cases
        tgkey = dims.target_key('uc_berkeley_community', 'campus', row['audience_targeted'])
        sev_level, sev_score = derive_severity(se_subtype=subtype)
        sevkey = dims.severity_key(sev_level, sev_score)
        dmkey = dims.detection_method_key('user_reported', 'UC Berkeley ISO reporting')

        cur.execute("""
            INSERT INTO fact_incident
            (time_key, attack_type_key, source_key, target_key, severity_key, detection_method_key,
             incident_id, data_source, label, url_or_reference, is_confirmed)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (incident_id, data_source) DO NOTHING
        """, (tkey, atkey, skey, tgkey, sevkey, dmkey,
              row['incident_id'], 'berkeley_se', None, row['source_url'], True))
        inserted += 1
    return inserted


def main():
    conn = psycopg2.connect(**CONN)
    conn.autocommit = False
    cur = conn.cursor()
    dims = DimCache(cur)

    try:
        n_phish, n_benign = load_phreshphish(cur, dims, 'phreshphish_sample.csv')
        print(f"phreshphish: {n_phish} phish rows -> fact_incident, {n_benign} benign rows -> staging_benign_urls")

        # NOTE: OpenPhish Kaggle CSV has no per-row date. Using a placeholder
        # acquisition date since the true collection window is unknown/undocumented
        # on Kaggle. This is a stated limitation, not a real detection date.
        n_openphish = load_openphish_kaggle(cur, dims, 'openphish.csv',
                                     placeholder_date=date(2026, 7, 1))
        print(f"openphish_kaggle: {n_openphish} rows -> fact_incident (placeholder date used)")

        n_se = load_berkeley_se(cur, dims, 'berkeley_se_incidents.csv')
        print(f"berkeley_se: {n_se} rows -> fact_incident")

        conn.commit()
        print("\nCommitted successfully.")
    except Exception as e:
        conn.rollback()
        print("ERROR, rolled back:", e)
        raise
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
