import psycopg2
import pandas as pd
from urllib.parse import urlparse

CONN = dict(host="localhost", dbname="phishing_dw", user="Maya", password="")

conn = psycopg2.connect(**CONN)

# --- Pull phishing incidents (from fact_incident, URL-based sources only) ---
phish_query = """
    SELECT f.incident_id, f.url_or_reference AS url, f.data_source,
           s.hosting_platform, t.target_sector, sv.severity_level
    FROM fact_incident f
    LEFT JOIN dim_source s ON f.source_key = s.source_key
    LEFT JOIN dim_target t ON f.target_key = t.target_key
    JOIN dim_severity sv ON f.severity_key = sv.severity_key
    WHERE f.data_source IN ('phreshphish', 'openphish_kaggle')
"""
phish_df = pd.read_sql(phish_query, conn)
phish_df['label'] = 1  # phishing

# --- Pull benign URLs (held-out staging table) ---
benign_df = pd.read_sql("SELECT url FROM staging_benign_urls", conn)
benign_df['label'] = 0  # benign

conn.close()

print("Phishing rows:", len(phish_df))
print("Benign rows:", len(benign_df))

# --- Feature engineering (same logic as our earlier ETL exploration) ---
def extract_features(url):
    p = urlparse(url)
    domain = p.netloc.lower()
    return pd.Series({
        'url_length': len(url),
        'path_length': len(p.path),
        'subdomain_count': max(domain.count('.') - 1, 0),
        'is_https': 1 if p.scheme == 'https' else 0,
        'domain_length': len(domain),
        'has_hyphen': 1 if '-' in domain else 0,
        'digit_count': sum(c.isdigit() for c in url),
    })

phish_feat = phish_df['url'].apply(extract_features)
benign_feat = benign_df['url'].apply(extract_features)

phish_full = pd.concat([phish_df[['url', 'label']], phish_feat], axis=1)
benign_full = pd.concat([benign_df[['url', 'label']], benign_feat], axis=1)

full_df = pd.concat([phish_full, benign_full], ignore_index=True)
full_df.to_csv('mining_features.csv', index=False)

print("\nCombined feature set shape:", full_df.shape)
print(full_df.head())
print("\nLabel balance:")
print(full_df['label'].value_counts())
