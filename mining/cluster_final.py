import psycopg2
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA

CONN = dict(host="localhost", dbname="phishing_dw", user="Maya", password="")

# --- Re-pull phishing rows WITH incident_id so we can write clusters back ---
conn = psycopg2.connect(**CONN)
phish = pd.read_sql("""
    SELECT f.incident_id, f.url_or_reference AS url
    FROM fact_incident f
    WHERE f.data_source IN ('phreshphish', 'openphish_kaggle')
""", conn)
conn.close()

from urllib.parse import urlparse
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

feat = phish['url'].apply(extract_features)
phish = pd.concat([phish, feat], axis=1)

feature_cols = ['url_length', 'path_length', 'subdomain_count', 'is_https',
                 'domain_length', 'has_hyphen', 'digit_count']
X = phish[feature_cols]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# --- Fit final k=4 model ---
km = KMeans(n_clusters=4, random_state=42, n_init=10)
phish['cluster'] = km.fit_predict(X_scaled)

# --- Name clusters dynamically based on centroid characteristics ---
profile = phish.groupby('cluster')[feature_cols].mean()

def name_cluster(row):
    if row['url_length'] > 150:
        return 'long_obfuscated_url'
    elif row['has_hyphen'] > 0.5 and row['digit_count'] > 7:
        return 'hyphenated_numeric_lookalike'
    elif row['has_hyphen'] > 0.5:
        return 'hyphen_based_generic_phishing'
    elif row['has_hyphen'] < 0.2:
        return 'plain_short_domain_phishing'
    else:
        return 'mixed_pattern'

cluster_names = {idx: name_cluster(row) for idx, row in profile.iterrows()}
phish['cluster_name'] = phish['cluster'].map(cluster_names)

print("Cluster naming:")
for idx, name in cluster_names.items():
    print(f"  cluster {idx} -> {name} (n={sum(phish['cluster']==idx)})")

print("\nFull profile:")
print(profile.round(2))

# --- Visualization: PCA to 2D for a scatter plot ---
pca = PCA(n_components=2, random_state=42)
X_pca = pca.fit_transform(X_scaled)
phish['pca1'] = X_pca[:, 0]
phish['pca2'] = X_pca[:, 1]

plt.figure(figsize=(9, 7))
for name in phish['cluster_name'].unique():
    sub = phish[phish['cluster_name'] == name]
    plt.scatter(sub['pca1'], sub['pca2'], label=name, alpha=0.5, s=15)
plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]*100:.1f}% variance)')
plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]*100:.1f}% variance)')
plt.title('Phishing URL Structural Clusters (k=4)')
plt.legend()
plt.tight_layout()
plt.savefig('clusters_pca.png', dpi=150)
print("\nSaved clusters_pca.png")

# --- Write cluster assignments back into the warehouse ---
conn = psycopg2.connect(**CONN)
cur = conn.cursor()
cur.execute("""
    CREATE TABLE IF NOT EXISTS mining_cluster_results (
        incident_id VARCHAR(150) PRIMARY KEY,
        cluster_id INT,
        cluster_name VARCHAR(100)
    )
""")
cur.execute("TRUNCATE mining_cluster_results")
for _, row in phish.iterrows():
    cur.execute("""
        INSERT INTO mining_cluster_results (incident_id, cluster_id, cluster_name)
        VALUES (%s, %s, %s)
        ON CONFLICT (incident_id) DO UPDATE SET cluster_id=EXCLUDED.cluster_id, cluster_name=EXCLUDED.cluster_name
    """, (row['incident_id'], int(row['cluster']), row['cluster_name']))
conn.commit()
cur.close()
conn.close()
print(f"\nWrote {len(phish)} cluster assignments to mining_cluster_results table (joinable to fact_incident via incident_id)")

phish.to_csv('clustered_phishing.csv', index=False)
print("Saved clustered_phishing.csv")
