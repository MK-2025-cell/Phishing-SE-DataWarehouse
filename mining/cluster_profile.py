import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

df = pd.read_csv('mining_features.csv')
phish = df[df['label'] == 1].copy()

feature_cols = ['url_length', 'path_length', 'subdomain_count', 'is_https',
                 'domain_length', 'has_hyphen', 'digit_count']
X = phish[feature_cols]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

for k in [2, 4, 5, 9]:
    print(f"\n{'='*60}")
    print(f"k = {k}")
    print('='*60)
    km = KMeans(n_clusters=k, random_state=42, n_init=10)
    phish['cluster'] = km.fit_predict(X_scaled)

    print("\nCluster sizes:")
    print(phish['cluster'].value_counts().sort_index())

    print("\nCluster centroids (mean feature values, UNSCALED for readability):")
    profile = phish.groupby('cluster')[feature_cols].mean().round(2)
    print(profile)
