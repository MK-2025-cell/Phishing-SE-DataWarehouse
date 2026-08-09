import pandas as pd
import matplotlib
matplotlib.use('Agg')  # saves plots to file instead of trying to show a window
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

df = pd.read_csv('mining_features.csv')
phish = df[df['label'] == 1].copy()

feature_cols = ['url_length', 'path_length', 'subdomain_count', 'is_https',
                 'domain_length', 'has_hyphen', 'digit_count']
X = phish[feature_cols]

# Scale features -- required for K-Means since url_length/domain_length
# are on a totally different scale than is_https (0/1)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# --- Elbow method: try k=2 through k=10, plot inertia (within-cluster SS) ---
inertias = []
silhouettes = []
k_range = range(2, 11)

for k in k_range:
    km = KMeans(n_clusters=k, random_state=42, n_init=10)
    labels = km.fit_predict(X_scaled)
    inertias.append(km.inertia_)
    silhouettes.append(silhouette_score(X_scaled, labels))
    print(f"k={k}: inertia={km.inertia_:.1f}, silhouette={silhouettes[-1]:.3f}")

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
ax1.plot(list(k_range), inertias, marker='o')
ax1.set_xlabel('k'); ax1.set_ylabel('Inertia'); ax1.set_title('Elbow Method')

ax2.plot(list(k_range), silhouettes, marker='o', color='orange')
ax2.set_xlabel('k'); ax2.set_ylabel('Silhouette Score'); ax2.set_title('Silhouette Method')

plt.tight_layout()
plt.savefig('elbow_silhouette.png', dpi=150)
print("\nSaved elbow_silhouette.png -- look at it to pick the best k")
print("Rule of thumb: elbow = where inertia stops dropping sharply;")
print("silhouette = pick k with the HIGHEST score.")
