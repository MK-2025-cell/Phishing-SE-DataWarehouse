import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import (classification_report, confusion_matrix,
                              ConfusionMatrixDisplay, accuracy_score,
                              precision_score, recall_score, f1_score)

df = pd.read_csv('mining_features.csv')

feature_cols = ['url_length', 'path_length', 'subdomain_count', 'is_https',
                 'domain_length', 'has_hyphen', 'digit_count']
X = df[feature_cols]
y = df['label']  # 1 = phishing, 0 = benign

print("Class balance:")
print(y.value_counts())

# Stratified split -- keeps the same 11:1 ratio in both train and test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# class_weight='balanced' -- this is the key fix for the 11:1 imbalance.
# It automatically penalizes misclassifying the minority class (benign)
# more heavily during training, instead of letting the model just learn
# to always predict "phishing" and still score high accuracy.
clf = SVC(kernel='rbf', class_weight='balanced', random_state=42)
clf.fit(X_train_scaled, y_train)

y_pred = clf.predict(X_test_scaled)

print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred, target_names=['benign', 'phishing']))

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
print(f"Accuracy:  {acc:.3f}")
print(f"Precision: {prec:.3f}")
print(f"Recall:    {rec:.3f}")
print(f"F1 score:  {f1:.3f}")

# --- Confusion matrix plot ---
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['benign', 'phishing'])
disp.plot(cmap='Blues')
plt.title('SVM Confusion Matrix (class_weight=balanced)')
plt.savefig('confusion_matrix.png', dpi=150, bbox_inches='tight')
print("\nSaved confusion_matrix.png")

# --- Also try WITHOUT class_weight for comparison, to show why it matters ---
clf_naive = SVC(kernel='rbf', random_state=42)  # no class_weight
clf_naive.fit(X_train_scaled, y_train)
y_pred_naive = clf_naive.predict(X_test_scaled)

print("\n=== Comparison: WITHOUT class_weight='balanced' ===")
print(classification_report(y_test, y_pred_naive, target_names=['benign', 'phishing']))
print(f"Naive accuracy: {accuracy_score(y_test, y_pred_naive):.3f}")
print(f"Naive recall (benign class): {recall_score(y_test, y_pred_naive, pos_label=0):.3f}")
print(f"Balanced recall (benign class): {recall_score(y_test, y_pred, pos_label=0):.3f}")
