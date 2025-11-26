import argparse
import joblib
import json
import matplotlib.pyplot as plt
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report
import shap
import os

# Import the cleaner loader
from data_loader import load_dataset


def train_model(csv_path):
    print("--------------------------------------------------")
    print("🚀 Starting Training Pipeline")

    # 1. LOAD
    X, y = load_dataset(csv_path)

    # 2. SPLIT
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 3. TRAIN
    print("🧠 Training XGBoost Model...")
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42
    )
    model.fit(X_train, y_train)

    # 4. EVALUATE
    y_pred = model.predict(X_test)
    print("\n\t\tModel Evaluation")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")

    # 5. SHAP (Explainability)
    # Using TreeExplainer is faster for XGBoost
    print("📊 Generating SHAP Plots...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer(X_test)

    plt.figure()
    shap.summary_plot(shap_values, X_test, show=False)
    if not os.path.exists("shap"): os.makedirs("shap")
    plt.savefig("shap/shap_plot.png", bbox_inches='tight')
    print("   -> Saved 'shap/shap_plot.png'")

    # 6. SAVE MODEL
    if not os.path.exists("model"): os.makedirs("model")
    joblib.dump(model, "model/model.pkl")
    print("💾 Model saved to 'model/model.pkl'")

    # 7. SAVE FEATURES LIST (Critical for Member 2)
    if not os.path.exists("features"): os.makedirs("features")
    features = X.columns.tolist()
    with open("features/features.json", "w") as f:
        json.dump(features, f)
    print("📜 Feature list saved to 'features/features.json'")
    print("--------------------------------------------------")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train XGBoost malware classifier")
    # DEFAULT is now the SMART dataset
    parser.add_argument("--dataset", type=str, default="data/ClaMP_Smart-5184.csv",
                        help="Path to dataset CSV file")
    args = parser.parse_args()

    if not os.path.exists(args.dataset):
        print(f"❌ Error: Dataset '{args.dataset}' not found. Did you run upgrade_dataset.py?")
    else:
        train_model(args.dataset)