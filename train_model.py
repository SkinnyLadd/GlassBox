import argparse
import joblib
import json
import matplotlib.pyplot as plt
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report
import shap
from data_loader import load_dataset

def train_model(csv_path="data/ClaMP_Integrated-5184.csv"):
    #load dataset
    X, y = load_dataset(csv_path)

    #train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    #train XGBoost classifier
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n\t\tModel Evaluation")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))

    #SHAP explainability
    explainer = shap.Explainer(model, X_train)
    shap_values = explainer(X_test)
    plt.figure()
    shap.summary_plot(shap_values, X_test, show=False)
    plt.savefig("shap/shap_plot.png")
    print("SHAP plot saved as shap_plot.png")

    #saving model
    joblib.dump(model, "model/model.pkl")
    print("Trained model saved as model.pkl")

    #save feature list
    features = X.columns.tolist()
    with open("features/features.json", "w") as f:
        json.dump(features, f)
    print("Feature list saved as features.json")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train XGBoost malware classifier")
    parser.add_argument("--dataset", type=str, default="data/ClaMP_Smart-5184.csv",
                        help="Path to dataset CSV file")
    args = parser.parse_args()

    train_model(args.dataset)
