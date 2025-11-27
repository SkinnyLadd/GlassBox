import pandas as pd


def load_dataset(csv_path):
    """
    Loads and cleans the dataset from the given path.
    """
    print(f"Loading data from: {csv_path}")
    data = pd.read_csv(csv_path)

    # 1. Fill missing values
    data.fillna(data.median(numeric_only=True), inplace=True)

    # 2. Drop non-numeric columns (Safety check)
    non_numeric_cols = data.select_dtypes(exclude=['int64', 'float64', 'bool']).columns
    if len(non_numeric_cols) > 0:
        print(f"Dropping non-numeric columns: {list(non_numeric_cols)}")
        data = data.drop(non_numeric_cols, axis=1)

    # 3. Separate features (X) and target (y)
    if "class" not in data.columns:
        raise ValueError("Error: 'class' column not found in dataset.")

    X = data.drop("class", axis=1)
    y = data["class"]

    return X, y