def load_dataset(csv_path="data/ClaMP_Integrated-5184.csv"):
    import pandas as pd
    
    data = pd.read_csv(csv_path)

    #preprocessing
    
    #fill missing values with median
    data.fillna(data.median(numeric_only=True), inplace=True)

    #drop any non-numeric columns
    non_numeric_cols = data.select_dtypes(exclude=['int64', 'float64', 'bool']).columns
    if len(non_numeric_cols) > 0:
        print(f"Dropping non-numeric columns: {list(non_numeric_cols)}")
        data = data.drop(non_numeric_cols, axis=1)

    #separate features and target
    X = data.drop("class", axis=1)
    y = data["class"]

    return X, y
