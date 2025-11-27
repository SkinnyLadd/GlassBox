import pandas as pd

# Load the current dataset
df = pd.read_csv("data/ClaMP_Integrated-5184.csv")

print("Original Shape:", df.shape)

# --- 1. FEATURE ENGINEERING (Create Smart Ratios) ---
# Compression Ratio: (Virtual Size / Raw Size)
# Detects Packers: If code expands 10x in memory, it's likely packed.
df['CompressionRatio'] = df['SizeOfImage'] / df['filesize']

# Code Density: (Code Size / Raw Size)
# Detects Malware: Malware is often 100% code, no images/icons.
df['CodeDensity'] = df['SizeOfCode'] / df['filesize']

# --- 2. REMOVE BIASED COLUMNS ---
# We delete 'filesize' so the model STOPS looking at it.
# We delete the others because we used them to make the ratios.
cols_to_drop = [
    'filesize',
    'SizeOfImage',
    'SizeOfCode',
    'SizeOfInitializedData',
    'SizeOfUninitializedData'
]
df = df.drop(columns=cols_to_drop)

print("New Shape:", df.shape)

# --- 3. SAVE ---
df.to_csv("data/ClaMP_Smart-5184.csv", index=False)
print("✅ Dataset Upgraded! Saved as 'data/ClaMP_Smart-5184.csv'")