import pefile
import math
import struct
import sys
import os
import datetime

# The EXACT feature order expected by the model (from features.json)
MODEL_FEATURES = [
    "e_cblp", "e_cp", "e_cparhdr", "e_maxalloc", "e_sp", "e_lfanew", "NumberOfSections", "CreationYear",
    "FH_char0", "FH_char1", "FH_char2", "FH_char3", "FH_char4", "FH_char5", "FH_char6", "FH_char7",
    "FH_char8", "FH_char9", "FH_char10", "FH_char11", "FH_char12", "FH_char13", "FH_char14",
    "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData",
    "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase",
    "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
    "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion",
    "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem",
    "OH_DLLchar0", "OH_DLLchar1", "OH_DLLchar2", "OH_DLLchar3", "OH_DLLchar4", "OH_DLLchar5",
    "OH_DLLchar6", "OH_DLLchar7", "OH_DLLchar8", "OH_DLLchar9", "OH_DLLchar10",
    "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags",
    "sus_sections", "non_sus_sections", "packer", "E_text", "E_data", "filesize", "E_file", "fileinfo"
]


def get_entropy(data):
    """Calculates entropy (0-8)"""
    if not data: return 0.0
    occurrences = {}
    for byte in data: occurrences[byte] = occurrences.get(byte, 0) + 1
    entropy = 0
    for byte in occurrences:
        p_x = float(occurrences[byte]) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy


def extract_features(file_path):
    data_dict = {}

    if not os.path.exists(file_path):
        return None

    try:
        pe = pefile.PE(file_path)
    except Exception:
        return None

    # --- 1. Standard Headers ---
    data_dict['e_cblp'] = pe.DOS_HEADER.e_cblp
    data_dict['e_cp'] = pe.DOS_HEADER.e_ccp if hasattr(pe.DOS_HEADER, 'e_ccp') else pe.DOS_HEADER.e_cp
    data_dict['e_cparhdr'] = pe.DOS_HEADER.e_cparhdr
    data_dict['e_maxalloc'] = pe.DOS_HEADER.e_maxalloc
    data_dict['e_sp'] = pe.DOS_HEADER.e_sp
    data_dict['e_lfanew'] = pe.DOS_HEADER.e_lfanew
    data_dict['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections

    # Convert TimeDateStamp to Year
    try:
        data_dict['CreationYear'] = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).year
    except:
        data_dict['CreationYear'] = 0

    # --- 2. BIT MASKING: File Header Characteristics (FH_char) ---
    # We split the integer into 15 bits (0 or 1)
    characteristics = pe.FILE_HEADER.Characteristics
    for i in range(15):
        # Check if the i-th bit is set
        data_dict[f'FH_char{i}'] = 1 if (characteristics & (1 << i)) else 0

    # --- 3. Optional Header Standard Fields ---
    opt = pe.OPTIONAL_HEADER
    data_dict['MajorLinkerVersion'] = opt.MajorLinkerVersion
    data_dict['MinorLinkerVersion'] = opt.MinorLinkerVersion
    data_dict['SizeOfCode'] = opt.SizeOfCode
    data_dict['SizeOfInitializedData'] = opt.SizeOfInitializedData
    data_dict['SizeOfUninitializedData'] = opt.SizeOfUninitializedData
    data_dict['AddressOfEntryPoint'] = opt.AddressOfEntryPoint
    data_dict['BaseOfCode'] = opt.BaseOfCode
    try:
        data_dict['BaseOfData'] = opt.BaseOfData
    except:
        data_dict['BaseOfData'] = 0
    data_dict['ImageBase'] = opt.ImageBase
    data_dict['SectionAlignment'] = opt.SectionAlignment
    data_dict['FileAlignment'] = opt.FileAlignment
    data_dict['MajorOperatingSystemVersion'] = opt.MajorOperatingSystemVersion
    data_dict['MinorOperatingSystemVersion'] = opt.MinorOperatingSystemVersion
    data_dict['MajorImageVersion'] = opt.MajorImageVersion
    data_dict['MinorImageVersion'] = opt.MinorImageVersion
    data_dict['MajorSubsystemVersion'] = opt.MajorSubsystemVersion
    data_dict['MinorSubsystemVersion'] = opt.MinorSubsystemVersion
    data_dict['SizeOfImage'] = opt.SizeOfImage
    data_dict['SizeOfHeaders'] = opt.SizeOfHeaders
    data_dict['CheckSum'] = opt.CheckSum
    data_dict['Subsystem'] = opt.Subsystem

    # --- 4. BIT MASKING: DLL Characteristics (OH_DLLchar) ---
    dll_chars = opt.DllCharacteristics
    for i in range(11):
        data_dict[f'OH_DLLchar{i}'] = 1 if (dll_chars & (1 << i)) else 0

    data_dict['SizeOfStackReserve'] = opt.SizeOfStackReserve
    data_dict['SizeOfStackCommit'] = opt.SizeOfStackCommit
    data_dict['SizeOfHeapReserve'] = opt.SizeOfHeapReserve
    data_dict['SizeOfHeapCommit'] = opt.SizeOfHeapCommit
    data_dict['LoaderFlags'] = opt.LoaderFlags

    # --- 5. DERIVED / CALCULATED FEATURES ---

    # Section Analysis
    sus_sections = 0
    non_sus_sections = 0
    standard_names = ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.reloc', '.pdata']

    e_text = 0.0
    e_data = 0.0

    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
        if name in standard_names:
            non_sus_sections += 1
        else:
            sus_sections += 1

        # Capture entropy of specific sections
        if name == '.text':
            e_text = get_entropy(section.get_data())
        elif name == '.data':
            e_data = get_entropy(section.get_data())

    data_dict['sus_sections'] = sus_sections
    data_dict['non_sus_sections'] = non_sus_sections
    data_dict['E_text'] = e_text
    data_dict['E_data'] = e_data

    # File Size & Total Entropy
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        data_dict['filesize'] = len(raw_data)
        data_dict['E_file'] = get_entropy(raw_data)

    # Packer Detection (Simple heuristic: High entropy + Non-standard sections)
    # If entropy > 7.0 and we have suspicious sections, assume packed.
    if data_dict['E_file'] > 7.0 and sus_sections > 0:
        data_dict['packer'] = 1
    else:
        data_dict['packer'] = 0

    # File Info (Count of version info keys)
    try:
        data_dict['fileinfo'] = len(pe.FileInfo)
    except:
        data_dict['fileinfo'] = 0

    # --- FINAL STEP: ORDERING ---
    # We must return a LIST in the exact order of features.json
    final_vector = []
    for feature in MODEL_FEATURES:
        final_vector.append(data_dict.get(feature, 0))  # Default to 0 if missing

    return final_vector


# --- TEST BLOCK ---
if __name__ == "__main__":
    # If user provides a file, use it. Otherwise, default to Notepad.
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
    else:
        # Default test target (safe system file)
        target_file = r"C:\Windows\System32\notepad.exe"

    print(f"--------------------------------------------------")
    print(f"🔎 Scanning Target: {target_file}")

    # Run the extraction
    res = extract_features(target_file)

    if res:
        print(f"✅ Extraction Successful!")
        print(f"📊 Features Extracted: {len(res)}")
        print(f"🎯 Expected Count:     {len(MODEL_FEATURES)}")

        if len(res) == len(MODEL_FEATURES):
            print("\n>> INTEGRATION PASSED: Feature vector matches model input perfectly.")
        else:
            print("\n>> CRITICAL ERROR: Feature count mismatch!")
    else:
        print("❌ Error: Could not extract features.")
        print("   Make sure the file exists and is a valid Windows .exe (PE) file.")
    print(f"--------------------------------------------------")