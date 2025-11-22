import pefile
import math
import struct
import sys
import os


def get_entropy(data):
    """
    Calculates the entropy (randomness) of a chunk of data.
    Returns a float between 0.0 (all zeros) and 8.0 (total chaos).
    """
    if not data:
        return 0.0

    # counting how many times each byte appears in the data
    occurrences = {}
    for byte in data:
        occurrences[byte] = occurrences.get(byte, 0) + 1

    # calculating the math formula for entropy (Shannon Entropy)
    entropy = 0
    total_len = len(data)
    for byte in occurrences:
        p_x = float(occurrences[byte]) / total_len
        entropy -= p_x * math.log(p_x, 2)

    return entropy


def extract_features(file_path):
    """
    Extracts the specific raw + derived features used in ClaMP.
    Returns a DICTIONARY of features ready for the AI model.
    """
    features = {}

    # checking if file exists before we crash everything
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return None

    try:
        # loading the PE file using the library
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"Error parsing file {file_path}: {e}")
        return None

    # --- 1. DOS HEADER (The old school header) ---
    # grabbing these weirdly named fields that viruses often mess up
    features['e_magic'] = pe.DOS_HEADER.e_magic
    features['e_cblp'] = pe.DOS_HEADER.e_cblp
    features['e_cp'] = pe.DOS_HEADER.e_cp
    features['e_crlc'] = pe.DOS_HEADER.e_crlc
    features['e_cparhdr'] = pe.DOS_HEADER.e_cparhdr
    features['e_minalloc'] = pe.DOS_HEADER.e_minalloc
    features['e_maxalloc'] = pe.DOS_HEADER.e_maxalloc
    features['e_ss'] = pe.DOS_HEADER.e_ss
    features['e_sp'] = pe.DOS_HEADER.e_sp
    features['e_csum'] = pe.DOS_HEADER.e_csum
    features['e_ip'] = pe.DOS_HEADER.e_ip
    features['e_cs'] = pe.DOS_HEADER.e_cs
    features['e_lfarlc'] = pe.DOS_HEADER.e_lfarlc
    features['e_ovno'] = pe.DOS_HEADER.e_ovno
    features['e_res'] = 0  # usually reserved so we just putting 0
    features['e_oemid'] = pe.DOS_HEADER.e_oemid
    features['e_oeminfo'] = pe.DOS_HEADER.e_oeminfo
    features['e_res2'] = 0
    features['e_lfanew'] = pe.DOS_HEADER.e_lfanew

    # --- 2. FILE HEADER (General info) ---
    features['Machine'] = pe.FILE_HEADER.Machine
    features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
    features['CreationYear'] = 0  # ignoring this cause it's not in the raw header
    features['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable
    features['NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
    features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    features['Characteristics'] = pe.FILE_HEADER.Characteristics

    # --- 3. OPTIONAL HEADER (The juicy stuff) ---
    # using a try block cause some old files might miss these
    try:
        opt = pe.OPTIONAL_HEADER
        features['Magic'] = opt.Magic
        features['MajorLinkerVersion'] = opt.MajorLinkerVersion
        features['MinorLinkerVersion'] = opt.MinorLinkerVersion
        features['SizeOfCode'] = opt.SizeOfCode
        features['SizeOfInitializedData'] = opt.SizeOfInitializedData
        features['SizeOfUninitializedData'] = opt.SizeOfUninitializedData
        features['AddressOfEntryPoint'] = opt.AddressOfEntryPoint
        features['BaseOfCode'] = opt.BaseOfCode

        # handling 32-bit vs 64-bit difference for BaseOfData
        try:
            features['BaseOfData'] = opt.BaseOfData
        except AttributeError:
            features['BaseOfData'] = 0

        features['ImageBase'] = opt.ImageBase
        features['SectionAlignment'] = opt.SectionAlignment
        features['FileAlignment'] = opt.FileAlignment
        features['MajorOperatingSystemVersion'] = opt.MajorOperatingSystemVersion
        features['MinorOperatingSystemVersion'] = opt.MinorOperatingSystemVersion
        features['MajorImageVersion'] = opt.MajorImageVersion
        features['MinorImageVersion'] = opt.MinorImageVersion
        features['MajorSubsystemVersion'] = opt.MajorSubsystemVersion
        features['MinorSubsystemVersion'] = opt.MinorSubsystemVersion
        features['SizeOfImage'] = opt.SizeOfImage
        features['SizeOfHeaders'] = opt.SizeOfHeaders
        features['CheckSum'] = opt.CheckSum
        features['Subsystem'] = opt.Subsystem
        features['DllCharacteristics'] = opt.DllCharacteristics
        features['SizeOfStackReserve'] = opt.SizeOfStackReserve
        features['SizeOfStackCommit'] = opt.SizeOfStackCommit
        features['SizeOfHeapReserve'] = opt.SizeOfHeapReserve
        features['SizeOfHeapCommit'] = opt.SizeOfHeapCommit
        features['LoaderFlags'] = opt.LoaderFlags
        features['NumberOfRvaAndSizes'] = opt.NumberOfRvaAndSizes
    except Exception as e:
        print(f"Warning: Optional Header issue: {e}")

    # --- 4. DERIVED FEATURES (The 'Special Sauce') ---
    # calculating the entropy of the whole file to spot packed malware
    try:
        # reading the raw bytes from disk
        with open(file_path, 'rb') as f:
            data = f.read()
            features['Entropy'] = get_entropy(data)
    except:
        features['Entropy'] = 0

    # counting how many DLLs the file imports
    # normal files import many (kernel32, user32), malware often imports few
    try:
        features['ImportedDlls'] = len(pe.DIRECTORY_ENTRY_IMPORT)
    except AttributeError:
        features['ImportedDlls'] = 0

    # finding the most chaotic section (often where the virus hides)
    max_entropy = 0
    for section in pe.sections:
        ent = section.get_entropy()
        if ent > max_entropy:
            max_entropy = ent
    features['MaxSectionEntropy'] = max_entropy

    return features


# --- TEST BLOCK ---
# running this directly to see if it works
if __name__ == "__main__":
    # check if user gave a file path
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        print(f"Scanning: {target_file} ...")
        res = extract_features(target_file)

        if res:
            print("\n--- EXTRACTED FEATURES ---")
            # printing just a few important ones to verify
            print(f"Entropy: {res.get('Entropy', 0):.4f}")
            print(f"Imported DLLs: {res.get('ImportedDlls', 0)}")
            print(f"Max Section Entropy: {res.get('MaxSectionEntropy', 0):.4f}")
            print(f"Total Features Extracted: {len(res)}")
    else:
        print("Usage: python extractor.py path_to_file.exe")
