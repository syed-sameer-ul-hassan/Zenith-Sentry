import os
def safe_read(filepath: str, max_bytes: int = 1048576) -> str:
    try:
        if not os.path.isfile(filepath): return ""
        with open(filepath, 'r', errors='ignore') as f: return f.read(max_bytes)
    except: return ""
