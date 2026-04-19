import os
import logging
logger = logging.getLogger(__name__)
def safe_read(filepath: str, max_bytes: int = 1048576) -> str:
    try:
        if not isinstance(filepath, str):
            logger.warning(f"Invalid filepath type: {type(filepath)}")
            return ""
        if not os.path.isfile(filepath):
            logger.debug(f"File not found: {filepath}")
            return ""
        try:
            file_size = os.path.getsize(filepath)
            if file_size > max_bytes:
                logger.warning(f"File too large: {filepath} ({file_size} > {max_bytes})")
                return ""
        except OSError as e:
            logger.warning(f"Could not determine file size: {e}")
            return ""
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            return f.read(max_bytes)
    except PermissionError:
        logger.debug(f"Permission denied reading: {filepath}")
        return ""
    except OSError as e:
        logger.warning(f"IO error reading {filepath}: {e}")
        return ""
    except Exception as e:
        logger.error(f"Unexpected error reading {filepath}: {e}")
        return ""
