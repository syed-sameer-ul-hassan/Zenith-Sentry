#!/usr/bin/env python3
"""
Encryption utilities for sensitive data protection.
Provides config encryption, log file encryption, and credential storage.
"""
import os
import logging
import base64
import hashlib
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

ENCRYPTION_KEY_ENV = "ZENITH_ENCRYPTION_KEY"
DEFAULT_KEY_FILE = "/etc/zenith-sentry/encryption.key"

class EncryptionManager:
    """
    Manages encryption and decryption of sensitive data.
    
    Uses AES-256 via Fernet (symmetric encryption) with PBKDF2 key derivation.
    """
    
    def __init__(self, password: Optional[str] = None, key_file: Optional[str] = None):
        """
        Initialize the encryption manager.
        
        Args:
            password: Password for key derivation (or None to use environment/file)
            key_file: Path to key file (or None to use default)
        """
        self.key = self._get_or_generate_key(password, key_file)
        self.cipher = Fernet(self.key)
    
    def _get_or_generate_key(self, password: Optional[str], key_file: Optional[str]) -> bytes:
        """
        Get encryption key from environment, file, or generate one.
        
        Args:
            password: Optional password for key derivation
            key_file: Optional path to key file
            
        Returns:
            32-byte encryption key
        """
                                        
        env_key = os.environ.get(ENCRYPTION_KEY_ENV)
        if env_key:
            try:
                                           
                return base64.urlsafe_b64decode(env_key.encode())
            except Exception as e:
                logger.warning(f"Failed to decode encryption key from environment: {e}")
        
        key_path = key_file or DEFAULT_KEY_FILE
        if os.path.exists(key_path):
            try:
                with open(key_path, 'rb') as f:
                    key = f.read()
                    if len(key) == 44:                              
                        return base64.urlsafe_b64decode(key)
                    elif len(key) == 32:
                        return base64.urlsafe_b64encode(key)
                    else:
                        logger.warning(f"Invalid key length in {key_path}")
            except Exception as e:
                logger.warning(f"Failed to read key file: {e}")
        
        if password:
            return self._derive_key_from_password(password)
        else:
                                             
            key = Fernet.generate_key()
            self._save_key(key, key_path)
            logger.info(f"Generated new encryption key and saved to {key_path}")
            return key
    
    def _derive_key_from_password(self, password: str) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: Password string
            
        Returns:
            32-byte derived key
        """
        password_bytes = password.encode('utf-8')
        salt = b'zenith-sentry-salt'                                                 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def _save_key(self, key: bytes, key_file: str) -> None:
        """
        Save encryption key to file with restricted permissions.
        
        Args:
            key: 32-byte encryption key
            key_file: Path to save key
        """
        try:
                                                  
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            
            with open(key_file, 'wb') as f:
                f.write(key)
            
            os.chmod(key_file, 0o600)
            
            logger.info(f"Encryption key saved to {key_file}")
        except Exception as e:
            logger.error(f"Failed to save encryption key: {e}")
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data
        """
        try:
            return self.cipher.encrypt(data)
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data.
        
        Args:
            encrypted_data: Data to decrypt
            
        Returns:
            Decrypted data
        """
        try:
            return self.cipher.decrypt(encrypted_data)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def encrypt_string(self, text: str) -> str:
        """
        Encrypt a string and return base64-encoded result.
        
        Args:
            text: String to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        encrypted = self.encrypt(text.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_string(self, encrypted_text: str) -> str:
        """
        Decrypt a base64-encoded encrypted string.
        
        Args:
            encrypted_text: Base64-encoded encrypted string
            
        Returns:
            Decrypted string
        """
        encrypted = base64.b64decode(encrypted_text.encode('utf-8'))
        decrypted = self.decrypt(encrypted)
        return decrypted.decode('utf-8')

def encrypt_config(config_path: str, output_path: Optional[str] = None) -> bool:
    """
    Encrypt a YAML configuration file.
    
    Args:
        config_path: Path to config file to encrypt
        output_path: Path to save encrypted config (default: config_path + .enc)
        
    Returns:
        True if encryption succeeded, False otherwise
    """
    try:
        if output_path is None:
            output_path = config_path + '.enc'
        
        with open(config_path, 'rb') as f:
            config_data = f.read()
        
        manager = EncryptionManager()
        encrypted = manager.encrypt(config_data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
        
        os.chmod(output_path, 0o600)
        
        logger.info(f"Config encrypted and saved to {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to encrypt config: {e}")
        return False

def decrypt_config(encrypted_path: str, output_path: Optional[str] = None) -> bool:
    """
    Decrypt an encrypted YAML configuration file.
    
    Args:
        encrypted_path: Path to encrypted config file
        output_path: Path to save decrypted config (default: encrypted_path without .enc)
        
    Returns:
        True if decryption succeeded, False otherwise
    """
    try:
        if output_path is None:
            if encrypted_path.endswith('.enc'):
                output_path = encrypted_path[:-4]
            else:
                output_path = encrypted_path + '.dec'
        
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        manager = EncryptionManager()
        decrypted = manager.decrypt(encrypted_data)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        
        os.chmod(output_path, 0o600)
        
        logger.info(f"Config decrypted and saved to {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to decrypt config: {e}")
        return False

class SecureLogHandler:
    """
    Log handler that encrypts log entries before writing to file.
    """
    
    def __init__(self, filename: str, encryption_manager: Optional[EncryptionManager] = None):
        """
        Initialize secure log handler.
        
        Args:
            filename: Path to log file
            encryption_manager: EncryptionManager instance (creates one if None)
        """
        self.filename = filename
        self.encryption_manager = encryption_manager or EncryptionManager()
        self._init_log_file()
    
    def _init_log_file(self) -> None:
        """Initialize log file with proper permissions."""
        try:
                                        
            os.makedirs(os.path.dirname(self.filename), exist_ok=True)
            
            if not os.path.exists(self.filename):
                with open(self.filename, 'ab') as f:
                    pass
                os.chmod(self.filename, 0o600)
                
        except Exception as e:
            logger.error(f"Failed to initialize log file: {e}")
    
    def emit(self, message: str) -> None:
        """
        Encrypt and write a log message.
        
        Args:
            message: Log message to write
        """
        try:
                             
            encrypted = self.encryption_manager.encrypt_string(message)
            
            with open(self.filename, 'a', encoding='utf-8') as f:
                f.write(encrypted + '\n')
                
        except Exception as e:
            logger.error(f"Failed to write encrypted log: {e}")
    
    def read_logs(self, decrypt: bool = True) -> list:
        """
        Read log entries from file.
        
        Args:
            decrypt: Whether to decrypt entries (default: True)
            
        Returns:
            List of log messages
        """
        try:
            messages = []
            with open(self.filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        if decrypt:
                            messages.append(self.encryption_manager.decrypt_string(line))
                        else:
                            messages.append(line)
            return messages
        except Exception as e:
            logger.error(f"Failed to read log file: {e}")
            return []

def hash_password(password: str) -> str:
    """
    Hash a password using SHA-256 (for credential storage).
    
    Note: For production, use bcrypt or argon2 instead.
    
    Args:
        password: Password to hash
        
    Returns:
        Hex digest of hashed password
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a hash.
    
    Args:
        password: Password to verify
        hashed: Hashed password to compare against
        
    Returns:
        True if password matches hash, False otherwise
    """
    return hash_password(password) == hashed
