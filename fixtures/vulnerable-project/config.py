"""Configuration with weak TLS settings."""

TLS_CONFIG = {
    "min_version": "TLSv1.0",  # Deprecated
    "max_version": "TLSv1.2",
    "ciphers": "RSA-AES128-SHA256",  # RSA quantum vulnerable
}

SSL_CONFIG = {
    "enabled": True,
    "version": "SSLv3",  # Must not be used
}

SSH_CONFIG = {
    "host_key_algorithms": ["ssh-rsa"],  # RSA quantum vulnerable
    "kex_algorithms": ["diffie-hellman-group14-sha1"],  # Weak DH
}
