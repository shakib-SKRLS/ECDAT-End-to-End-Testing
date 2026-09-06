"""Configuration with modern TLS settings."""

TLS_CONFIG = {
    "min_version": "TLSv1.2",  # Minimum acceptable
    "max_version": "TLSv1.3",  # Modern protocol
    "ciphers": "TLS_AES_256_GCM_SHA384",  # Modern cipher suite
}

SSH_CONFIG = {
    "host_key_algorithms": ["ssh-ed25519"],  # Ed25519 (though quantum vulnerable, currently acceptable)
    "kex_algorithms": ["curve25519-sha256"],  # Modern ECDH
}
