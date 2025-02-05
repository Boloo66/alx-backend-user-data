#!/usr/bin/env python3
"""
Module for password hashing and validation
"""

import bcrypt

def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The plain text password.

    Returns:
        bytes: The hashed password.
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Checks if a password matches the given hashed password.

    Args:
        hashed_password (bytes): The hashed password.
        password (str): The plain text password.

    Returns:
        bool: True if password matches, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
