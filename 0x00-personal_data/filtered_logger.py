#!/usr/bin/env python3
"""
Module for securely connecting to a MySQL database using environment variables
and logging user data while redacting PII fields.
"""

import os
import re
import logging
import mysql.connector
from typing import List, Tuple
from mysql.connector.connection import MySQLConnection

# Fields that should be redacted
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)s: %(message)s"
    SEPARATOR = "; "

    def __init__(self, fields: List[str]):
        """ Initialize RedactingFormatter with specific fields """
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Format log messages and redact PII fields """
        message = super().format(record)
        return self.filter_datum(self.fields, self.REDACTION, message, self.SEPARATOR)

    @staticmethod
    def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
        """ Replace PII fields with redacted values in log messages """
        for field in fields:
            message = re.sub(fr"{field}=[^;]*", f"{field}={redaction}", message)
        return message


def get_logger() -> logging.Logger:
    """ Returns a configured logger """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))

    logger.addHandler(stream_handler)

    return logger


def get_db() -> MySQLConnection:
    """
    Returns a MySQL database connection object.

    Uses environment variables for database credentials.
    """
    db_config = {
        "user": os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        "password": os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        "host": os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        "database": os.getenv("PERSONAL_DATA_DB_NAME"),
    }

    return mysql.connector.connect(**db_config)


def main():
    """ Retrieves all rows from the users table and logs them in a redacted format """
    logger = get_logger()
    db = get_db()
    cursor = db.cursor()

    query = "SELECT * FROM users;"
    cursor.execute(query)

    # Column names for reference
    columns = [desc[0] for desc in cursor.description]

    for row in cursor:
        user_data = "; ".join([f"{col}={val}" for col, val in zip(columns, row)])
        logger.info(user_data)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
