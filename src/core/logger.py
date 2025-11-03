"""
Logging system for honeypot events and attacks
"""
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


class HoneypotLogger:
    """Centralized logging for honeypot events"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.log_dir = Path(config.get('logging', {}).get('log_dir', 'logs'))
        self.log_dir.mkdir(exist_ok=True)

        # Setup standard logger
        self.logger = self._setup_logger()

        # Attack log file - will be set dynamically per day
        self.current_date = None
        self.attack_log_file = None
        self._update_log_file()

    def _setup_logger(self) -> logging.Logger:
        """Configure the standard Python logger"""
        log_config = self.config.get('logging', {})
        level = getattr(logging, log_config.get('level', 'INFO'))

        logger = logging.getLogger('honeypot')
        logger.setLevel(level)

        # Suppress verbose Paramiko logging (reduces noise from SSH negotiation errors)
        logging.getLogger('paramiko').setLevel(logging.WARNING)

        # Console handler
        if log_config.get('console', True):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # File handler
        if log_config.get('file', True):
            file_handler = logging.FileHandler(
                self.log_dir / 'honeypot.log'
            )
            file_handler.setLevel(level)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger

    def _update_log_file(self):
        """Update log file path if date has changed"""
        today = datetime.now().strftime('%Y%m%d')
        if today != self.current_date:
            self.current_date = today
            self.attack_log_file = self.log_dir / f"attacks_{today}.json"
            self.logger.debug(f"Log file updated: {self.attack_log_file}")

    def log_attack(self, event_data: Dict[str, Any]):
        """Log an attack attempt with full details"""
        # Check if we need to rotate to a new day's log file
        self._update_log_file()

        event_data['timestamp'] = datetime.now().isoformat()

        # Add to JSON log file
        with open(self.attack_log_file, 'a') as f:
            f.write(json.dumps(event_data) + '\n')

        # Also log to standard logger
        protocol = event_data.get('protocol', 'unknown')
        source_ip = event_data.get('source_ip', 'unknown')
        username = event_data.get('username', '')

        self.logger.info(
            f"Attack attempt: {protocol} from {source_ip} - "
            f"user: {username}"
        )

    def log_connection(self, protocol: str, source_ip: str, source_port: int):
        """Log a new connection"""
        self.logger.info(
            f"New connection: {protocol} from {source_ip}:{source_port}"
        )

    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)

    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)

    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)

    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)
