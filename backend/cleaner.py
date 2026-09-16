"""
Auto-Purge Background Cleaner
Runs periodic sweeps of the storage directory to permanently shred expired blobs.
"""

import threading
import time
import logging
from backend.storage import storage
from backend.config import CLEANUP_INTERVAL_SECONDS

logger = logging.getLogger("vault.cleaner")


class VaultCleaner(threading.Thread):
    def __init__(self, interval: int = CLEANUP_INTERVAL_SECONDS):
        super().__init__(daemon=True)
        self.interval = interval
        self.running = True

    def run(self):
        while self.running:
            try:
                purged = storage.purge_expired()
                if purged > 0:
                    logger.info(f"Auto-purged {purged} expired vault blobs.")
            except Exception as e:
                logger.error(f"Error during vault cleanup sweep: {e}")
            time.sleep(self.interval)

    def stop(self):
        self.running = False


# Background cleaner singleton
cleaner = VaultCleaner()
