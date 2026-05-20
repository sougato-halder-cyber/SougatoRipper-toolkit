#!/usr/bin/env python3
"""
monitor.py
System Monitoring & Activity Logger Module
Contains: ActivityMonitor
"""

import os
import time
import datetime
import pyautogui
import threading


class ActivityMonitor:
    """Silently capture screenshots and log system events at intervals."""

    def __init__(self):
        self.screenshot_dir = "data/screenshots"
        self.log_dir = "data"
        os.makedirs(self.screenshot_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        self.running = False
        self._stop_event = threading.Event()

    def start(self, interval=10, duration=60, callback=None):
        """
        Start monitoring: take screenshots and log events.
        :param interval: Seconds between screenshots
        :param duration: Total duration in seconds (0 = infinite)
        :param callback: Function to call with status messages
        """
        self.running = True
        self._stop_event.clear()
        start_time = time.time()
        count = 0

        log_path = os.path.join(self.log_dir, "activity_log.txt")

        while not self._stop_event.is_set():
            count += 1
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            # Take screenshot
            try:
                screenshot_path = os.path.join(self.screenshot_dir, f"screenshot_{timestamp}.png")
                pyautogui.screenshot(screenshot_path)
                msg = f"[{timestamp}] Screenshot saved: {screenshot_path}"
            except Exception as e:
                msg = f"[{timestamp}] Screenshot failed: {e}"

            # Log event
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

            if callback:
                callback(msg)

            # Check duration
            if duration > 0 and (time.time() - start_time) >= duration:
                if callback:
                    callback("[+] Duration reached. Monitoring complete.")
                break

            # Wait for interval or stop signal
            self._stop_event.wait(interval)

        self.running = False

    def stop(self):
        """Signal the monitor to stop."""
        self._stop_event.set()
        self.running = False
