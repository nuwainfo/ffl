#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import logging

from tqdm import tqdm

from .Utils import formatSize, ONE_MB


class BitmathTqdm(tqdm):
    """Custom tqdm class with consistent size formatting."""

    def __init__(self, *args, sizeFormatter=None, unit='B', unitScale=False, **kwargs):
        self.sizeFormatter = sizeFormatter or formatSize
        self._lastNFormatted = ""
        self._lastTotalFormatted = ""

        if 'bar_format' not in kwargs:
            kwargs['bar_format'] = (
                'Progress: {percentage:3.0f}%|{bar}| '
                '{n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
            )

        super().__init__(*args, unit=unit, unit_scale=unitScale, **kwargs)

    def _formatSpeed(self, rateBytesPerSec):
        """Format speed using the same formatter as size."""
        if rateBytesPerSec <= 0:
            return "0/sec"

        speedFormatted = self.sizeFormatter(int(rateBytesPerSec))
        return f"{speedFormatted}/sec"

    def _formatSizeStable(self, sizeBytes, isTotal=False):
        """Format size with stability considerations for dynamic units."""
        formatted = self.sizeFormatter(sizeBytes)

        # Cache the total size format to maintain consistency
        if isTotal and formatted != self._lastTotalFormatted:
            self._lastTotalFormatted = formatted

        return formatted

    @property
    def format_dict(self):
        """Override format_dict to use consistent formatting."""
        d = super().format_dict

        rate = d.get('rate', 0) or 0
        d['rate_fmt'] = self._formatSpeed(rate)
        d['n_fmt'] = self._formatSizeStable(d.get('n', 0), isTotal=False)
        d['total_fmt'] = self._formatSizeStable(d.get('total', 0), isTotal=True)

        return d


class Progress:

    def __init__(self, totalSize, sizeFormatter=None, loggerCallback=print, logInterval=2.0, useBar=False):
        self.totalSize = totalSize
        self.sizeFormatter = sizeFormatter or formatSize
        self.loggerCallback = loggerCallback
        self.logInterval = logInterval
        self.useBar = useBar

        # Progress tracking
        self.transferred = 0
        self.startTime = time.monotonic()
        self.lastProgressTime = self.startTime
        self.lastProgressBytes = 0

        # Initialize progress bar if requested and available
        self.pbar = None
        if self.useBar:
            self._initProgressBar()

    def _initProgressBar(self):
        """Initialize the tqdm progress bar."""
        try:
            self.pbar = BitmathTqdm(
                total=self.totalSize,
                desc='Progress',
                sizeFormatter=self.sizeFormatter,
                leave=True,
                ncols=100, # Increased width to accommodate extraText
                ascii=False,
                bar_format=(
                    'Progress: {percentage:3.0f}%|{bar}| '
                    '{n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]{postfix}'
                )
            )
        except Exception:
            self.pbar = tqdm(total=self.totalSize, desc='Progress', unit='B', unit_scale=True, leave=True)

    def update(self, bytesTransferred, forceLog=False, extraText=""):
        """Update progress with new bytes transferred."""
        previousTransferred = self.transferred
        self.transferred = bytesTransferred
        currentTime = time.monotonic()

        if self.useBar and self.pbar:
            self._updateProgressBar(previousTransferred, extraText)

        shouldLog = self._shouldLog(forceLog, currentTime)
        if shouldLog and not self.useBar:
            self._logProgress(currentTime, extraText)

    def _updateProgressBar(self, previousTransferred, extraText):
        """Update the progress bar display."""
        try:
            increment = self.transferred - previousTransferred
            if increment > 0:
                self.pbar.update(increment)

            # Method 1: Use postfix (appears after the progress bar)
            if extraText:
                self.pbar.set_postfix_str(f" {extraText}")
            else:
                self.pbar.set_postfix_str("")

            # Method 2: Alternative - modify description (appears before the bar)
            # if extraText:
            #     self.pbar.set_description(f"Progress ({extraText})")
            # else:
            #     self.pbar.set_description("Progress")

            if self.transferred >= self.totalSize:
                self.finishBar()
        except (ValueError, AttributeError) as e:
            self.loggerCallback(f"Progress bar error: {e}")
            self.useBar = False

    def _shouldLog(self, forceLog, currentTime):
        """Determine if progress should be logged."""
        return (
            forceLog or self.transferred % (5 * ONE_MB) == 0 or
            (currentTime - self.lastProgressTime) >= self.logInterval
        )

    def _logProgress(self, currentTime, extraText):
        """Log progress information."""
        timeDelta = currentTime - self.lastProgressTime
        bytesDelta = self.transferred - self.lastProgressBytes

        speedBytesPerSec = bytesDelta / timeDelta if timeDelta > 0 else 0
        speedDisplay = self.sizeFormatter(int(speedBytesPerSec))

        sizeDisplay = self.sizeFormatter(self.transferred)
        totalDisplay = self.sizeFormatter(self.totalSize)
        percentage = (self.transferred * 100.0 / self.totalSize) if self.totalSize > 0 else 0

        progressMsg = f'Progress: {sizeDisplay}/{totalDisplay} ({percentage:.2f}%), {speedDisplay}/sec'
        if extraText:
            progressMsg += f', {extraText}'

        self.loggerCallback(progressMsg)

        self.lastProgressTime = currentTime
        self.lastProgressBytes = self.transferred

    def setDescription(self, desc):
        """Set the description of the progress bar."""
        if self.useBar and self.pbar:
            self.pbar.set_description(desc)

    def setPostfix(self, **kwargs):
        """Set postfix information for the progress bar."""
        if self.useBar and self.pbar:
            self.pbar.set_postfix(**kwargs)

    def write(self, text):
        """Write text without interfering with the progress bar."""
        if self.useBar and self.pbar:
            self.pbar.write(text)
        else:
            self.loggerCallback(text)

    def getPercentage(self):
        """Get current completion percentage."""
        return (self.transferred * 100.0 / self.totalSize) if self.totalSize > 0 else 0

    def getSpeed(self):
        """Get current transfer speed in bytes per second."""
        currentTime = time.monotonic()
        timeDelta = currentTime - self.lastProgressTime
        bytesDelta = self.transferred - self.lastProgressBytes

        return bytesDelta / timeDelta if timeDelta > 0 else 0

    def getElapsedTime(self):
        """Get elapsed time since progress started."""
        return time.monotonic() - self.startTime

    def getRemainingTime(self):
        """Estimate remaining time based on current speed."""
        if self.transferred <= 0:
            return float('inf')

        elapsed = self.getElapsedTime()
        if elapsed <= 0:
            return float('inf')

        speed = self.transferred / elapsed
        if speed <= 0:
            return float('inf')

        remainingBytes = self.totalSize - self.transferred
        return remainingBytes / speed

    def getFormattedSpeed(self):
        """Get formatted speed string using sizeFormatter."""
        speed = self.getSpeed()
        return f"{self.sizeFormatter(int(speed))}/sec" if speed > 0 else "0/sec"

    def finishBar(self):
        """Finish the progress bar if it's being used."""
        if self.useBar and self.pbar:
            try:
                if hasattr(self.pbar, 'total') and self.pbar.total:
                    remaining = self.pbar.total - self.pbar.n
                    if remaining > 0:
                        self.pbar.update(remaining)

                self.pbar.close()
            except (ValueError, AttributeError) as e:
                logger = logging.getLogger(__name__)
                logger.debug(f"Exception during progress bar cleanup: {e}")
            finally:
                self.pbar = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, excType, excVal, excTb):
        """Context manager exit - ensure progress bar is closed."""
        self.finishBar()

    def __del__(self):
        """Destructor - ensure progress bar is closed."""
        self.finishBar()


def createProgressBar(totalSize, description="Progress", sizeFormatter=None, **kwargs):
    """Create a progress bar with consistent formatting."""
    return BitmathTqdm(total=totalSize, desc=description, sizeFormatter=sizeFormatter or formatSize, **kwargs)
