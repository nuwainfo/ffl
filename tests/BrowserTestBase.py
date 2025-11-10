#!/usr/bin/env python
# -*- coding: utf-8 -*-
# $Id: BrowserTestBase.py 17873 2025-11-08 09:02:13Z Bear $
#
# Copyright (c) 2025 Nuwa Information Co., Ltd, All Rights Reserved.
#
# Licensed under the Proprietary License,
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at our web site.
#
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import time
import platform
import threading
import json

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

CONCURRENT_WEBRTC_DOWNLOADS = int(os.getenv('TEST_CONCURRENT_E2EE_DOWNLOADS', '1'))

import undetected_chromedriver as uc

from get_gecko_driver import GetGeckoDriver
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from .CoreTestBase import FastFileLinkTestBase, generateRandomFile, getFileHash


# ---------------------------
# Browser Test Base Class
# ---------------------------
class BrowserTestBase(FastFileLinkTestBase):
    """Base class for browser-based download tests (Chrome, Firefox)"""

    DEFAULT_FILE_SIZE = 11 * 1024 * 1024 # 5MB
    _geckoDriverPath = None
    _geckoDriverLock = threading.Lock()

    def __init__(self, methodName='runTest', fileSizeBytes=None):
        if fileSizeBytes is None:
            fileSizeBytes = self.DEFAULT_FILE_SIZE
        super().__init__(methodName, fileSizeBytes=fileSizeBytes)

    def setUp(self):
        """Set up test environment including browser download directories"""
        super().setUp()

        # Create separate download directories for different browsers
        self.chromeDownloadDir = os.path.join(self.tempDir, "chrome_downloads")
        self.firefoxDownloadDir = os.path.join(self.tempDir, "firefox_downloads")

        os.makedirs(self.chromeDownloadDir, exist_ok=True)
        os.makedirs(self.firefoxDownloadDir, exist_ok=True)

        # Keep track of active drivers for cleanup
        self.activeDrivers = []

    def _getBrowserDownloadDir(self, browserName, index=0):
        if browserName == 'chrome':
            baseDir = self.chromeDownloadDir
        elif browserName == 'firefox':
            baseDir = self.firefoxDownloadDir
        else:
            raise ValueError(f"Unsupported browser for download dir allocation: {browserName}")

        if CONCURRENT_WEBRTC_DOWNLOADS <= 1:
            return baseDir

        dirPath = os.path.join(baseDir, f"user_{index}")
        os.makedirs(dirPath, exist_ok=True)
        return dirPath

    def tearDown(self):
        """Clean up test environment including browser instances"""
        # Clean up any remaining browser instances with timeout
        for idx, driver in enumerate(self.activeDrivers):
            cleanupComplete = threading.Event()

            def quitDriver():
                try:
                    driver.quit()
                except Exception as e:
                    print(f"[Test] Warning: Failed to cleanup driver {idx}: {e}")
                finally:
                    cleanupComplete.set()

            # Run driver.quit() in a separate thread with timeout
            cleanupThread = threading.Thread(target=quitDriver)
            cleanupThread.daemon = True
            cleanupThread.start()

            # Wait up to 5 seconds for cleanup
            if not cleanupComplete.wait(timeout=5):
                print(f"[Test] Warning: Driver {idx} cleanup timed out after 5 seconds - forcing continue")
                # Thread is daemon so it won't block exit

        super().tearDown()

    def _setupChromeDriver(self, downloadDir):
        """Setup undetected Chrome WebDriver"""
        prefs = {
            "download.default_directory": downloadDir,
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True,
            "safebrowsing.disable_download_protection": True,
            "profile.default_content_setting_values.automatic_downloads": 1
        }

        options = uc.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        options.add_argument("--disable-cache")  # Optional, not always effective
        options.add_experimental_option("prefs", prefs)
        options.set_capability('goog:loggingPrefs', {'browser': 'ALL', 'performance': 'ALL'})

        # Allow local HTTP static assets (mixed content) when STATIC_SERVER uses http://
        staticServer = os.environ.get("STATIC_SERVER", "")
        if staticServer.startswith("http://"):
            options.add_argument('--allow-running-insecure-content')
            options.add_argument('--allow-insecure-localhost')

        driver = uc.Chrome(options=options)
        try:
            driver.execute_cdp_cmd(
                "Page.setDownloadBehavior", {
                    "behavior": "allow",
                    "downloadPath": downloadDir,
                    "eventsEnabled": True
                }
            )
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setCacheDisabled", {"cacheDisabled": True})            
        except Exception as e:
            print(f"[Test] Warning: Failed to set download behavior via CDP: {e}")

        self.activeDrivers.append(driver)
        return driver

    def _setupFirefoxDriver(self, downloadDir):
        """Setup Firefox WebDriver with get-gecko-driver"""
        with self._geckoDriverLock:
            if not self._geckoDriverPath:
                getDriver = GetGeckoDriver()
                geckoDriverDir = None
                try:
                    print("[Test] Installing GeckoDriver...")
                    geckoDriverDir = getDriver.install()
                    print(f"[Test] GeckoDriver installed to: {geckoDriverDir}")
                except Exception as e:
                    # Print the error but continue - driver might already be installed
                    print(f"[Test] Warning during GeckoDriver installation: {e}")
                    print(f"[Test] Exception type: {type(e).__name__}")
                    import traceback
                    print(f"[Test] Traceback: {traceback.format_exc()}")

                    # Try to extract path from error message (for "Text file busy" errors)
                    # Example: OSError: [Errno 26] Text file busy: 'geckodriver/0.36.0/bin/geckodriver'
                    errorStr = str(e)
                    if 'geckodriver' in errorStr.lower():
                        import re
                        # Try to extract path from error message
                        pathMatch = re.search(r"['\"]([^'\"]*geckodriver[^'\"]*)['\" ]", errorStr)
                        if pathMatch:
                            extractedPath = pathMatch.group(1)
                            print(f"[Test] Extracted path from error: {extractedPath}")
                            if os.path.isfile(extractedPath):
                                # Use the directory containing the geckodriver executable
                                geckoDriverDir = os.path.dirname(extractedPath)
                                print(f"[Test] Using directory from extracted path: {geckoDriverDir}")
                            elif os.path.isfile(os.path.abspath(extractedPath)):
                                # Try absolute path
                                absPath = os.path.abspath(extractedPath)
                                geckoDriverDir = os.path.dirname(absPath)
                                print(f"[Test] Using directory from absolute path: {geckoDriverDir}")

                    # Fallback: Try to get output path from driver object
                    if not geckoDriverDir and hasattr(getDriver, 'output_path'):
                        geckoDriverDir = getDriver.output_path
                        print(f"[Test] Attempting to use output_path: {geckoDriverDir}")

                # Check if we got a valid directory
                if not geckoDriverDir:
                    raise Exception(
                        f"GeckoDriver installation failed and no valid output path found. "
                        f"Install GeckoDriver manually or check the error above."
                    )

                if platform.system() == "Windows":
                    geckoDriverPath = os.path.join(geckoDriverDir, "geckodriver.exe")
                else:
                    geckoDriverPath = os.path.join(geckoDriverDir, "geckodriver")

                if not os.path.isfile(geckoDriverPath):
                    raise Exception(f"GeckoDriver executable not found at: {geckoDriverPath}")

                self._geckoDriverPath = geckoDriverPath
                print(f"[Test] Using GeckoDriver: {geckoDriverPath}")

        geckoDriverPath = self._geckoDriverPath

        firefoxOptions = FirefoxOptions()
        firefoxOptions.add_argument('--headless')
        if platform.system() == 'Darwin':
            firefoxOptions.binary_location = "/Applications/Firefox.app/Contents/MacOS/firefox"

        firefoxOptions.set_preference("browser.download.folderList", 2)
        firefoxOptions.set_preference("browser.download.manager.showWhenStarting", False)
        firefoxOptions.set_preference("browser.download.dir", downloadDir)
        firefoxOptions.set_preference(
            "browser.helperApps.neverAsk.saveToDisk", "application/octet-stream,application/binary,application/x-binary"
        )

        service = FirefoxService(executable_path=geckoDriverPath)
        driver = webdriver.Firefox(service=service, options=firefoxOptions)
        self.activeDrivers.append(driver)
        return driver

    def _attachConsoleMirror(self, driver):
        """Attach console log mirroring to capture browser console logs in window.__TEST_LOGS__

        This works for both Chrome and Firefox by intercepting console methods
        and storing logs in a JavaScript array that can be retrieved later.
        """
        driver.execute_script(
            """
            (function() {
                if (window.__TEST_LOGS__) return;
                window.__TEST_LOGS__ = [];
                const levels = ['log', 'info', 'warn', 'error', 'debug'];
                const orig = {};

                function serialize(v) {
                    try {
                        if (v === null) return 'null';
                        if (v === undefined) return 'undefined';
                        if (typeof v === 'object') return JSON.stringify(v);
                        return String(v);
                    } catch (e) {
                        return '[unserializable]';
                    }
                }

                levels.forEach(level => {
                    orig[level] = console[level];
                    console[level] = function(...args) {
                        try {
                            window.__TEST_LOGS__.push([Date.now(), level, args.map(serialize).join(' ')]);
                        } catch (_) {}
                        try {
                            return orig[level].apply(console, args);
                        } catch (_) {}
                    };
                });
            })();
        """
        )

    def _getConsoleLogs(self, driver):
        """Retrieve captured console logs from window.__TEST_LOGS__

        Returns:
            List of tuples: [(timestamp, level, message), ...]
        """
        try:
            logs = driver.execute_script("return (window.__TEST_LOGS__ || []).slice();")
            return logs if logs else []
        except Exception as e:
            print(f"[Test] Warning: Failed to retrieve console logs: {e}")
            return []

    def _enableTargetDiscovery(self, driver):
        """Enable Chrome DevTools Protocol target discovery for debugging

        This enables monitoring of browser targets (pages, iframes, workers) which is useful
        for debugging StreamSaver mitm iframe issues in headless Chrome.

        Args:
            driver: Chrome WebDriver instance
        """
        try:
            driver.execute_cdp_cmd("Target.setDiscoverTargets", {"discover": True})
            print("[CDP] Target discovery enabled")
        except Exception as e:
            print(f"[CDP] Failed to enable Target discovery: {e}")

    def _drainAndPrintTargetEvents(self, driver):
        """Extract and print CDP Target events from performance log

        Drains Target creation/destruction events from Chrome's performance log to help debug
        StreamSaver mitm iframe lifecycle issues. Returns a snapshot of active targets.

        Args:
            driver: Chrome WebDriver instance

        Returns:
            dict: Mapping of targetId to URL for active targets
        """
        import json
        targets = {}
        if not hasattr(self, '_printedEvents'):
            self._printedEvents = set()
        try:
            logs = driver.get_log("performance")
            for entry in logs:
                try:
                    msg = json.loads(entry["message"])["message"]
                    msgStr = str(msg)
                    if msgStr not in self._printedEvents:
                        print(msg)
                        self._printedEvents.add(msgStr)
                except Exception as e:
                    print(e)
                    continue

                method = msg.get("method", "")
                params = msg.get("params", {})
                if method in ("Target.targetCreated", "Target.targetInfoChanged", "Target.targetDestroyed"):
                    print("[CDP]", method, params)
                    info = params.get("targetInfo") or {}
                    url = info.get("url") or ""
                    targetId = (info.get("targetId") or params.get("targetId"))

                    if method != "Target.targetDestroyed":
                        if targetId:
                            targets[targetId] = url
                    else:
                        # Print last known URL when target is destroyed
                        knownUrl = targets.get(targetId, url)
                        print(f"[CDP] targetDestroyed targetId={targetId} url={knownUrl}")
        except Exception as e:
            print(f"[CDP] Failed to read performance log: {e}")
        return targets

    def _getBrowserLogs(self, driver):
        """Get browser console logs using appropriate method for the browser type

        For Chrome: Uses driver.get_log("browser") (native ChromeDriver support)
        For Firefox: Uses console mirror approach via _getConsoleLogs()

        Returns:
            List of log entries with unified format for both browsers
            Chrome format: [{'timestamp': ..., 'level': 'INFO'/'SEVERE'/etc, 'message': '...'}, ...]
            Firefox format: [(timestamp, level, message), ...]
        """
        # Detect browser type
        browserType = None
        try:
            caps = driver.capabilities
            browserName = caps.get('browserName', '').lower()
            if 'chrome' in browserName:
                browserType = 'chrome'
            elif 'firefox' in browserName:
                browserType = 'firefox'
        except Exception:
            pass

        if browserType == 'chrome':
            # Use native Chrome logging
            try:
                return driver.get_log("browser")
            except Exception as e:
                print(f"[Test] Warning: Failed to get Chrome logs via get_log: {e}")
                return []
        elif browserType == 'firefox':
            # Use console mirror for Firefox
            return self._getConsoleLogs(driver)
        else:
            print(f"[Test] Warning: Unknown browser type, cannot retrieve logs")
            return []

    def _triggerDownload(self, driver):
        """Try to trigger the download"""
        try:
            downloadButton = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable(
                    (By.XPATH, "//button[contains(text(), 'Download')] | //a[contains(text(), 'Download')]")
                )
            )
            downloadButton.click()
            print("[Test] Clicked download button")
            return
        except TimeoutException:
            pass

        try:
            downloadLink = WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.TAG_NAME, "a")))
            downloadLink.click()
            print("[Test] Clicked download link")
            return
        except TimeoutException:
            pass

        print("[Test] Assuming direct download link - waiting for download to start")

    def _waitForDownload(self, downloadDir, expectedFilename, timeout=60, driver=None):
        """Wait for the download to complete and return the path to the downloaded file"""

        def checkDownloadComplete():
            if not os.path.exists(downloadDir):
                return None

            try:
                for filename in os.listdir(downloadDir):
                    if filename == expectedFilename or filename.startswith(expectedFilename.split('.')[0]):
                        filePath = os.path.join(downloadDir, filename)
                        if not (
                            filename.endswith('.part') or filename.endswith('.crdownload') or filename.endswith('.tmp')
                        ):
                            if os.path.getsize(filePath) > 0:
                                return filePath
            except (OSError, PermissionError) as e:
                print(f"[Test] Error checking download directory: {e}")
                return None
            return None

        downloadedFile = None
        startTime = time.time()
        lastProgressSize = 0
        lastProgressTime = time.time()
        stallThreshold = 30 # Consider stalled if no progress for 30 seconds

        print(f"[Test] Waiting for download in: {downloadDir}")
        # Print expected filename with encoding handling for Windows console
        try:
            print(f"[Test] Expected filename: {expectedFilename}")
        except UnicodeEncodeError:
            print(f"[Test] Expected filename: <contains unicode characters>")

        while time.time() - startTime < timeout:
            downloadedFile = checkDownloadComplete()
            if downloadedFile:
                # Print with encoding handling for Windows console
                try:
                    print(f"[Test] Found downloaded file: {downloadedFile}")
                except UnicodeEncodeError:
                    print(f"[Test] Found downloaded file: <contains unicode characters>")
                break

            # Track download progress to detect stalls
            currentProgressSize = 0
            if os.path.exists(downloadDir):
                try:
                    currentFiles = os.listdir(downloadDir)
                    print(f"[Test] Current files in download dir: {currentFiles}")
                    if currentFiles:                        
                        for filename in currentFiles:
                            filePath = os.path.join(downloadDir, filename)
                            try:
                                size = os.path.getsize(filePath)
                                print(f"[Test]   {filename}: {size} bytes")
                                # Track .crdownload file size for stall detection
                                if filename.endswith('.crdownload') or filename.endswith('.part'):
                                    currentProgressSize = max(currentProgressSize, size)
                                    print(f"[Test]   -> Tracking progress file: {currentProgressSize} bytes")
                            except (OSError, PermissionError) as sizeErr:
                                print(f"[Test]   {filename}: size unavailable ({sizeErr})")
                except (OSError, PermissionError) as e:
                    print(f"[Test] Error listing download directory: {e}")

            # Debug: Always print current progress size
            # print(f"[Test] currentProgressSize={currentProgressSize}, lastProgressSize={lastProgressSize}, elapsed={time.time() - startTime:.1f}s")

            # Detect stalled download (no progress for stallThreshold seconds)
            if currentProgressSize > 0:
                if currentProgressSize > lastProgressSize:
                    # Progress detected
                    lastProgressSize = currentProgressSize
                    lastProgressTime = time.time()
                else:
                    # No progress
                    stallDuration = time.time() - lastProgressTime
                    if stallDuration > stallThreshold:
                        print(f"[Test] WARNING: Download appears stalled! No progress for {stallDuration:.1f} seconds")
                        print(f"[Test] Last progress: {lastProgressSize} bytes")
                        print(f"[Test] This may indicate a Chrome headless + StreamSaver issue")

            time.sleep(2)

        if driver:
            try:
                # Only Chrome supports performance logs via get_log
                logs = driver.get_log('performance')
                for entry in logs:
                    msg = json.loads(entry['message'])['message']
                    if msg.get('method') in ('Browser.downloadProgress','Network.loadingFailed'):
                        print('[CDP]', msg)
            except (AttributeError, Exception) as e:
                # Firefox and other browsers don't support get_log('performance')
                print(f"[Test] Performance logs not available for this browser: {e}")            
                                 

        if True: #not downloadedFile:
            if driver:
                # 如果超時或失敗時，再抓一次，常常能看到 targetDestroyed
                self._drainAndPrintTargetEvents(driver)
                
                browserLogs = self._getBrowserLogs(driver)
                # Print ALL browser logs on failure (no filtering)
                print("[Test] Browser logs at time of failure (all logs):")
                for logEntry in browserLogs:
                    message, level = self._normalizeLogEntry(logEntry)
                    print(f"  [{level}] {message}")                
        
        if not downloadedFile:
            try:
                filesInDir = os.listdir(downloadDir) if os.path.exists(downloadDir) else []
                raise Exception(
                    f"Download did not complete within {timeout} seconds. Files in download dir: {filesInDir}"
                )
            except (OSError, PermissionError) as e:
                raise Exception(
                    f"Download did not complete within {timeout} seconds. Error accessing download dir: {e}"
                )

        return downloadedFile
        

    def _normalizeLogEntry(self, logEntry):
        """Normalize log entry to unified format (message, level)

        Args:
            logEntry: Either dict (Chrome) or tuple (Firefox)

        Returns:
            tuple: (message, level)
        """
        if isinstance(logEntry, dict):
            return logEntry.get("message", ""), logEntry.get("level", "INFO")
        else:
            # Firefox format: (timestamp, level, message)
            timestamp, level, message = logEntry
            return message, level        

    def _withBrowserFallbackDisabled(self, url):
        """Return URL with ?fallback=0 to disable browser-side HTTP fallback"""
        parsed = urlparse(url)
        queryItems = [
            (key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key != 'fallback'
        ]
        queryItems.append(('fallback', '0'))
        newQuery = urlencode(queryItems)
        return urlunparse(parsed._replace(query=newQuery))

    def _injectWebRTCDataChannelDelayPatch(self, driver):
        """Inject JavaScript to delay WebRTC datachannel handler to avoid StreamSaver race condition

        This patches RTCPeerConnection to delay the datachannel event handler by 700ms after
        the channel opens. This prevents a race condition in Chrome headless where:
        1. StreamSaver starts navigating the mitm iframe
        2. WebRTC datachannel opens and starts receiving data immediately
        3. Chrome cancels the download because the iframe navigation isn't ready yet

        The 700ms delay allows the mitm iframe navigation to complete before data transfer starts.

        NOTE: Currently disabled by default (not injected) as the other two patches may be sufficient.
        Can be re-enabled by uncommenting the injection call in _downloadWithBrowser.

        Args:
            driver: Chrome WebDriver instance
        """
        script = """
(() => {
  const enablePatch = true;
  if (!enablePatch) return;

  const OriginalRTCPeerConnection = RTCPeerConnection;
  window.RTCPeerConnection = function(...args) {
    const pc = new OriginalRTCPeerConnection(...args);

    let userDefinedHandler = null;
    pc.addEventListener('datachannel', async (event) => {
      // Wait until channel is actually open before starting timer
      await new Promise((resolve) => {
        if (event.channel.readyState === 'open') return resolve();
        const onOpen = () => {
          event.channel.removeEventListener('open', onOpen);
          resolve();
        };
        event.channel.addEventListener('open', onOpen, { once: true });
      });

      // Delay 700ms to avoid StreamSaver mitm iframe navigation race condition
      await new Promise(resolve => setTimeout(resolve, 700));

      if (userDefinedHandler) {
        userDefinedHandler(event);
      }
    }, { once: false });

    // Intercept ondatachannel setter to store user's handler
    Object.defineProperty(pc, 'ondatachannel', {
      configurable: true,
      get() { return userDefinedHandler; },
      set(fn) { userDefinedHandler = fn; }
    });

    return pc;
  };
})();
"""
        # Currently disabled - can be enabled by uncommenting in _downloadWithBrowser
        # driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": script})

    def _injectPerformanceTimelineMonitor(self, driver):
        """Inject JavaScript to monitor page load and iframe events via performance timeline

        This script logs timing information for debugging:
        - DOMContentLoaded event
        - Window load event
        - Iframe additions to DOM
        - Iframe load events

        Useful for debugging the StreamSaver mitm iframe lifecycle and identifying timing issues.

        Args:
            driver: Chrome WebDriver instance
        """
        script = """
(() => {
  const startTime = performance.now();
  const logTimestamp = (label) =>
    console.log('[CI-TIMELINE]', label, (performance.now() - startTime).toFixed(1), 'ms');

  document.addEventListener('DOMContentLoaded', () => logTimestamp('domcontentloaded'));
  window.addEventListener('load', () => logTimestamp('window-load'));

  const setupMutationObserver = () => {
    try {
      const rootElement = document.documentElement || document.body;
      if (!rootElement) return;

      const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          for (const node of mutation.addedNodes) {
            if (node && node.nodeType === 1 && node.tagName === 'IFRAME') {
              logTimestamp('iframe added: ' + (node.src || '(no src yet)'));
              node.addEventListener('load', () => logTimestamp('iframe load: ' + (node.src || '')), { once: true });
            }
          }
        }
      });
      observer.observe(rootElement, { childList: true, subtree: true });
    } catch (e) {
      console.error('Failed to setup mutation observer:', e);
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupMutationObserver, { once: true });
  } else {
    setupMutationObserver();
  }
})();
"""
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": script})

    def _injectStreamSaverMitmPrewarm(self, driver):
        """Inject JavaScript to pre-warm StreamSaver mitm iframe and service worker

        This script fixes Chrome headless + StreamSaver race condition by:
        1. Prefetching the mitm.html file early (before StreamSaver needs it)
        2. Creating a hidden mitm iframe and waiting for it to load
        3. Pre-registering the service worker
        4. Exposing window.__MITM_READY__ promise that resolves when ready

        This ensures the mitm iframe and service worker are ready BEFORE WebRTC starts
        transferring data, preventing Chrome from canceling the download.

        Args:
            driver: Chrome WebDriver instance
        """
        script = r"""
(function() {
  if (window.__FFL_MITM_BOOTSTRAP__) return;
  window.__FFL_MITM_BOOTSTRAP__ = true;

  const MITM_URL = '/static/assets/mitm.html';

  // 提前告訴 StreamSaver 用哪個 mitm（即使主程式稍後還會再設一次，也不會有副作用）
  try { window.streamSaver = window.streamSaver || {}; streamSaver.mitm = MITM_URL; } catch {}

  // 單例：等到 mitm iframe load 或 SW 發來 "streamsaver/ready" 即視為 ready
  let resolveReady;
  const readyP = new Promise(r => { resolveReady = r; });
  window.__FFL_STREAMSAVER_READY__ = readyP;

  const markReady = () => { try { resolveReady(); } catch {} };

  // 當 SW / mitm 通知 ready 時就完成
  window.addEventListener('message', (ev) => {
    const msg = ev && ev.data;
    if (typeof msg === 'string' && msg.indexOf('streamsaver/ready') === 0) {
      markReady();
    }
  });

  const ensureOnce = () => {
    try {
      const inject = () => {
        if (document.__ffl_mitm_iframe__) { markReady(); return; }
        const iframe = document.createElement('iframe');
        iframe.src = MITM_URL;
        iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none;';
        iframe.addEventListener('load', () => markReady(), { once: true });
        (document.body || document.documentElement).appendChild(iframe);
        document.__ffl_mitm_iframe__ = iframe;
      };
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', inject, { once: true });
      } else {
        queueMicrotask(inject);
      }
    } catch { markReady(); }
  };

  // 盡早預取，不阻塞
  try {
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = MITM_URL;
    (document.head || document.documentElement).appendChild(link);
  } catch {}

  ensureOnce();
})();
"""


        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": script})

    def _downloadWithBrowser(self, driver, shareLink, downloadDir, expectedFilename, disableFallback=False):
        """Download file using the specified browser driver"""
        try:
            targetUrl = self._withBrowserFallbackDisabled(shareLink) if disableFallback else shareLink

            if 'JENKINS_HOME' in os.environ and isinstance(driver, uc.Chrome):
                # Inject JavaScript patches before page navigation to fix Chrome headless + StreamSaver race condition
                # These scripts must be injected via CDP before the page loads to take effect
                # Note: DataChannel delay patch is currently disabled as the other two patches are sufficient
                # Uncomment if needed: self._injectWebRTCDataChannelDelayPatch(driver)
                self._injectPerformanceTimelineMonitor(driver)
                self._injectStreamSaverMitmPrewarm(driver)
                        
            print(f"[Test] Navigating to: {targetUrl}")
            driver.get(targetUrl)

            WebDriverWait(driver,
                          10).until(lambda driver: driver.execute_script("return document.readyState") == "complete")

            # Attach console mirror for Firefox (Chrome uses native get_log)
            try:
                caps = driver.capabilities
                if 'firefox' in caps.get('browserName', '').lower():
                    self._attachConsoleMirror(driver)
            except Exception:
                pass

            print("[Test] Waiting for automatic download to start...")

            downloadedFile = self._waitForDownload(downloadDir, expectedFilename, driver=driver)
            
            # Print with encoding handling for Windows console
            try:
                print(f"[Test] Download completed successfully: {downloadedFile}")
            except UnicodeEncodeError:
                print(f"[Test] Download completed successfully: <contains unicode characters>")

            return downloadedFile

        except TimeoutException:
            raise Exception("Timeout waiting for download to complete")
        except Exception as e:
            raise Exception(f"Download failed: {e}")
