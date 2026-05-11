#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2025-2026 FastFileLink contributors
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

import os
import argparse
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import json

from datetime import datetime, timedelta
from dataclasses import dataclass
from uuid import uuid4

import psutil
import requests

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

if __package__ in (None, ""):
    repoRoot = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repoRoot not in sys.path:
        sys.path.insert(0, repoRoot)

from bases.Settings import SettingsGetter
from bases.Utils import StallResilientAdapter, getEnv, parseSizeString
from bases.Kernel import StorageLocator

from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common import utils as selenium_utils
from selenium.webdriver.support.ui import WebDriverWait

try:
    from .ResumeTestBase import ResumeBrowserTestBase
    from .CoreTestBase import getFileHash
except ImportError:
    if repoRoot not in sys.path:
        sys.path.insert(0, repoRoot)
        
    from tests.ResumeTestBase import ResumeBrowserTestBase
    from tests.CoreTestBase import getFileHash

DIRECT_RUN = __name__ == "__main__"
BROWSER_CHOICES = ("chrome", "firefox")
ROUTE_CHOICES = ("auto", "sw", "pass")
BROWSER_DRIVEN_SCENARIOS = {"http-browser", "normal", "webrtc", "fallback", "upload"}

# Curated "full" matrix.
# Keep only combinations that exercise distinct download behavior:
# - `http-browser`: pure HTTP browser path; Firefox `pass` is distinct because the
#   test maps it to `native=true`, which exercises browser-owned/native handling.
# - `normal`: default happy-path coverage for both browsers; route variants add no
#   meaningful value when P2P succeeds without relay fallback.
# - `webrtc`: fallback is disabled, so route variants are irrelevant and `pass`
#   is actively misleading for Firefox because it does not exercise HTTP/native flow.
# - `fallback`: explicit relay fallback coverage; keep Firefox `pass` because it
#   exercises the native/browser-owned HTTP resume path after P2P disruption.
# - `upload`: browser download from an upload-mode share still benefits from Firefox
#   native-path coverage, but extra route variants are redundant.
CURATED_FULL_MATRIX = {
    "http-request": [(None, None)],
    "http-browser": [("chrome", "auto"), ("firefox", "auto"), ("firefox", "pass")],
    "normal": [("chrome", "auto"), ("firefox", "auto")],
    "webrtc": [("chrome", "auto"), ("firefox", "auto")],
    "fallback": [("chrome", "auto"), ("firefox", "auto"), ("firefox", "pass")],
    "upload": [("chrome", "auto"), ("firefox", "auto"), ("firefox", "pass")],
}


@dataclass(frozen=True)
class NetworkEmulationConfig:
    scope: str = "share"
    interface: str = ""
    delay: str = ""
    jitter: str = ""
    loss: str = ""
    rate: str = ""
    burst: str = ""
    latency: str = ""

    @classmethod
    def fromEnvironment(cls):
        return cls(
            scope=os.getenv("FFL_LARGE_FILE_NET_SCOPE", "share").strip().lower() or "share",
            interface=os.getenv("FFL_LARGE_FILE_NET_INTERFACE", "").strip(),
            delay=os.getenv("FFL_LARGE_FILE_NET_DELAY", "").strip(),
            jitter=os.getenv("FFL_LARGE_FILE_NET_JITTER", "").strip(),
            loss=os.getenv("FFL_LARGE_FILE_NET_LOSS", "").strip(),
            rate=os.getenv("FFL_LARGE_FILE_NET_RATE", "").strip(),
            burst=os.getenv("FFL_LARGE_FILE_NET_BURST", "").strip(),
            latency=os.getenv("FFL_LARGE_FILE_NET_LATENCY", "").strip(),
        )

    def isEnabled(self):
        return any(
            value
            for value in (
                self.interface,
                self.delay,
                self.jitter,
                self.loss,
                self.rate,
                self.burst,
                self.latency,
            )
        )

    def validate(self):
        if self.scope not in ("share", "browser", "both", "host"):
            raise ValueError(
                "Network emulation scope must be 'share', 'browser', 'both', or 'host' "
                "(--net-scope / FFL_LARGE_FILE_NET_SCOPE)"
            )
        if self.jitter and not self.delay:
            raise ValueError("Network emulation jitter requires --net-delay / FFL_LARGE_FILE_NET_DELAY")
        if (self.burst or self.latency) and not self.rate:
            raise ValueError(
                "Network emulation burst/latency requires --net-rate / FFL_LARGE_FILE_NET_RATE"
            )
        if not (self.delay or self.loss or self.rate):
            raise ValueError(
                "Network emulation requires at least one of delay/loss/rate to be configured"
            )

    def describe(self):
        parts = [f"scope={self.scope}"]
        if self.interface:
            parts.append(f"iface={self.interface}")
        if self.delay:
            parts.append(f"delay={self.delay}")
        if self.jitter:
            parts.append(f"jitter={self.jitter}")
        if self.loss:
            parts.append(f"loss={self.loss}")
        if self.rate:
            parts.append(f"rate={self.rate}")
        if self.burst:
            parts.append(f"burst={self.burst}")
        if self.latency:
            parts.append(f"latency={self.latency}")
        return ", ".join(parts) if parts else "disabled"


class LinuxTrafficControl:
    DEFAULT_BURST = "32kbit"
    DEFAULT_LATENCY = "400ms"

    def __init__(self, config):
        self.config = config
        self.interface = ""
        self._applied = False
        self._sudoPrefix = []

    def ensureSupported(self):
        self.config.validate()
        if platform.system() != "Linux":
            raise RuntimeError("Network emulation is only supported on Linux hosts")

        if shutil.which("tc") is None:
            raise RuntimeError("Network emulation requires `tc` on PATH")

        if shutil.which("ip") is None:
            raise RuntimeError("Network emulation requires `ip` on PATH")

        self._sudoPrefix = self._determinePrivilegePrefix()
        self.interface = self.config.interface or self._detectDefaultInterface()
        if not self.interface:
            raise RuntimeError(
                "Network emulation could not determine a network interface. "
                "Pass --net-interface explicitly."
            )

    def apply(self):
        self.ensureSupported()
        print(f"[Test] Applying Linux traffic control: {self.config.describe()}, resolved_iface={self.interface}")
        self.clear(quiet=True)

        for command in self._buildApplyCommands():
            self._run(command)

        self._applied = True

    def clear(self, quiet=False):
        if not self.interface:
            try:
                self.interface = self.config.interface or self._detectDefaultInterface()
            except Exception as exc:
                if not quiet:
                    print(f"[Test] Network emulation cleanup skipped: {exc}")
                return

        if not self._sudoPrefix:
            try:
                self._sudoPrefix = self._determinePrivilegePrefix()
            except Exception as exc:
                if not quiet:
                    print(f"[Test] Network emulation cleanup skipped: {exc}")
                return

        deleteCommand = ["tc", "qdisc", "del", "dev", self.interface, "root"]
        result = self._run(deleteCommand, check=False)
        self._applied = False

        stderr = (result.stderr or "").strip()
        if result.returncode == 0:
            if not quiet:
                print(f"[Test] Cleared Linux traffic control on {self.interface}")
            return

        benignErrors = (
            "No such file or directory",
            "Cannot delete qdisc with handle of zero",
            "RTNETLINK answers: No such file or directory",
        )
        if any(message in stderr for message in benignErrors):
            if not quiet:
                print(f"[Test] No existing traffic control qdisc to clear on {self.interface}")
            return

        if not quiet:
            print(
                f"[Test] Warning: failed to clear traffic control on {self.interface}: "
                f"exit={result.returncode}, stderr={stderr or '<empty>'}"
            )

    def _buildApplyCommands(self):
        commands = []
        if self.config.rate:
            burst = self.config.burst or self.DEFAULT_BURST
            latency = self.config.latency or self.DEFAULT_LATENCY
            commands.append(
                [
                    "tc", "qdisc", "add", "dev", self.interface,
                    "root", "handle", "1:", "tbf",
                    "rate", self.config.rate,
                    "burst", burst,
                    "latency", latency,
                ]
            )
            netemCommand = self._buildNetemCommand(parentHandle="1:1", handle="10:")
            if netemCommand:
                commands.append(netemCommand)
            return commands

        netemCommand = self._buildNetemCommand(parentHandle=None, handle=None)
        if netemCommand:
            commands.append(netemCommand)
        return commands

    def _buildNetemCommand(self, parentHandle, handle):
        netemTokens = []
        if self.config.delay:
            netemTokens.extend(["delay", self.config.delay])
            if self.config.jitter:
                netemTokens.append(self.config.jitter)
        if self.config.loss:
            netemTokens.extend(["loss", self.config.loss])

        if not netemTokens:
            return None

        command = ["tc", "qdisc", "add", "dev", self.interface]
        if parentHandle:
            command.extend(["parent", parentHandle])
        else:
            command.append("root")
        if handle:
            command.extend(["handle", handle])
        command.append("netem")
        command.extend(netemTokens)
        return command

    def _determinePrivilegePrefix(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return []

        if shutil.which("sudo") is None:
            raise RuntimeError("Network emulation requires root privileges or passwordless sudo")

        probe = subprocess.run(
            ["sudo", "-n", "tc", "qdisc", "show", "dev", "lo"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if probe.returncode == 0:
            return ["sudo", "-n"]

        stderr = (probe.stderr or "").strip()
        raise RuntimeError(
            "Network emulation requires passwordless sudo for `tc`. "
            f"Probe failed with: {stderr or 'unknown error'}"
        )

    def _detectDefaultInterface(self):
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            raise RuntimeError(f"Failed to detect default network interface: {stderr or 'unknown error'}")

        for line in result.stdout.splitlines():
            tokens = line.strip().split()
            if "dev" not in tokens:
                continue
            devIndex = tokens.index("dev")
            if devIndex + 1 < len(tokens):
                return tokens[devIndex + 1]

        raise RuntimeError("Failed to detect default network interface from `ip route show default`")

    def _run(self, command, check=True):
        fullCommand = [*self._sudoPrefix, *command]
        print(f"[Test] tc command: {' '.join(fullCommand)}")
        result = subprocess.run(
            fullCommand,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if check and result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            raise RuntimeError(
                f"Traffic control command failed: {' '.join(fullCommand)} | "
                f"exit={result.returncode} stdout={stdout or '<empty>'} stderr={stderr or '<empty>'}"
            )
        return result


class LinuxShareNetworkNamespace:
    DEFAULT_BURST = "32kbit"
    DEFAULT_LATENCY = "400ms"

    def __init__(self, config, role="share"):
        self.config = config
        self.role = role
        self.externalInterface = ""
        self.namespace = ""
        self.hostVeth = ""
        self.peerVeth = ""
        self.subnet = ""
        self.hostAddress = ""
        self.peerAddress = ""
        self._applied = False
        self._sudoPrefix = []
        self._iptablesCommand = ""
        self._originalIpForward = None
        self._ipForwardChanged = False
        self._wrapperDir = ""
        self._wrapperPaths = {}

    def ensureSupported(self):
        self.config.validate()
        if platform.system() != "Linux":
            raise RuntimeError("Network emulation is only supported on Linux hosts")

        if shutil.which("tc") is None:
            raise RuntimeError("Network emulation requires `tc` on PATH")

        if shutil.which("ip") is None:
            raise RuntimeError("Network emulation requires `ip` on PATH")

        if shutil.which("sysctl") is None:
            raise RuntimeError("Network emulation requires `sysctl` on PATH")

        self._iptablesCommand = shutil.which("iptables") or ""
        if not self._iptablesCommand:
            raise RuntimeError("Network emulation requires `iptables` on PATH")

        self._sudoPrefix = self._determinePrivilegePrefix()
        self.externalInterface = self.config.interface or self._detectDefaultInterface()
        if not self.externalInterface:
            raise RuntimeError(
                "Network emulation could not determine a network interface. "
                "Pass --net-interface explicitly."
            )

    def apply(self):
        self.ensureSupported()
        self._allocateNamespaceTopology()
        print(
            f"[Test] Applying Linux {self.role} namespace emulation: "
            f"{self.config.describe()}, resolved_iface={self.externalInterface}, ns={self.namespace}"
        )
        try:
            self._createNamespace()
            self._enableIpForwarding()
            self._configureNat()
            self._applyQdisc()
            self._applied = True
        except Exception:
            self.clear(quiet=True)
            raise

    def clear(self, quiet=False):
        if self.hostVeth:
            result = self._runPrivileged(["tc", "qdisc", "del", "dev", self.hostVeth, "root"], check=False)
            if result.returncode == 0 and not quiet:
                print(f"[Test] Cleared qdisc on {self.hostVeth}")

        self._removeNatRule(["-D", "POSTROUTING", "-s", self.subnet, "-o", self.externalInterface, "-j", "MASQUERADE"], quiet)
        self._removeFilterRule(["-D", "FORWARD", "-i", self.hostVeth, "-o", self.externalInterface, "-j", "ACCEPT"], quiet)
        self._removeFilterRule(
            ["-D", "FORWARD", "-i", self.externalInterface, "-o", self.hostVeth, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            quiet,
        )

        if self.hostVeth:
            result = self._runPrivileged(["ip", "link", "del", self.hostVeth], check=False)
            if result.returncode == 0 and not quiet:
                print(f"[Test] Removed veth {self.hostVeth}")

        if self.namespace:
            result = self._runPrivileged(["ip", "netns", "del", self.namespace], check=False)
            if result.returncode == 0 and not quiet:
                print(f"[Test] Removed network namespace {self.namespace}")

        if self._wrapperDir and os.path.isdir(self._wrapperDir):
            shutil.rmtree(self._wrapperDir, ignore_errors=True)

        if self._ipForwardChanged and self._originalIpForward is not None:
            self._runPrivileged(["sysctl", "-w", f"net.ipv4.ip_forward={self._originalIpForward}"], check=False)

        self._applied = False

    def wrapShareCommand(self, commandPrefix, extraEnv=None):
        if not self._applied:
            return commandPrefix

        if not self._sudoPrefix:
            return ["ip", "netns", "exec", self.namespace, *commandPrefix]

        envAssignments = self._buildExecEnvAssignments(extraEnv)
        return [*self._sudoPrefix, "env", *envAssignments, "ip", "netns", "exec", self.namespace, *commandPrefix]

    def createExecutableWrapper(self, targetPath, label, extraEnv=None):
        if not self._applied:
            return targetPath

        os.makedirs(self._ensureWrapperDir(), exist_ok=True)
        safeLabel = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-") or "wrapped"
        wrapperPath = os.path.join(self._wrapperDir, safeLabel)
        if not wrapperPath.endswith(".sh"):
            wrapperPath = f"{wrapperPath}.sh"

        envAssignments = self._buildExecEnvAssignments(extraEnv)
        if self._sudoPrefix:
            launchPrefix = [*self._sudoPrefix, "env", *envAssignments, "ip", "netns", "exec", self.namespace]
        else:
            launchPrefix = ["env", *envAssignments, "ip", "netns", "exec", self.namespace]

        scriptLines = [
            "#!/bin/sh",
            f"exec {' '.join(self._shellQuote(token) for token in launchPrefix)} {self._shellQuote(targetPath)} \"$@\"",
            "",
        ]
        with open(wrapperPath, "w", encoding="utf-8", newline="\n") as wrapperFile:
            wrapperFile.write("\n".join(scriptLines))
        os.chmod(wrapperPath, 0o755)
        self._wrapperPaths[label] = wrapperPath
        return wrapperPath

    def getNamespacePeerIp(self):
        return self.peerAddress.split("/")[0] if self.peerAddress else ""

    def getHostPeerIp(self):
        return self.hostAddress.split("/")[0] if self.hostAddress else ""

    def _allocateNamespaceTopology(self):
        suffix = uuid4().hex[:8]
        rolePrefix = "fflshr" if self.role == "share" else "fflbrw"
        self.namespace = f"{rolePrefix}-{suffix}"
        self.hostVeth = f"{rolePrefix[:5]}h{suffix[:5]}"
        self.peerVeth = f"{rolePrefix[:5]}p{suffix[:5]}"
        subnetSuffix = int(suffix[:2], 16)
        self.subnet = f"10.203.{subnetSuffix}.0/24"
        self.hostAddress = f"10.203.{subnetSuffix}.1/24"
        self.peerAddress = f"10.203.{subnetSuffix}.2/24"

    def _createNamespace(self):
        self._runPrivileged(["ip", "netns", "add", self.namespace])
        self._runPrivileged(["ip", "link", "add", self.hostVeth, "type", "veth", "peer", "name", self.peerVeth])
        self._runPrivileged(["ip", "link", "set", self.peerVeth, "netns", self.namespace])
        self._runPrivileged(["ip", "addr", "add", self.hostAddress, "dev", self.hostVeth])
        self._runPrivileged(["ip", "link", "set", self.hostVeth, "up"])
        self._runPrivileged(["ip", "netns", "exec", self.namespace, "ip", "addr", "add", self.peerAddress, "dev", self.peerVeth])
        self._runPrivileged(["ip", "netns", "exec", self.namespace, "ip", "link", "set", self.peerVeth, "up"])
        self._runPrivileged(["ip", "netns", "exec", self.namespace, "ip", "link", "set", "lo", "up"])
        self._runPrivileged(["ip", "netns", "exec", self.namespace, "ip", "route", "add", "default", "via", self.hostAddress.split("/")[0]])

    def _enableIpForwarding(self):
        self._originalIpForward = self._readSysctl("net.ipv4.ip_forward")
        if self._originalIpForward == "1":
            return
        self._runPrivileged(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        self._ipForwardChanged = True

    def _configureNat(self):
        self._runPrivileged(
            [self._iptablesCommand, "-t", "nat", "-A", "POSTROUTING", "-s", self.subnet, "-o", self.externalInterface, "-j", "MASQUERADE"]
        )
        self._runPrivileged(
            [self._iptablesCommand, "-A", "FORWARD", "-i", self.hostVeth, "-o", self.externalInterface, "-j", "ACCEPT"]
        )
        self._runPrivileged(
            [self._iptablesCommand, "-A", "FORWARD", "-i", self.externalInterface, "-o", self.hostVeth, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]
        )

    def _applyQdisc(self):
        for command in self._buildApplyCommands():
            self._runPrivileged(command)

    def _buildApplyCommands(self):
        commands = []
        if self.config.rate:
            burst = self.config.burst or self.DEFAULT_BURST
            latency = self.config.latency or self.DEFAULT_LATENCY
            commands.append(
                [
                    "tc", "qdisc", "add", "dev", self.hostVeth,
                    "root", "handle", "1:", "tbf",
                    "rate", self.config.rate,
                    "burst", burst,
                    "latency", latency,
                ]
            )
            netemCommand = self._buildNetemCommand(parentHandle="1:1", handle="10:")
            if netemCommand:
                commands.append(netemCommand)
            return commands

        netemCommand = self._buildNetemCommand(parentHandle=None, handle=None)
        if netemCommand:
            commands.append(netemCommand)
        return commands

    def _buildNetemCommand(self, parentHandle, handle):
        netemTokens = []
        if self.config.delay:
            netemTokens.extend(["delay", self.config.delay])
            if self.config.jitter:
                netemTokens.append(self.config.jitter)
        if self.config.loss:
            netemTokens.extend(["loss", self.config.loss])

        if not netemTokens:
            return None

        command = ["tc", "qdisc", "add", "dev", self.hostVeth]
        if parentHandle:
            command.extend(["parent", parentHandle])
        else:
            command.append("root")
        if handle:
            command.extend(["handle", handle])
        command.append("netem")
        command.extend(netemTokens)
        return command

    def _determinePrivilegePrefix(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return []

        if shutil.which("sudo") is None:
            raise RuntimeError("Namespaced network emulation requires root privileges or passwordless sudo")

        probe = subprocess.run(
            ["sudo", "-n", "ip", "netns", "list"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if probe.returncode == 0:
            return ["sudo", "-n"]

        stderr = (probe.stderr or "").strip()
        raise RuntimeError(
            "Namespaced network emulation requires passwordless sudo for `ip netns`. "
            f"Probe failed with: {stderr or 'unknown error'}"
        )

    def _detectDefaultInterface(self):
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            raise RuntimeError(f"Failed to detect default network interface: {stderr or 'unknown error'}")

        for line in result.stdout.splitlines():
            tokens = line.strip().split()
            if "dev" not in tokens:
                continue
            devIndex = tokens.index("dev")
            if devIndex + 1 < len(tokens):
                return tokens[devIndex + 1]

        raise RuntimeError("Failed to detect default network interface from `ip route show default`")

    def _readSysctl(self, key):
        result = self._runPrivileged(["sysctl", "-n", key], check=False)
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            raise RuntimeError(f"Failed to read sysctl {key}: {stderr or 'unknown error'}")
        return (result.stdout or "").strip()

    def _removeNatRule(self, args, quiet):
        if not self._iptablesCommand or not self.subnet or not self.externalInterface:
            return
        result = self._runPrivileged([self._iptablesCommand, "-t", "nat", *args], check=False)
        if result.returncode == 0 and not quiet:
            print("[Test] Removed NAT rule")

    def _removeFilterRule(self, args, quiet):
        if not self._iptablesCommand or not self.hostVeth or not self.externalInterface:
            return
        result = self._runPrivileged([self._iptablesCommand, *args], check=False)
        if result.returncode == 0 and not quiet:
            print("[Test] Removed FORWARD rule")

    def _buildExecEnvAssignments(self, extraEnv):
        effectiveEnv = {}
        for key in (
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "DISPLAY",
            "XAUTHORITY",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "PYTHONUNBUFFERED",
        ):
            value = os.getenv(key)
            if value:
                effectiveEnv[key] = value

        for key, value in (extraEnv or {}).items():
            effectiveEnv[key] = str(value)

        return [f"{key}={value}" for key, value in effectiveEnv.items()]

    def _ensureWrapperDir(self):
        if not self._wrapperDir:
            baseDir = os.path.join(os.getcwd(), ".netns_wrappers")
            os.makedirs(baseDir, exist_ok=True)
            self._wrapperDir = tempfile.mkdtemp(prefix=f"{self.role}_netns_wrap_", dir=baseDir)
        return self._wrapperDir

    def _shellQuote(self, value):
        return "'" + str(value).replace("'", "'\"'\"'") + "'"

    def _runPrivileged(self, command, check=True):
        fullCommand = [*self._sudoPrefix, *command]
        print(f"[Test] netns command: {' '.join(fullCommand)}")
        result = subprocess.run(
            fullCommand,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if check and result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            raise RuntimeError(
                f"Namespaced network command failed: {' '.join(fullCommand)} | "
                f"exit={result.returncode} stdout={stdout or '<empty>'} stderr={stderr or '<empty>'}"
            )
        return result


class NamespacedWebDriverServiceMixin:
    def __init__(self, remote_host, *args, **kwargs):
        self.remote_host = remote_host
        super().__init__(*args, **kwargs)

    @property
    def service_url(self):
        return f"http://{selenium_utils.join_host_port(self.remote_host, self.port)}"

    def is_connectable(self):
        return selenium_utils.is_connectable(self.port, self.remote_host)


class NamespacedFirefoxService(NamespacedWebDriverServiceMixin, FirefoxService):
    pass


class NamespacedChromeService(NamespacedWebDriverServiceMixin, ChromeService):
    def __init__(self, network_controller, remote_host, allowed_source_ip, *args, **kwargs):
        self._networkController = network_controller
        self._allowedSourceIp = allowed_source_ip
        self._wrappedExecutable = False
        self._wrapperLabel = kwargs.pop("wrapper_label", "chromedriver-service")

        serviceArgs = list(kwargs.pop("service_args", []) or [])
        if self._allowedSourceIp and not any(arg.startswith("--allowed-ips=") for arg in serviceArgs):
            serviceArgs.append(f"--allowed-ips={self._allowedSourceIp}")
        super().__init__(remote_host, *args, service_args=serviceArgs, **kwargs)

    def start(self):
        if self._networkController and self.path and not self._wrappedExecutable:
            self.path = self._networkController.createExecutableWrapper(self.path, self._wrapperLabel)
            self._wrappedExecutable = True

        super().start()


def createNetworkControllers(config):
    if not config.isEnabled():
        return []
    if config.scope == "host":
        return [LinuxTrafficControl(config)]
    if config.scope == "share":
        return [LinuxShareNetworkNamespace(config, role="share")]
    if config.scope == "browser":
        return [LinuxShareNetworkNamespace(config, role="browser")]
    if config.scope == "both":
        return [
            LinuxShareNetworkNamespace(config, role="share"),
            LinuxShareNetworkNamespace(config, role="browser"),
        ]
    raise ValueError(f"Unsupported network emulation scope: {config.scope}")

@unittest.skipUnless(
    DIRECT_RUN or getEnv("FFL_ENABLE_LARGE_FILE_TESTS", False),
    "Set FFL_ENABLE_LARGE_FILE_TESTS=1 to run manual large-file browser integration tests.",
)
class LargeFileTest(ResumeBrowserTestBase):
    """Manual configurable large-file integration tests for HTTP/WebRTC/browser download and upload flows."""

    DEFAULT_FILE_SIZE = 1
    DISK_SPACE_BUFFER = parseSizeString(os.getenv("FFL_LARGE_FILE_DISK_BUFFER", "512M"))
    BROWSER_MIN_AVAILABLE_MEMORY = parseSizeString(os.getenv("FFL_LARGE_FILE_BROWSER_MIN_AVAILABLE_MEMORY", "512M"))
    BROWSER_MAX_SWAP_USED_PERCENT = float(os.getenv("FFL_LARGE_FILE_BROWSER_MAX_SWAP_USED_PERCENT", "80"))
    LARGE_FILE_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_SIZE", "20G"))
    DEFAULT_BROWSER = os.getenv("FFL_LARGE_FILE_BROWSER", "chrome").strip().lower()
    STALL_AFTER_BYTES = parseSizeString(os.getenv("FFL_LARGE_FILE_STALL_AFTER", "96M"))
    SHARE_READY_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_SHARE_TIMEOUT", "900"))
    UPLOAD_READY_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_UPLOAD_TIMEOUT", "43200"))
    DOWNLOAD_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_DOWNLOAD_TIMEOUT", "43200"))
    FALLBACK_TIMEOUT_MS = int(os.getenv("FFL_LARGE_FILE_FALLBACK_MS", "120000"))
    REQUEST_CHUNK_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_REQUEST_CHUNK_SIZE", "4M"))
    REQUEST_LOG_INTERVAL = parseSizeString(os.getenv("FFL_LARGE_FILE_REQUEST_LOG_INTERVAL", "512M"))
    REQUEST_SOCKET_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_REQUEST_SOCKET_TIMEOUT", "900"))
    ESTIMATE_MIN_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_ESTIMATE_MIN_SIZE", "1G"))
    ESTIMATE_PROBE_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_ESTIMATE_PROBE_SIZE", "16M"))
    ESTIMATE_CACHE_TTL_SECONDS = int(os.getenv("FFL_LARGE_FILE_ESTIMATE_CACHE_TTL", "86400"))
    ESTIMATE_LOWER_FACTOR = float(os.getenv("FFL_LARGE_FILE_ESTIMATE_LOWER_FACTOR", "0.85"))
    ESTIMATE_UPPER_FACTOR = float(os.getenv("FFL_LARGE_FILE_ESTIMATE_UPPER_FACTOR", "1.15"))
    ESTIMATE_ANOMALY_FACTOR = float(os.getenv("FFL_LARGE_FILE_ESTIMATE_ANOMALY_FACTOR", "1.25"))
    ESTIMATE_ANOMALY_GRACE_SECONDS = int(os.getenv("FFL_LARGE_FILE_ESTIMATE_ANOMALY_GRACE_SECONDS", "600"))
    ESTIMATE_CONNECT_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_ESTIMATE_CONNECT_TIMEOUT", "30"))
    VERIFY_HASH = getEnv("FFL_LARGE_FILE_VERIFY_HASH", False)
    NETWORK_EMULATION = NetworkEmulationConfig.fromEnvironment()
    HTTP_PROBE_CACHE = None
    HTTP_PROBE_CACHE_FILE_PATH = None

    def __init__(self, methodName="runTest"):
        super().__init__(methodName)
        self._directRunBrowserOverride = None
        self._directRunRouteOverride = None

    @classmethod
    def configureFromEnvironment(cls):
        cls.DISK_SPACE_BUFFER = parseSizeString(os.getenv("FFL_LARGE_FILE_DISK_BUFFER", "512M"))
        cls.BROWSER_MIN_AVAILABLE_MEMORY = parseSizeString(
            os.getenv("FFL_LARGE_FILE_BROWSER_MIN_AVAILABLE_MEMORY", "512M")
        )
        cls.BROWSER_MAX_SWAP_USED_PERCENT = float(
            os.getenv("FFL_LARGE_FILE_BROWSER_MAX_SWAP_USED_PERCENT", "80")
        )
        cls.LARGE_FILE_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_SIZE", "20G"))
        cls.DEFAULT_BROWSER = os.getenv("FFL_LARGE_FILE_BROWSER", "chrome").strip().lower()
        cls.STALL_AFTER_BYTES = parseSizeString(os.getenv("FFL_LARGE_FILE_STALL_AFTER", "96M"))
        cls.SHARE_READY_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_SHARE_TIMEOUT", "900"))
        cls.UPLOAD_READY_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_UPLOAD_TIMEOUT", "43200"))
        cls.DOWNLOAD_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_DOWNLOAD_TIMEOUT", "43200"))
        cls.FALLBACK_TIMEOUT_MS = int(os.getenv("FFL_LARGE_FILE_FALLBACK_MS", "120000"))
        cls.REQUEST_CHUNK_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_REQUEST_CHUNK_SIZE", "4M"))
        cls.REQUEST_LOG_INTERVAL = parseSizeString(os.getenv("FFL_LARGE_FILE_REQUEST_LOG_INTERVAL", "512M"))
        cls.REQUEST_SOCKET_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_REQUEST_SOCKET_TIMEOUT", "900"))
        cls.ESTIMATE_MIN_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_ESTIMATE_MIN_SIZE", "1G"))
        cls.ESTIMATE_PROBE_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_ESTIMATE_PROBE_SIZE", "16M"))
        cls.ESTIMATE_CACHE_TTL_SECONDS = int(os.getenv("FFL_LARGE_FILE_ESTIMATE_CACHE_TTL", "86400"))
        cls.ESTIMATE_LOWER_FACTOR = float(os.getenv("FFL_LARGE_FILE_ESTIMATE_LOWER_FACTOR", "0.85"))
        cls.ESTIMATE_UPPER_FACTOR = float(os.getenv("FFL_LARGE_FILE_ESTIMATE_UPPER_FACTOR", "1.15"))
        cls.ESTIMATE_ANOMALY_FACTOR = float(os.getenv("FFL_LARGE_FILE_ESTIMATE_ANOMALY_FACTOR", "1.25"))
        cls.ESTIMATE_ANOMALY_GRACE_SECONDS = int(
            os.getenv("FFL_LARGE_FILE_ESTIMATE_ANOMALY_GRACE_SECONDS", "600")
        )
        cls.ESTIMATE_CONNECT_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_ESTIMATE_CONNECT_TIMEOUT", "30"))
        cls.VERIFY_HASH = getEnv("FFL_LARGE_FILE_VERIFY_HASH", False)
        cls.NETWORK_EMULATION = NetworkEmulationConfig.fromEnvironment()

    def setUp(self):
        self.configureFromEnvironment()
        super().setUp()

        self._cleanupPaths = set()
        self._currentOutputCapture = {}
        self._currentDriver = None
        self._networkController = None
        self._networkControllers = []
        self._shareNetworkController = None
        self._browserNetworkController = None
        self._registerSigintHandler()
        self._applyNetworkEmulationIfNeeded()
        self.largeFilePath = self._prepareLargeFile()
        self.testFilePath = self.largeFilePath
        self.originalFileSize = os.path.getsize(self.largeFilePath)
        self.fileSizeBytes = self.originalFileSize
        self.expectedFilename = os.path.basename(self.largeFilePath)

        if self.VERIFY_HASH:
            print("[Test] Computing full SHA-256 for the large test file...")
            self.originalFileHash = getFileHash(self.largeFilePath)
            print(f"[Test] Large file SHA-256: {self.originalFileHash}")
        else:
            self.originalFileHash = None
            print("[Test] Full hash verification disabled for large-file test (size-only verification).")

        print(f"[Test] Large file path: {self.largeFilePath}")
        print(f"[Test] Large file size: {self.originalFileSize} bytes")
        print(f"[Test] Browser: {self._getSelectedBrowserName()}")
        if self._directRunRouteOverride:
            print(f"[Test] Route: {self._directRunRouteOverride}")
            
        if self.NETWORK_EMULATION.isEnabled():
            print(f"[Test] Network emulation: {self.NETWORK_EMULATION.describe()}")

    def shortDescription(self):
        description = super().shortDescription()
        matrixLabel = self._getDirectRunMatrixLabel()
        if description and matrixLabel:
            return f"{description} [{matrixLabel}]"
        return description or matrixLabel

    def _getSelectedBrowserName(self):
        return self._directRunBrowserOverride or self.DEFAULT_BROWSER

    def _getDirectRunMatrixLabel(self):
        if not self._isBrowserDrivenScenario():
            return ""

        labelParts = [f"browser={self._getSelectedBrowserName()}"]
        if self._directRunRouteOverride:
            labelParts.append(f"route={self._directRunRouteOverride}")
        return ", ".join(labelParts)

    def _isBrowserDrivenScenario(self):
        scenarioName = TEST_TO_SCENARIO.get(self._testMethodName)
        return scenarioName in BROWSER_DRIVEN_SCENARIOS

    def _registerSigintHandler(self):
        previousHandler = signal.getsignal(signal.SIGINT)

        def sigintHandler(sig, frame):
            print('\n[Test] Ctrl+C detected - dumping diagnostic logs before exit')
            try:
                self._printServerOutput(self._currentOutputCapture, lastNLines=None)
            except Exception as exc:
                print(f'[Test] Failed to dump server output: {exc}')
            try:
                if self._currentDriver:
                    self._printBrowserLogs(driver=self._currentDriver, title='Browser logs at Ctrl+C')
            except Exception as exc:
                print(f'[Test] Failed to dump browser logs: {exc}')
            signal.signal(signal.SIGINT, previousHandler)
            os.kill(os.getpid(), signal.SIGINT)

        signal.signal(signal.SIGINT, sigintHandler)

    def prepareTestConfigDir(self, tempConfigDir):
        preparedDir = super().prepareTestConfigDir(tempConfigDir)
        self._writeBuiltinTunnelConfig(preparedDir)
        return preparedDir

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            self._clearNetworkEmulationIfNeeded()
            self._cleanupLargeArtifacts()

    def _prepareLargeFile(self):
        existingPath = os.getenv("FFL_LARGE_FILE_PATH")
        if existingPath:
            existingPath = os.path.abspath(existingPath)
            if not os.path.exists(existingPath):
                raise AssertionError(f"FFL_LARGE_FILE_PATH does not exist: {existingPath}")

            actualSize = os.path.getsize(existingPath)
            if actualSize != self.LARGE_FILE_SIZE:
                raise AssertionError(
                    f"Expected {self.LARGE_FILE_SIZE} bytes at FFL_LARGE_FILE_PATH, got {actualSize}: {existingPath}"
                )
            return existingPath

        outputDir = os.path.abspath(os.getenv("FFL_LARGE_FILE_DIR", self.tempDir))
        os.makedirs(outputDir, exist_ok=True)
        self._assertDiskSpaceAvailable(
            outputDir,
            self.LARGE_FILE_SIZE,
            "large file source directory",
            envVarName="FFL_LARGE_FILE_DIR",
        )

        filePath = os.path.join(outputDir, f"large_{self.LARGE_FILE_SIZE}_bytes.bin")
        if os.path.exists(filePath):
            currentSize = os.path.getsize(filePath)
            if currentSize == self.LARGE_FILE_SIZE:
                print(f"[Test] Reusing existing large file: {filePath}")
                return filePath

            print(f"[Test] Replacing stale large file with wrong size ({currentSize} bytes): {filePath}")
            os.remove(filePath)

        self._createLargePlaceholderFile(filePath, self.LARGE_FILE_SIZE)
        return filePath

    def _createLargePlaceholderFile(self, filePath, sizeBytes):
        print(f"[Test] Creating {sizeBytes} byte large file placeholder: {filePath}")

        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["fsutil", "file", "createnew", filePath, str(sizeBytes)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=True
                )
                if result.stdout.strip():
                    print(f"[Test] fsutil: {result.stdout.strip()}")
                return
            except Exception as exc:
                print(f"[Test] fsutil file creation failed, falling back to sparse seek: {exc}")

        else:
            try:
                subprocess.run(["truncate", "-s", str(sizeBytes), filePath], timeout=120, check=True)
                return
            except Exception as exc:
                print(f"[Test] truncate failed, falling back to sparse seek: {exc}")

        with open(filePath, "wb") as handle:
            if sizeBytes > 0:
                handle.seek(sizeBytes - 1)
                handle.write(b"\0")

    def _applyNetworkEmulationIfNeeded(self):
        if not self.NETWORK_EMULATION.isEnabled():
            return

        try:
            controllers = createNetworkControllers(self.NETWORK_EMULATION)
            for controller in controllers:
                controller.apply()
                if not isinstance(controller, LinuxShareNetworkNamespace):
                    continue

                if controller.role == "share":
                    self._shareNetworkController = controller
                    continue

                if controller.role == "browser":
                    self._browserNetworkController = controller
            self._networkControllers = controllers
            self._networkController = controllers[0] if controllers else None
        except (RuntimeError, ValueError) as exc:
            self.skipTest(f"Network emulation requested but unsupported: {exc}")

    def _clearNetworkEmulationIfNeeded(self):
        if not self._networkControllers:
            return

        try:
            for controller in reversed(self._networkControllers):
                controller.clear()
        finally:
            self._browserNetworkController = None
            self._shareNetworkController = None
            self._networkControllers = []
            self._networkController = None

    def _writeBuiltinTunnelConfig(self, configDir):
        configPath = os.path.join(configDir, "tunnels.json")
        tunnelDomain = (
            os.getenv("FFL_TUNNEL_DOMAIN")
            or os.getenv("BUILTIN_TUNNEL")
            or "33.fastfilelink.com"
        ).strip()
        config = {
            "tunnels": {},
            "settings": {
                "preferred_tunnel": "default",
                "fallback_order": ["default"],
            },
            "_comment": (
                "LargeFileTest pins builtin tunnel usage so isolated test configs do not "
                "auto-create a cloudflare-preferred tunnels.json."
            ),
        }
        with open(configPath, "w", encoding="utf-8") as configFile:
            json.dump(config, configFile, indent=2)
        print(f"[Test] Wrote builtin-only tunnel config to {configPath} for {tunnelDomain}")

    def _cleanupLargeArtifacts(self):
        cleanupTargets = sorted(self._cleanupPaths, key=lambda path: len(path), reverse=True)
        for targetPath in cleanupTargets:
            if not targetPath:
                continue

            try:
                if os.path.isdir(targetPath):
                    print(f"[Test] Cleaning download directory: {targetPath}")
                    shutil.rmtree(targetPath, ignore_errors=True)
                elif os.path.exists(targetPath):
                    print(f"[Test] Removing downloaded file: {targetPath}")
                    os.remove(targetPath)
            except Exception as exc:
                print(f"[Test] Warning: failed to clean large-file artifact {targetPath}: {exc}")

    def _registerCleanupPath(self, path):
        if path:
            self._cleanupPaths.add(os.path.abspath(path))

    def _assertDiskSpaceAvailable(self, targetPath, requiredBytes, purpose, envVarName):
        targetPath = os.path.abspath(targetPath)
        usage = shutil.disk_usage(targetPath)
        requiredWithBuffer = requiredBytes + self.DISK_SPACE_BUFFER
        print(
            f"[Test] Disk check for {purpose}: path={targetPath}, "
            f"free={usage.free} bytes, required={requiredBytes} bytes, buffer={self.DISK_SPACE_BUFFER} bytes"
        )
        if usage.free >= requiredWithBuffer:
            return

        raise AssertionError(
            f"Insufficient free space for {purpose}: path={targetPath}, free={usage.free} bytes, "
            f"required at least {requiredWithBuffer} bytes "
            f"(file size {requiredBytes} + buffer {self.DISK_SPACE_BUFFER}). "
            f"Set {envVarName} to a larger filesystem."
        )

    def _getLargeDownloadRoot(self):
        rootPath = os.path.abspath(os.getenv("FFL_LARGE_FILE_DOWNLOAD_DIR", self.tempDir))
        os.makedirs(rootPath, exist_ok=True)
        self._assertDiskSpaceAvailable(
            rootPath,
            self.LARGE_FILE_SIZE,
            "large file download directory",
            envVarName="FFL_LARGE_FILE_DOWNLOAD_DIR",
        )
        return rootPath

    def _prepareDownloadDir(self, browserName):
        downloadDir = os.path.join(self._getLargeDownloadRoot(), f"{self._testMethodName}_{browserName}_downloads")
        if os.path.isdir(downloadDir):
            shutil.rmtree(downloadDir, ignore_errors=True)
        os.makedirs(downloadDir, exist_ok=True)
        self._registerCleanupPath(downloadDir)
        return downloadDir

    def _setupBrowserAndDir(self):
        self._cleanupStaleBrowserProcesses()
        self._assertBrowserHostResourcesHealthy()
        browserName = self._getSelectedBrowserName()
        downloadDir = self._prepareDownloadDir(browserName)

        if browserName == "chrome":
            driver = self._setupChromeDriver(downloadDir)
        elif browserName == "firefox":
            driver = self._setupFirefoxDriver(downloadDir)
        else:
            raise ValueError(f"Unsupported FFL_LARGE_FILE_BROWSER: {browserName}")

        return driver, downloadDir

    def _assertBrowserHostResourcesHealthy(self):
        virtualMemory = psutil.virtual_memory()
        swapMemory = psutil.swap_memory()

        print(
            f"[Test] Browser host resource check: "
            f"available_mem={virtualMemory.available} bytes, "
            f"swap_used={swapMemory.used} bytes, "
            f"swap_percent={swapMemory.percent:.1f}%"
        )

        if virtualMemory.available < self.BROWSER_MIN_AVAILABLE_MEMORY:
            raise AssertionError(
                "Host resources are too constrained to start a browser large-file case safely: "
                f"available memory is {virtualMemory.available} bytes, which is below the required "
                f"{self.BROWSER_MIN_AVAILABLE_MEMORY} bytes. "
                "Wait for previous browser processes to exit, reboot/clean the host, or lower "
                "FFL_LARGE_FILE_BROWSER_MIN_AVAILABLE_MEMORY if you intentionally want to proceed."
            )

        if swapMemory.total > 0 and swapMemory.percent >= self.BROWSER_MAX_SWAP_USED_PERCENT:
            raise AssertionError(
                "Host swap usage is already too high to start another browser large-file case safely: "
                f"swap usage is {swapMemory.percent:.1f}% ({swapMemory.used}/{swapMemory.total} bytes), "
                f"threshold is {self.BROWSER_MAX_SWAP_USED_PERCENT:.1f}%. "
                "Clean up stuck browser/test processes, reboot the host, or raise "
                "FFL_LARGE_FILE_BROWSER_MAX_SWAP_USED_PERCENT if you intentionally want to proceed."
            )

    def _cleanupStaleBrowserProcesses(self):
        killedPids = []
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmdlineList = proc.info.get("cmdline") or []
                cmdline = " ".join(cmdlineList).lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if not cmdline:
                continue

            isHeadlessChrome = (
                name in ("chrome.exe", "chrome", "google-chrome", "google-chrome-stable")
                and "--headless" in cmdline
            )
            isTestChrome = (
                isHeadlessChrome
                and (
                    "--test-type" in cmdline
                    or "localhost:8000" in cmdline
                    or "fastfilelink.com" in cmdline
                    or "127.0.0.1" in cmdline
                )
            )
            isTestDriver = name in (
                "undetected_chromedriver.exe",
                "chromedriver.exe",
                "undetected_chromedriver",
                "chromedriver",
            )

            if not (isTestChrome or isTestDriver):
                continue

            try:
                proc.kill()
                killedPids.append(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                print(f"[Test] Warning: failed to kill stale browser process {proc.info['pid']}: {exc}")

        if killedPids:
            print(f"[Test] Cleaned stale browser/driver processes: {killedPids}")

    def _addQueryParams(self, url, **params):
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        for key, value in params.items():
            query[key] = str(value)
        return urlunparse(parsed._replace(query=urlencode(query)))

    def _downloadUrlFromShareLink(self, shareLink):
        return shareLink.rstrip("/") + "/download"

    def _createDownloadSession(self):
        try:
            SettingsGetter.getInstance()
        except RuntimeError:
            SettingsGetter(platform=platform.system(), exePath=sys.executable)

        session = requests.Session()
        adapter = StallResilientAdapter(
            chunkSize=self.REQUEST_CHUNK_SIZE,
            allowedMethods={"GET"},
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _getObservedRequestUrls(self, driver):
        urls = []
        if not self._isChromeDriver(driver):
            return self._extractRequestUrlsFromBrowserLogs(driver)

        try:
            for entry in driver.get_log("performance"):
                try:
                    message = json.loads(entry["message"])["message"]
                except Exception:
                    continue

                params = message.get("params", {})
                requestUrl = params.get("request", {}).get("url")
                responseUrl = params.get("response", {}).get("url")
                if requestUrl:
                    urls.append(requestUrl)
                elif responseUrl:
                    urls.append(responseUrl)
        except Exception as exc:
            print(f"[Test] Warning: failed to collect Chrome performance request URLs: {exc}")
            urls.extend(self._extractRequestUrlsFromBrowserLogs(driver))
        return urls

    def _extractRequestUrlsFromBrowserLogs(self, driver):
        urls = []
        seen = set()
        try:
            browserLogs = self._getBrowserLogs(driver)
        except Exception as exc:
            print(f"[Test] Warning: failed to retrieve browser logs for request evidence: {exc}")
            return urls

        for logEntry in browserLogs:
            try:
                message, level = self._normalizeLogEntry(logEntry)
            except Exception:
                continue

            if "/download" not in message and "/offer" not in message:
                continue

            for match in re.findall(r"https?://[^\s'\"`]+", message):
                normalized = match.rstrip("),.;")
                if normalized in seen:
                    continue
                seen.add(normalized)
                urls.append(normalized)

            if "/download" in message and "/download" not in seen:
                seen.add("/download")
                urls.append("/download")
            if "/offer" in message and "/offer" not in seen:
                seen.add("/offer")
                urls.append("/offer")

        if urls:
            print(f"[Test] Derived request evidence from browser logs: {urls}")
        return urls

    def _getObservedServerRequestPaths(self, outputCapture):
        if not outputCapture:
            return set()

        serverOutput = self._updateCapturedOutput(outputCapture)
        observedPaths = set()
        if re.search(r"\bGET\s+/offer\b", serverOutput):
            observedPaths.add("/offer")
        if re.search(r"\bGET\s+/download\b", serverOutput):
            observedPaths.add("/download")
        return observedPaths

    def _createBrowserEvidence(self):
        return {
            "observedUrls": set(),
            "fallbackDetected": False,
            "resumeDetected": False,
            "writerUsed": False,
            "baseBytes": 0,
        }

    def _updateBrowserEvidence(self, driver, evidence):
        if not driver or evidence is None:
            return evidence

        for url in self._getObservedRequestUrls(driver):
            evidence["observedUrls"].add(url)

        analysis = self._analyzeBrowserLogsForResume(driver)
        evidence["fallbackDetected"] = evidence["fallbackDetected"] or analysis["fallbackDetected"]
        evidence["resumeDetected"] = evidence["resumeDetected"] or analysis["resumeDetected"]
        evidence["writerUsed"] = evidence["writerUsed"] or analysis["writerUsed"]
        evidence["baseBytes"] = max(evidence["baseBytes"], analysis["baseBytes"])
        return evidence

    def _analysisFromEvidence(self, evidence):
        if not evidence:
            return {
                "resumeDetected": False,
                "fallbackDetected": False,
                "writerUsed": False,
                "baseBytes": 0,
                "logs": [],
            }

        return {
            "resumeDetected": evidence["resumeDetected"],
            "fallbackDetected": evidence["fallbackDetected"],
            "writerUsed": evidence["writerUsed"],
            "baseBytes": evidence["baseBytes"],
            "logs": [],
        }

    def _getResumeEvidenceUrls(self, observedUrls):
        if not observedUrls:
            return []

        return [
            url for url in observedUrls
            if "/download" in url and (
                "resume_start=" in url
                or "resume_base=" in url
                or "ff_auto_resume=1" in url
                or "dl_path=sw_writer_resume" in url
            )
        ]

    def _printTransferSummary(self, label, totalBytes, elapsedSeconds):
        if elapsedSeconds <= 0:
            print(f"[Test] {label} summary: elapsed time too small to calculate throughput")
            return

        mibPerSecond = (totalBytes / (1024 * 1024)) / elapsedSeconds
        mbps = (totalBytes * 8) / elapsedSeconds / 1_000_000
        print(
            f"[Test] {label} summary: {totalBytes} bytes in {elapsedSeconds:.1f}s "
            f"({mibPerSecond:.2f} MiB/s, {mbps:.1f} Mbps)"
        )

    def _shouldPrintHTTPProbeEstimate(self):
        return self.originalFileSize >= self.ESTIMATE_MIN_SIZE

    def _normalizeHTTPProbeCacheHost(self, requestUrl):
        hostname = (urlparse(requestUrl).hostname or "").strip().lower()
        hostLabels = hostname.split(".")

        if len(hostLabels) >= 3 and hostLabels[0].isdigit():
            return ".".join(hostLabels[1:])

        return hostname

    def _getHTTPProbeCacheKey(self, requestUrl):
        return self._normalizeHTTPProbeCacheHost(requestUrl)

    def _getHTTPProbeCacheFilePath(self):
        cacheFile = os.getenv("FFL_LARGE_FILE_ESTIMATE_CACHE_FILE", "").strip()
        if cacheFile:
            return os.path.abspath(cacheFile)

        if self.__class__.HTTP_PROBE_CACHE_FILE_PATH:
            return self.__class__.HTTP_PROBE_CACHE_FILE_PATH

        storageLocator = StorageLocator.getInstance()
        candidateDirs = [
            getattr(storageLocator, "_platformDir", ""),
            getattr(storageLocator, "_homeDir", ""),
            os.path.abspath("."),
        ]
        cacheFilename = "large_file_test_http_probe_cache.json"

        for candidateDir in candidateDirs:
            if not candidateDir:
                continue
            try:
                os.makedirs(candidateDir, exist_ok=True)
                cacheFilePath = os.path.join(candidateDir, cacheFilename)
                self.__class__.HTTP_PROBE_CACHE_FILE_PATH = cacheFilePath
                return cacheFilePath
            except OSError as exc:
                print(f"[Test] HTTP preflight cache directory unavailable: {candidateDir} => {exc}")

        fallbackPath = os.path.abspath(cacheFilename)
        self.__class__.HTTP_PROBE_CACHE_FILE_PATH = fallbackPath
        return fallbackPath

    def _pruneExpiredHTTPProbeCache(self, cacheData, now=None):
        now = time.time() if now is None else now
        prunedCache = {}
        ttlSeconds = max(0, self.ESTIMATE_CACHE_TTL_SECONDS)

        for cacheKey, cacheEntry in (cacheData or {}).items():
            if not isinstance(cacheEntry, dict):
                continue

            timestamp = cacheEntry.get("timestamp")
            if not isinstance(timestamp, (int, float)):
                continue

            if ttlSeconds and (now - timestamp) > ttlSeconds:
                continue

            prunedCache[cacheKey] = cacheEntry

        return prunedCache

    def _loadHTTPProbeCache(self):
        if self.__class__.HTTP_PROBE_CACHE is not None:
            return self.__class__.HTTP_PROBE_CACHE

        cacheFilePath = self._getHTTPProbeCacheFilePath()
        loadedCache = {}

        if os.path.exists(cacheFilePath):
            try:
                with open(cacheFilePath, "r", encoding="utf-8") as cacheFile:
                    cachePayload = json.load(cacheFile)
                if isinstance(cachePayload, dict):
                    loadedCache = self._pruneExpiredHTTPProbeCache(cachePayload)
                else:
                    print(f"[Test] HTTP preflight cache ignored: root JSON must be an object ({cacheFilePath})")
            except (OSError, ValueError) as exc:
                print(f"[Test] HTTP preflight cache load warning: {cacheFilePath} => {exc}")

        self.__class__.HTTP_PROBE_CACHE = loadedCache
        return self.__class__.HTTP_PROBE_CACHE

    def _saveHTTPProbeCache(self):
        cacheFilePath = self._getHTTPProbeCacheFilePath()
        cacheDirectory = os.path.dirname(cacheFilePath) or "."
        cachePayload = self._pruneExpiredHTTPProbeCache(self._loadHTTPProbeCache())

        try:
            os.makedirs(cacheDirectory, exist_ok=True)
            tempCachePath = f"{cacheFilePath}.tmp"
            with open(tempCachePath, "w", encoding="utf-8") as cacheFile:
                json.dump(cachePayload, cacheFile, indent=2, sort_keys=True)
            os.replace(tempCachePath, cacheFilePath)
        except OSError as exc:
            print(f"[Test] HTTP preflight cache save warning: {cacheFilePath} => {exc}")

    def _getCachedHTTPProbe(self, cacheKey):
        cacheNow = time.time()
        cacheData = self._loadHTTPProbeCache()
        cachedProbe = cacheData.get(cacheKey)
        if not cachedProbe:
            return None

        timestamp = cachedProbe.get("timestamp")
        if not isinstance(timestamp, (int, float)):
            cacheData.pop(cacheKey, None)
            self._saveHTTPProbeCache()
            return None

        if self.ESTIMATE_CACHE_TTL_SECONDS and (cacheNow - timestamp) > self.ESTIMATE_CACHE_TTL_SECONDS:
            cacheData.pop(cacheKey, None)
            self._saveHTTPProbeCache()
            return None

        return dict(cachedProbe, fromCache=True)

    def _storeCachedHTTPProbe(self, cacheKey, probeResult):
        cacheData = self._loadHTTPProbeCache()
        cacheData[cacheKey] = dict(probeResult, fromCache=False)
        self._saveHTTPProbeCache()

    def _getHTTPProbeScenarioNote(self, requestUrl):
        scenarioName = TEST_TO_SCENARIO.get(self._testMethodName)
        queryValues = dict(parse_qsl(urlparse(requestUrl).query, keep_blank_values=True))
        webrtcValue = str(queryValues.get("webrtc", "")).strip().lower()
        webrtcExplicitlyDisabled = webrtcValue in ("0", "false", "off", "no")

        if scenarioName in ("http-request", "http-browser") or webrtcExplicitlyDisabled:
            return None

        if scenarioName == "upload":
            return (
                "This estimate covers recipient-side HTTP relay throughput only; "
                "uploader-side cloud upload time is not included."
            )

        return (
            "This estimate is based on an HTTP tunnel probe; actual runtime may differ "
            "if the scenario spends time on P2P before falling back."
        )

    def _formatDurationCompact(self, seconds):
        seconds = max(0, int(round(seconds)))
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        parts = []

        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if secs or not parts:
            parts.append(f"{secs}s")

        return " ".join(parts)

    def _formatCompletionClock(self, dt):
        timeFormat = "%H:%M:%S" if dt.date() == datetime.now().date() else "%m-%d %H:%M:%S"
        return dt.strftime(timeFormat)

    def _probeHTTPTransferRate(self, requestUrl):
        probeBytes = max(1, min(self.originalFileSize, self.ESTIMATE_PROBE_SIZE))
        cacheKey = self._getHTTPProbeCacheKey(requestUrl)
        cachedProbe = self._getCachedHTTPProbe(cacheKey)

        if cachedProbe:
            return cachedProbe

        chunkSize = max(64 * 1024, min(self.REQUEST_CHUNK_SIZE, probeBytes, 1024 * 1024))
        socketTimeout = max(30, min(self.DOWNLOAD_TIMEOUT, self.REQUEST_SOCKET_TIMEOUT))
        headers = {
            "Cache-Control": "no-cache",
            "Range": f"bytes=0-{probeBytes - 1}",
        }

        session = self._createDownloadSession()
        response = None
        measuredBytes = 0
        startTime = time.time()

        try:
            response = session.get(
                requestUrl,
                stream=True,
                timeout=(self.ESTIMATE_CONNECT_TIMEOUT, socketTimeout),
                headers=headers,
            )
            response.raise_for_status()

            for chunk in response.iter_content(chunk_size=chunkSize):
                if not chunk:
                    continue

                remainingBytes = probeBytes - measuredBytes
                measuredBytes += min(len(chunk), remainingBytes)
                if measuredBytes >= probeBytes:
                    break

            elapsedSeconds = max(time.time() - startTime, 0.001)
            if measuredBytes <= 0:
                raise AssertionError("HTTP preflight probe did not receive any bytes")

            probeResult = {
                "timestamp": time.time(),
                "requestUrl": requestUrl,
                "probeBytes": probeBytes,
                "measuredBytes": measuredBytes,
                "elapsedSeconds": elapsedSeconds,
                "bytesPerSecond": measuredBytes / elapsedSeconds,
                "statusCode": response.status_code,
                "contentRange": response.headers.get("Content-Range"),
                "fromCache": False,
            }
            self._storeCachedHTTPProbe(cacheKey, probeResult)
            return probeResult
        finally:
            if response is not None:
                try:
                    response.close()
                except OSError as exc:
                    print(f"[Test] HTTP preflight probe response close warning: {exc}")
            session.close()

    def _printHTTPTransferEstimate(self, requestUrl, label):
        if not self._shouldPrintHTTPProbeEstimate():
            return

        note = self._getHTTPProbeScenarioNote(requestUrl)
        print(f"[Test] HTTP preflight estimate for {label}: probing tunnel throughput...")

        try:
            probeResult = self._probeHTTPTransferRate(requestUrl)
        except Exception as exc:
            print(f"[Test] HTTP preflight estimate skipped: {exc}")
            return

        bytesPerSecond = probeResult["bytesPerSecond"]
        if bytesPerSecond <= 0:
            print("[Test] HTTP preflight estimate skipped: measured throughput was zero")
            return

        sampleMiBPerSecond = bytesPerSecond / (1024 * 1024)
        sampleMbps = (bytesPerSecond * 8) / 1_000_000
        sampleSource = "cache" if probeResult.get("fromCache") else "live probe"

        centerSeconds = self.originalFileSize / bytesPerSecond
        lowerSeconds = centerSeconds * self.ESTIMATE_LOWER_FACTOR
        upperSeconds = centerSeconds * self.ESTIMATE_UPPER_FACTOR
        anomalySeconds = max(
            upperSeconds * self.ESTIMATE_ANOMALY_FACTOR,
            upperSeconds + self.ESTIMATE_ANOMALY_GRACE_SECONDS,
        )

        now = datetime.now()
        finishLower = now + timedelta(seconds=lowerSeconds)
        finishUpper = now + timedelta(seconds=upperSeconds)
        anomalyCutoff = now + timedelta(seconds=anomalySeconds)

        print(
            f"[Test] HTTP preflight sample ({sampleSource}): {probeResult['measuredBytes']} bytes "
            f"in {probeResult['elapsedSeconds']:.2f}s "
            f"({sampleMiBPerSecond:.2f} MiB/s, {sampleMbps:.1f} Mbps), status={probeResult['statusCode']}"
        )
        if probeResult["contentRange"]:
            print(f"[Test] HTTP preflight Content-Range: {probeResult['contentRange']}")

        print(
            f"[Test] Estimated completion for {self.originalFileSize} bytes: "
            f"{self._formatDurationCompact(lowerSeconds)} to {self._formatDurationCompact(upperSeconds)}"
        )
        print(
            f"[Test] Expected finish window: {self._formatCompletionClock(finishLower)} "
            f"to {self._formatCompletionClock(finishUpper)}"
        )
        print(
            f"[Test] If still running well past {self._formatCompletionClock(anomalyCutoff)}, "
            "it may indicate an anomaly."
        )
        if note:
            print(f"[Test] Note: {note}")

    def _waitForLargeDownload(self, downloadDir, expectedFilename, timeout, driver=None, evidence=None):
        partialSuffixes = (".part", ".crdownload", ".tmp")
        stem = os.path.splitext(expectedFilename)[0]

        def findFinishedFile():
            if not os.path.isdir(downloadDir):
                return None

            for fileName in os.listdir(downloadDir):
                if fileName == expectedFilename or fileName.startswith(stem):
                    filePath = os.path.join(downloadDir, fileName)
                    if not fileName.endswith(partialSuffixes) and os.path.isfile(filePath):
                        if os.path.getsize(filePath) > 0:
                            return filePath
            return None

        def getLargestPartial():
            largestPath = None
            largestSize = 0
            if not os.path.isdir(downloadDir):
                return largestPath, largestSize

            for fileName in os.listdir(downloadDir):
                if not (fileName == expectedFilename or fileName.startswith(stem)):
                    continue

                if not fileName.endswith(partialSuffixes):
                    continue

                filePath = os.path.join(downloadDir, fileName)
                try:
                    size = os.path.getsize(filePath)
                except OSError:
                    continue

                if size > largestSize:
                    largestPath = filePath
                    largestSize = size

            return largestPath, largestSize

        startTime = time.time()
        lastLoggedSize = -1
        lastProgressTime = startTime
        lastProgressSize = 0

        print(f"[Test] Waiting for large download in: {downloadDir}")
        print(f"[Test] Expected filename: {expectedFilename}")
        print(f"[Test] Timeout: {timeout} seconds")

        while time.time() - startTime < timeout:
            self._updateBrowserEvidence(driver, evidence)

            downloadedFile = findFinishedFile()
            if downloadedFile:
                self._updateBrowserEvidence(driver, evidence)
                elapsed = time.time() - startTime
                finalSize = os.path.getsize(downloadedFile)
                print(f"[Test] Large download completed: {downloadedFile}")
                self._printTransferSummary("Browser download", finalSize, elapsed)
                return downloadedFile

            partialPath, partialSize = getLargestPartial()
            now = time.time()

            if partialSize > lastProgressSize:
                lastProgressSize = partialSize
                lastProgressTime = now

            if partialSize != lastLoggedSize:
                if partialPath:
                    print(f"[Test] Partial progress: {partialSize} bytes ({partialPath})")
                elif not os.path.isdir(downloadDir):
                    print(f"[Test] Download directory not created yet: {downloadDir}")
                lastLoggedSize = partialSize

            stallDuration = now - lastProgressTime
            if partialSize > 0 and stallDuration >= 300:
                print(
                    f"[Test] WARNING: Large download stalled for {stallDuration:.0f}s at {partialSize} bytes"
                )
                lastProgressTime = now

            time.sleep(5)

        if driver is not None:
            try:
                self._updateBrowserEvidence(driver, evidence)
                self._printBrowserLogs(driver=driver, title="Browser logs at large-download timeout")
            except Exception as exc:
                print(f"[Test] Failed to print browser logs after timeout: {exc}")

        raise AssertionError(f"Large download did not complete within {timeout} seconds")

    def _downloadWithBrowserTimeout(self, driver, shareUrl, downloadDir, expectedFilename, timeout, evidence=None):
        print(f"[Test] Navigating browser to: {shareUrl}")
        driver.get(shareUrl)
        WebDriverWait(driver, 20).until(lambda d: d.execute_script("return document.readyState") == "complete")

        try:
            capabilities = driver.capabilities
            if "firefox" in capabilities.get("browserName", "").lower():
                self._attachConsoleMirror(driver)
        except Exception:
            pass

        return self._waitForLargeDownload(downloadDir, expectedFilename, timeout, driver=driver, evidence=evidence)

    def _downloadWithRequests(self, requestUrl, outputPath, timeout):
        self._registerCleanupPath(outputPath)
        os.makedirs(os.path.dirname(outputPath), exist_ok=True)

        totalBytes = 0
        lastLoggedThreshold = 0
        startTime = time.time()
        socketTimeout = max(60, min(timeout, self.REQUEST_SOCKET_TIMEOUT))

        self._printHTTPTransferEstimate(requestUrl, "direct HTTP download")
        print(f"[Test] Starting direct HTTP download: {requestUrl}")
        print(f"[Test] Request chunk size: {self.REQUEST_CHUNK_SIZE} bytes")
        print(f"[Test] Direct download output: {outputPath}")
        print(f"[Test] Direct HTTP socket timeout: {socketTimeout} seconds")

        session = self._createDownloadSession()
        try:
            with session.get(
                requestUrl,
                stream=True,
                timeout=(60, socketTimeout),
                headers={"Cache-Control": "no-cache"},
            ) as response:
                response.raise_for_status()
                print(f"[Test] Direct HTTP status: {response.status_code}")
                print(f"[Test] Final URL: {response.url}")
                print(f"[Test] Content-Length: {response.headers.get('Content-Length')}")

                with open(outputPath, "wb") as outputHandle:
                    for chunk in response.iter_content(chunk_size=self.REQUEST_CHUNK_SIZE):
                        if not chunk:
                            continue

                        outputHandle.write(chunk)
                        totalBytes += len(chunk)

                        if totalBytes - lastLoggedThreshold >= self.REQUEST_LOG_INTERVAL:
                            elapsed = time.time() - startTime
                            print(
                                f"[Test] Direct HTTP progress: {totalBytes} bytes in {elapsed:.1f}s"
                            )
                            lastLoggedThreshold = totalBytes
        finally:
            session.close()

        elapsed = time.time() - startTime
        print(f"[Test] Direct HTTP download completed: {totalBytes} bytes in {elapsed:.1f}s")
        self._printTransferSummary("Direct HTTP download", totalBytes, elapsed)
        return outputPath

    def _verifyLargeDownloadedFile(self, downloadedFilePath):
        if not os.path.exists(downloadedFilePath):
            raise AssertionError(f"Downloaded file does not exist: {downloadedFilePath}")

        downloadedFileSize = os.path.getsize(downloadedFilePath)
        print(f"[Test] Downloaded large file size: {downloadedFileSize} bytes")

        if downloadedFileSize != self.originalFileSize:
            raise AssertionError(
                f"Downloaded file size ({downloadedFileSize}) does not match expected ({self.originalFileSize})"
            )

        if self.originalFileHash:
            print("[Test] Computing downloaded file SHA-256...")
            downloadedHash = getFileHash(downloadedFilePath)
            print(f"[Test] Downloaded file SHA-256: {downloadedHash}")
            if downloadedHash != self.originalFileHash:
                raise AssertionError("Downloaded large file hash does not match the original")

        print("[Test] Large file verification successful")

    def _startLargeShare(self, p2p=True, timeout=None):
        shareEnv = self._getLargeShareEnv()
        binaryCommand = self._buildLargeShareBinaryCommand(shareEnv)
        outputCapture = {}
        shareLink = self._startFastFileLink(
            p2p=p2p,
            output=False,
            timeout=timeout or (self.SHARE_READY_TIMEOUT if p2p else self.UPLOAD_READY_TIMEOUT),
            captureOutputIn=outputCapture,
            extraEnvVars=shareEnv,
            extraArgs=["--preferred-tunnel", "default"],
            binaryCommand=binaryCommand,
        )
        self._currentOutputCapture = outputCapture
        return shareLink, outputCapture

    def _buildLargeShareBinaryCommand(self, shareEnv):
        configuredBinary = os.getenv("FFL_LARGE_FILE_BINARY", "").strip()
        if configuredBinary:
            commandPrefix = self._normalizeCommandSpec(configuredBinary)
            if not commandPrefix:
                raise AssertionError("FFL_LARGE_FILE_BINARY resolved to an empty command")
            commandPrefix = self._adaptExternalCommandForPlatform(commandPrefix)
        else:
            coreScriptPath = os.path.join(os.path.dirname(__file__), "CorePatched.py")
            if not os.path.exists(coreScriptPath):
                raise AssertionError(f"CorePatched.py not found at: {coreScriptPath}")
            commandPrefix = [sys.executable, coreScriptPath, "--cli"]

        if self._shareNetworkController:
            commandPrefix = self._shareNetworkController.wrapShareCommand(commandPrefix, extraEnv=shareEnv)
        return commandPrefix

    def _resolveBrowserBinaryPath(self, browserName, binaryPath):
        return binaryPath

    def _createNamespacedService(self, serviceClass, executablePath=None, label="", **kwargs):
        remoteHost = self._browserNetworkController.getNamespacePeerIp()
        serviceKwargs = dict(kwargs)
        if executablePath:
            wrappedPath = self._browserNetworkController.createExecutableWrapper(executablePath, label)
            serviceKwargs["executable_path"] = wrappedPath

        return serviceClass(remote_host=remoteHost, **serviceKwargs)

    def _createChromeService(self):
        if not self._browserNetworkController:
            return super()._createChromeService()

        return self._createNamespacedService(
            NamespacedChromeService,
            label="chromedriver-service",
            network_controller=self._browserNetworkController,
            allowed_source_ip=self._browserNetworkController.getHostPeerIp(),
        )

    def _createFirefoxService(self, geckoDriverPath):
        if not self._browserNetworkController:
            return super()._createFirefoxService(geckoDriverPath)

        remoteHost = self._browserNetworkController.getNamespacePeerIp()
        return self._createNamespacedService(
            NamespacedFirefoxService,
            geckoDriverPath,
            "geckodriver-service",
            service_args=["--host", remoteHost],
        )

    def _getLargeShareEnv(self):
        env = {}
        for key in (
            "FILESHARE_TEST",
            "STATIC_SERVER",
            "BUILTIN_TUNNEL",
            "FFL_TUNNEL_DOMAIN",
            "ONLY_BUILTIN_TUNNEL",
            "TUNNEL_TOKEN_SERVER_URL",
        ):
            value = os.getenv(key)
            if value:
                env[key] = value
        return env

    def _runBrowserLargeDownload(self, shareUrl, extraQueryParams=None):
        driver, downloadDir = self._setupBrowserAndDir()
        self._currentDriver = driver
        queryParams = dict(extraQueryParams or {})
        if self._directRunRouteOverride:
            queryParams.setdefault("route", self._directRunRouteOverride)
        self._applyRouteSpecificQueryParams(queryParams)
        finalUrl = self._addQueryParams(shareUrl, **queryParams) if queryParams else shareUrl
        self._printHTTPTransferEstimate(finalUrl, "browser download")
        evidence = self._createBrowserEvidence()
        downloadedFile = self._downloadWithBrowserTimeout(
            driver,
            finalUrl,
            downloadDir,
            self.expectedFilename,
            self.DOWNLOAD_TIMEOUT,
            evidence=evidence,
        )
        self._updateBrowserEvidence(driver, evidence)
        return downloadedFile, driver, evidence

    def _applyRouteSpecificQueryParams(self, queryParams):
        if self._getSelectedBrowserName() != "firefox":
            return

        if self._directRunRouteOverride != "pass":
            return

        # Firefox route=pass is intended to exercise the browser-owned/native
        # download path rather than the SW-transformed path.
        queryParams.setdefault("native", "true")

    def _shouldRequireResumeEvidence(self):
        return self.originalFileSize > self.USE_BLOB_THRESHOLD and self.STALL_AFTER_BYTES < self.originalFileSize

    def _shouldUseRequestsForUploadDownload(self):
        return self._getSelectedBrowserName() == "chrome" and self._isHeadlessEnabled()

    def _printHeadlessUploadWarning(self):
        print("[Test] WARNING: Large upload browser verification under Chrome headless is known to be unreliable.")
        print("[Test] WARNING: This is a Chrome headless limitation rather than a product download failure.")
        print("[Test] WARNING: Falling back to direct requests download verification for the upload scenario.")

    def _assertUploadCredentialAvailable(self):
        credentialPath = None
        if self._testConfigDir:
            credentialPath = os.path.join(self._testConfigDir, ".credential")
            if os.path.exists(credentialPath):
                print(f"[Test] Upload credential available in test config: {credentialPath}")
                return

            print(
                "[Test] Upload scenario did not find a copied .credential in the test config; "
                "trying _provisionLocalTestServerCredential() fallback."
            )
            self._provisionLocalTestServerCredential()
            if os.path.exists(credentialPath):
                print(
                    "[Test] Upload credential provisioned via local test-server fixture fallback: "
                    f"{credentialPath}"
                )
                print(
                    "[Test] NOTE: This fallback relies on the shared test@nuwainfo.com fixture and "
                    "is intended for development/testing convenience."
                )
                return

        originalStorageDir = None
        try:
            originalStorageDir = StorageLocator.getInstance().storageDir
        except Exception:
            originalStorageDir = None

        message = (
            "Upload scenario requires a valid login credential, but no .credential file was found "
            f"in the test config{f' ({credentialPath})' if credentialPath else ''}."
        )
        if originalStorageDir:
            message += (
                f" Original storage location is: {originalStorageDir}. "
                "Please run `ffl login` (or place a valid .credential there) before running the upload scenario."
            )
        else:
            message += " Please run `ffl login` before running the upload scenario."

        raise AssertionError(message)

    def testLargeHttpRequestDownload(self):
        """Large-file direct HTTP verification using requests without browser involvement."""
        try:
            shareLink, outputCapture = self._startLargeShare(p2p=True)

            outputPath = os.path.join(self._getLargeDownloadRoot(), f"{self._testMethodName}_{self.expectedFilename}")
            downloadedFile = self._downloadWithRequests(
                shareLink,
                outputPath,
                self.DOWNLOAD_TIMEOUT
            )

            self._verifyLargeDownloadedFile(downloadedFile)
            self._printServerOutput(outputCapture, lastNLines=80)
        finally:
            self._terminateProcess()

    def testLargeBrowserDownloadHttpOnly(self):
        """Large-file browser download forced to pure HTTP path via ?webrtc=0."""
        try:
            shareLink, outputCapture = self._startLargeShare(p2p=True)
            downloadedFile, driver, evidence = self._runBrowserLargeDownload(
                shareLink,
                extraQueryParams={"debug": 1, "webrtc": 0}
            )
            observedUrls = sorted(evidence["observedUrls"])
            offerUrls = [url for url in observedUrls if "/offer" in url]
            downloadUrls = [url for url in observedUrls if "/download" in url]
            observedServerPaths = self._getObservedServerRequestPaths(outputCapture)
            offerObserved = bool(offerUrls) or "/offer" in observedServerPaths
            downloadObserved = bool(downloadUrls) or "/download" in observedServerPaths

            self.assertFalse(
                offerObserved,
                (
                    "Expected no WebRTC /offer request for pure HTTP browser path, "
                    f"browser-observed URLs: {offerUrls}, server-observed paths: {sorted(observedServerPaths)}"
                )
            )
            self.assertTrue(
                downloadObserved,
                (
                    "Expected HTTP /download request for pure HTTP browser path, "
                    f"browser-observed URLs: {observedUrls}, server-observed paths: {sorted(observedServerPaths)}"
                )
            )

            self._verifyLargeDownloadedFile(downloadedFile)
            self._printServerOutput(outputCapture, lastNLines=80)
        finally:
            self._terminateProcess()

    def testLargeBrowserDownloadNormal(self):
        """Large-file browser download with no extra URL parameters (default behavior)."""
        try:
            shareLink, outputCapture = self._startLargeShare(p2p=True)
            downloadedFile, driver, evidence = self._runBrowserLargeDownload(shareLink)

            self._verifyLargeDownloadedFile(downloadedFile)
            self._printServerOutput(outputCapture, lastNLines=80)
        finally:
            self._terminateProcess()

    def testLargeBrowserDownloadWebRTCOnly(self):
        """Large-file P2P browser download with browser-side HTTP fallback disabled."""
        try:
            shareLink, outputCapture = self._startLargeShare(p2p=True)
            downloadedFile, driver, evidence = self._runBrowserLargeDownload(
                self._withBrowserFallbackDisabled(shareLink)
            )

            serverOutput = self._updateCapturedOutput(outputCapture)
            self.assertIn("P2P", serverOutput, "Expected P2P marker in sharer output for pure WebRTC scenario")
            self._verifyLargeDownloadedFile(downloadedFile)
        finally:
            self._terminateProcess()

    def testLargeBrowserDownloadAfterWebRTCDisconnect(self):
        """Large-file browser download after simulated WebRTC disconnect, resuming through HTTP relay."""
        try:
            shareLink, outputCapture = self._startLargeShare(p2p=True)
            downloadedFile, driver, evidence = self._runBrowserLargeDownload(
                shareLink,
                extraQueryParams={
                    "debug": 1,
                    "simulate-stall": "true",
                    "stall-after": self.STALL_AFTER_BYTES,
                    "fallback-ms": self.FALLBACK_TIMEOUT_MS,
                }
            )

            observedUrls = sorted(evidence["observedUrls"])
            analysis = self._analysisFromEvidence(evidence)
            resumeUrls = self._getResumeEvidenceUrls(observedUrls)
            self._printDiagnosticSummary(analysis)
            if resumeUrls:
                print(f"[Test] Resume-related download URLs observed: {resumeUrls}")

            self.assertTrue(analysis["fallbackDetected"], "Expected browser logs to show HTTP fallback")
            if self._shouldRequireResumeEvidence():
                self.assertTrue(
                    analysis["baseBytes"] > 0 or analysis["resumeDetected"] or bool(resumeUrls),
                    (
                        "Expected either browser resume logs, explicit resume_* query parameters, or "
                        "automatic writer-resume request evidence in the observed HTTP download traffic "
                        "after simulated WebRTC disconnect"
                    )
                )
            else:
                print(
                    "[Test] Resume evidence not required for this small-file smoke run; "
                    "download completion after fallback is sufficient."
                )

            self._verifyLargeDownloadedFile(downloadedFile)
            self._printServerOutput(outputCapture, lastNLines=80)
        finally:
            self._terminateProcess()

    def testLargeUploadAndBrowserDownload(self):
        """Large-file upload-mode share followed by browser download."""
        try:
            self._assertUploadCredentialAvailable()
            shareLink, outputCapture = self._startLargeShare(p2p=False)
            if self._shouldUseRequestsForUploadDownload():
                self._printHeadlessUploadWarning()
                outputPath = os.path.join(self._getLargeDownloadRoot(), f"{self._testMethodName}_{self.expectedFilename}")
                downloadedFile = self._downloadWithRequests(
                    shareLink,
                    outputPath,
                    self.DOWNLOAD_TIMEOUT
                )
            else:
                downloadedFile, driver, evidence = self._runBrowserLargeDownload(shareLink)

            self._verifyLargeDownloadedFile(downloadedFile)
            self._printServerOutput(outputCapture, lastNLines=80)
        finally:
            self._terminateProcess()


SCENARIO_TO_TEST = {
    "http-request": "testLargeHttpRequestDownload",
    "http-browser": "testLargeBrowserDownloadHttpOnly",
    "normal": "testLargeBrowserDownloadNormal",
    "webrtc": "testLargeBrowserDownloadWebRTCOnly",
    "fallback": "testLargeBrowserDownloadAfterWebRTCDisconnect",
    "upload": "testLargeUploadAndBrowserDownload",
}
TEST_TO_SCENARIO = {testName: scenarioName for scenarioName, testName in SCENARIO_TO_TEST.items()}


def buildArgumentParser():
    parser = argparse.ArgumentParser(description="Run manual large-file FastFileLink scenarios.")
    parser.add_argument(
        "--scenario",
        choices=[*SCENARIO_TO_TEST.keys(), "all"],
        nargs="+",
        default=["all"],
        help="Scenario(s) to run. Default: all",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run the curated full matrix with distinct scenario/browser/route coverage.",
    )
    parser.add_argument("--binary", help="External share command prefix, e.g. ./ffl.com or 'python Core.py --cli'")
    parser.add_argument("--size", help="Override FFL_LARGE_FILE_SIZE, e.g. 20M, 100G")
    parser.add_argument(
        "--browser",
        choices=[*BROWSER_CHOICES, "all"],
        nargs="+",
        help="Browser(s) for browser-driven scenarios. Supports 'all'. Default: current environment browser.",
    )
    parser.add_argument(
        "--route",
        choices=[*ROUTE_CHOICES, "all"],
        nargs="+",
        help="Route profile(s) for browser-driven scenarios. Supports 'all'. Default: auto.",
    )
    parser.add_argument("--file", dest="filePath", help="Override FFL_LARGE_FILE_PATH")
    parser.add_argument("--download-dir", dest="downloadDir", help="Override FFL_LARGE_FILE_DOWNLOAD_DIR")
    parser.add_argument("--tunnel", help="Override BUILTIN_TUNNEL and FFL_TUNNEL_DOMAIN")
    parser.add_argument(
        "--net-scope",
        choices=["share", "browser", "both", "host"],
        help="Linux network emulation scope: 'share' isolates only the sharer, 'browser' isolates only the browser, 'both' isolates both ends, 'host' applies tc to the whole host interface.",
    )
    parser.add_argument("--net-interface", help="Linux network interface to shape via tc/netem, e.g. eth0")
    parser.add_argument("--net-delay", help="Linux tc netem delay, e.g. 120ms")
    parser.add_argument("--net-jitter", help="Linux tc netem jitter, e.g. 30ms (requires --net-delay)")
    parser.add_argument("--net-loss", help="Linux tc netem loss, e.g. 2%%")
    parser.add_argument("--net-rate", help="Linux tc tbf rate, e.g. 500kbit or 2mbit")
    parser.add_argument("--net-burst", help="Linux tc tbf burst, e.g. 32kbit (requires --net-rate)")
    parser.add_argument("--net-latency", help="Linux tc tbf latency, e.g. 400ms (requires --net-rate)")
    return parser


def hasHelpfulBaselineEnv():
    baselineKeys = (
        "FILESHARE_TEST",
        "STATIC_SERVER",
        "FFL_LARGE_FILE_PATH",
        "FFL_LARGE_FILE_SIZE",
    )
    return any(os.getenv(key) for key in baselineKeys)


def printDirectRunExamples():
    examples = [
        (
            "Local JS + old tunnel quick smoke",
            [
                "$env:FILESHARE_TEST='True'",
                "$env:STATIC_SERVER='http://localhost:8000'",
                "$env:FFL_LARGE_FILE_DOWNLOAD_DIR='D:\\LargeFileTest\\downloads'",
                "python tests/LargeFileTest.py --scenario http-request --size 20M --tunnel 33.fastfilelink.com",
            ],
        ),
        (
            "HTTP browser smoke with local JS",
            [
                "$env:FILESHARE_TEST='True'",
                "$env:STATIC_SERVER='http://localhost:8000'",
                "$env:FFL_LARGE_FILE_DOWNLOAD_DIR='D:\\LargeFileTest\\downloads'",
                "python tests/LargeFileTest.py --scenario http-browser --size 20M --tunnel 33.fastfilelink.com",
            ],
        ),
        (
            "Fallback/resume smoke with local JS",
            [
                "$env:FILESHARE_TEST='True'",
                "$env:STATIC_SERVER='http://localhost:8000'",
                "$env:FFL_LARGE_FILE_STALL_AFTER='96M'",
                "$env:FFL_LARGE_FILE_FALLBACK_MS='2000'",
                "python tests/LargeFileTest.py --scenario fallback --size 100M --tunnel 33.fastfilelink.com",
            ],
        ),
        (
            "Linux slow-network simulation with tc/netem",
            [
                "export FILESHARE_TEST=True",
                "export STATIC_SERVER=http://localhost:8000",
                "python tests/LargeFileTest.py --scenario normal --browser firefox --route sw --size 40M --tunnel 33.fastfilelink.com --net-scope share --net-rate 500kbit --net-delay 120ms --net-jitter 30ms",
            ],
        ),
        (
            "Upload smoke using external artifact",
            [
                "$env:FILESHARE_TEST='True'",
                "$env:STATIC_SERVER='http://localhost:8000'",
                "python tests/LargeFileTest.py --scenario upload --size 20M --tunnel 33.fastfilelink.com --binary \"C:\\Users\\Naga\\miniconda3\\envs\\fileshare\\python.exe Core.py --cli\"",
            ],
        ),
    ]

    print("LargeFileTest needs environment setup before direct execution.")
    print("")
    print("Copy/paste examples (PowerShell):")
    print("")
    for title, commands in examples:
        print(f"# {title}")
        for command in commands:
            print(command)
        print("")


def applyDirectRunArgs(args):
    os.environ["FFL_ENABLE_LARGE_FILE_TESTS"] = "1"

    if args.binary:
        os.environ["FFL_LARGE_FILE_BINARY"] = args.binary
    if args.size:
        os.environ["FFL_LARGE_FILE_SIZE"] = args.size
    if args.filePath:
        os.environ["FFL_LARGE_FILE_PATH"] = args.filePath
    if args.downloadDir:
        os.environ["FFL_LARGE_FILE_DOWNLOAD_DIR"] = args.downloadDir
    if args.tunnel:
        os.environ["BUILTIN_TUNNEL"] = args.tunnel
        os.environ["FFL_TUNNEL_DOMAIN"] = args.tunnel
        os.environ["ONLY_BUILTIN_TUNNEL"] = "True"
    if args.net_scope:
        os.environ["FFL_LARGE_FILE_NET_SCOPE"] = args.net_scope
    if args.net_interface:
        os.environ["FFL_LARGE_FILE_NET_INTERFACE"] = args.net_interface
    if args.net_delay:
        os.environ["FFL_LARGE_FILE_NET_DELAY"] = args.net_delay
    if args.net_jitter:
        os.environ["FFL_LARGE_FILE_NET_JITTER"] = args.net_jitter
    if args.net_loss:
        os.environ["FFL_LARGE_FILE_NET_LOSS"] = args.net_loss
    if args.net_rate:
        os.environ["FFL_LARGE_FILE_NET_RATE"] = args.net_rate
    if args.net_burst:
        os.environ["FFL_LARGE_FILE_NET_BURST"] = args.net_burst
    if args.net_latency:
        os.environ["FFL_LARGE_FILE_NET_LATENCY"] = args.net_latency


def expandSelectedValues(selectedValues, availableValues):
    availableValues = list(availableValues)
    if not selectedValues or "all" in selectedValues:
        return availableValues

    deduplicated = []
    seen = set()
    for value in selectedValues:
        if value in seen:
            continue
        seen.add(value)
        deduplicated.append(value)
    return deduplicated


def resolveSelectedScenarios(args):
    if args.full:
        return list(SCENARIO_TO_TEST.keys())
    return expandSelectedValues(args.scenario, SCENARIO_TO_TEST.keys())


def resolveSelectedBrowsers(args):
    if args.full:
        return list(BROWSER_CHOICES)
    if args.browser:
        return expandSelectedValues(args.browser, BROWSER_CHOICES)
    return [LargeFileTest.DEFAULT_BROWSER]


def resolveSelectedRoutes(args):
    if args.full:
        return list(ROUTE_CHOICES)
    if args.route:
        return expandSelectedValues(args.route, ROUTE_CHOICES)
    return ["auto"]


def getCuratedFullScenarioVariants():
    scenarioVariants = []
    for scenario, variants in CURATED_FULL_MATRIX.items():
        for browserOverride, routeOverride in variants:
            scenarioVariants.append((scenario, browserOverride, routeOverride))
    return scenarioVariants


def createScenarioTestCase(scenario, browserOverride=None, routeOverride=None):
    testCase = LargeFileTest(SCENARIO_TO_TEST[scenario])
    testCase._directRunBrowserOverride = browserOverride
    testCase._directRunRouteOverride = routeOverride
    return testCase


def validateDirectRunNetworkEmulation():
    config = NetworkEmulationConfig.fromEnvironment()
    if not config.isEnabled():
        return None

    controllers = createNetworkControllers(config)
    for controller in controllers:
        controller.ensureSupported()
    return controllers


def runSelectedScenarios(args):
    applyDirectRunArgs(args)
    LargeFileTest.configureFromEnvironment()
    try:
        validateDirectRunNetworkEmulation()
    except RuntimeError as exc:
        print(f"[Test] Network emulation is not available: {exc}")
        return 2
    except ValueError as exc:
        print(f"[Test] Invalid network emulation settings: {exc}")
        return 2

    suite = unittest.TestSuite()
    if args.full:
        selectedScenarioSet = set(resolveSelectedScenarios(args))
        selectedExecutions = [
            (scenario, browserOverride, routeOverride)
            for scenario, browserOverride, routeOverride in getCuratedFullScenarioVariants()
            if scenario in selectedScenarioSet
        ]
    else:
        requestedScenarios = resolveSelectedScenarios(args)
        requestedBrowsers = resolveSelectedBrowsers(args)
        requestedRoutes = resolveSelectedRoutes(args)
        selectedExecutions = []

        for scenario in requestedScenarios:
            if scenario not in BROWSER_DRIVEN_SCENARIOS:
                selectedExecutions.append((scenario, None, None))
                continue

            for browserName in requestedBrowsers:
                for routeName in requestedRoutes:
                    selectedExecutions.append((scenario, browserName, routeName))

    for scenario, browserOverride, routeOverride in selectedExecutions:
        suite.addTest(
            createScenarioTestCase(
                scenario,
                browserOverride=browserOverride,
                routeOverride=routeOverride,
            )
        )

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if len(sys.argv) == 1 and not hasHelpfulBaselineEnv():
        printDirectRunExamples()
        sys.exit(0)

    sys.exit(runSelectedScenarios(buildArgumentParser().parse_args()))
