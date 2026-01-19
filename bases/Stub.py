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

# A universal “black hole” stub module that silently absorbs **all** attribute, item,
# call and await operations, while automatically replacing a heavy‑weight package
# (e.g. `av`) at import time.
#
# Key features
# ------------
# * **Automatic logging** – if the environment variable `STUB_LOG_FILE` is set,
#   every stubbed symbol or sub‑module that gets accessed is appended (once) to
#   the file path provided in that variable. This makes it trivial to discover
#   which parts of the original library were actually touched at run‑time.
#
# By default the module replaces `av`. Pass a different name to
# `installAs` if you need to stub something else.

from __future__ import annotations

import os
import sys
import types
import logging
import importlib.abc as _abc
import importlib.machinery as _machinery

from typing import Set, Optional

# ---------------------------------------------------------------------------
# Internal logging helpers
# ---------------------------------------------------------------------------
LOG_ENV_VAR: str = "STUB_LOG_FILE"
_loggedItems: Set[str] = set()


def _logAccess(itemName: str) -> None:
    logPath: Optional[str] = os.getenv(LOG_ENV_VAR)
    if logPath and itemName not in _loggedItems:
        try:
            with open(logPath, "a", encoding="utf-8") as fp:
                fp.write(itemName + "\n")
            _loggedItems.add(itemName)
        except OSError as e:
            # Fail silently – logging must never crash the program.
            logger = logging.getLogger(__name__)
            logger.debug(f"Failed to log access for {itemName}: {e}")


# ---------------------------------------------------------------------------
# The Black‑Hole module object
# ---------------------------------------------------------------------------
class BlackHole(types.ModuleType):

    # Attribute access -------------------------------------------------------
    def __getattr__(self, name: str): # noqa: D401 – short description OK
        fullName: str = f"{self.__name__}.{name}"
        _logAccess(fullName)
        # Re‑use existing stub or create a new one lazily.
        return sys.modules.setdefault(fullName, BlackHole(fullName))

    # Call, item access, assignment, iteration ------------------------------
    __call__ = lambda self, *a, **kw: self # type: ignore[assignment]
    __getitem__ = lambda self, key: self # type: ignore[assignment]
    __iter__ = lambda self: iter(()) # type: ignore[assignment]

    def __setitem__(self, key, value): # noqa: D401 – imperative mood
        # Silently ignore item assignment.
        pass

    def __setattr__(self, name: str, value): # noqa: D401 – imperative mood
        # Preserve dunder attributes; swallow everything else.
        if name.startswith("__"):
            super().__setattr__(name, value)
        else:
            # Regular attributes become no‑ops.
            pass

    # Awaitable support ------------------------------------------------------
    async def _asyncNoop(self): # noqa: D401 – imperative mood
        return self

    def __await__(self):
        return self._asyncNoop().__await__()

    # Debug representation ---------------------------------------------------
    def __repr__(self): # noqa: D401 – imperative mood
        return f"<StubModule {self.__name__}>"


# ---------------------------------------------------------------------------
# Finder & loader that supply BlackHole for *all* sub‑modules
# ---------------------------------------------------------------------------
class BlackHoleFinder(_abc.MetaPathFinder, _abc.Loader):

    def __init__(self, rootPackage: str):
        self.rootPackage = rootPackage

    # MetaPathFinder ---------------------------------------------------------
    def find_spec(self, fullname: str, path, target=None): # noqa: D401
        if fullname == self.rootPackage or fullname.startswith(self.rootPackage + "."):
            return _machinery.ModuleSpec(fullname, self)
        return None

    # Loader -----------------------------------------------------------------
    def create_module(self, spec): # noqa: D401 – imperative mood
        _logAccess(spec.name) # Every import counts as a stub access.
        return sys.modules.setdefault(spec.name, BlackHole(spec.name))

    def exec_module(self, module): # noqa: D401 – imperative mood
        # Nothing to execute – module is already a stub.
        pass


# ---------------------------------------------------------------------------
# Public installation helper
# ---------------------------------------------------------------------------


def installAs(targetName: str = "av") -> None: # noqa: D401 – imperative mood

    rootStub = BlackHole(targetName)
    rootStub.__path__ = [] # Make import machinery treat it as a package.
    sys.modules[targetName] = rootStub

    # Ensure our finder is first so we win the import race.
    sys.meta_path.insert(0, BlackHoleFinder(targetName))

    # Optional: allow "import stub" to yield the same object so users can test
    # it directly without touching ``sys.modules`` again.
    sys.modules.setdefault(__name__, rootStub)


class IsolationRef:
    """
    A isolation reference to any object (module, class...etc.)
    You can get attribute from it just like original object, but every
    modification is isolated in this reference (do not affect original object).
    For example:
        iwx = IsolationRef(wx)
        iwx.MessageBox          # OK.
        iwx.MessageBox = lambda: *args, **kws: None   # OK, but wx.MessageBox
                                                      # doesn't change.
        iwx.MessageBox(None, 'caption', 'message', 0) # Pass.
    """

    def __init__(self, target):
        """
        Constructor.

        @param target The reference target.
        """
        object.__setattr__(self, '_IsolationRef__target', target)
        object.__setattr__(self, '_IsolationRef__cache', {})

    def __getattribute__(self, name):
        c = object.__getattribute__(self, '_IsolationRef__cache')
        if name in c:
            return c[name]
        else:
            v = getattr(object.__getattribute__(self, '_IsolationRef__target'), name)
            c[name] = v
            return v

    def __setattr__(self, name, value):
        c = object.__getattribute__(self, '_IsolationRef__cache')
        if name in c:
            c[name] = value
        else:
            # Get into cache.
            getattr(self, name)
            c[name] = value


# ---------------------------------------------------------------------------
# Auto install for the common case (stubbing ``av``).
# ---------------------------------------------------------------------------
installAs("av")

import platform

if 'Cosmopolitan' in platform.version():
    BASE_DIR = os.path.dirname(os.path.dirname(__file__))
    lib = os.path.join(BASE_DIR, 'Lib', 'site-packages')
    if os.path.exists(lib) and lib not in sys.path:
        sys.path.insert(0, lib)
        sys.path.insert(0, os.path.dirname(lib))

    del sys.modules['sitecustomize']
    import sitecustomize # pylint: disable=import-error  # Reimport sitecustomize to apply cosmos patches.

    installAs("ifaddr")

    import _ifaddr_c # pylint: disable=import-error
    from aioice import ice
    ice.ifaddr = _ifaddr_c

    if platform.system() == "Windows":
        from aioice import mdns

        mdns.sys = IsolationRef(sys)
        mdns.sys.platform = 'win32'

    installAs("google_crc32c")

    from aiortc import rtcsctptransport
    from crc32c import crc32c # pylint: disable=import-error

    rtcsctptransport.crc32c = crc32c
