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

# Addons configuration and loading order

# List of enabled addons in loading order
# Addons will be loaded in this exact order by the AddonsManager
# Each addon may have an optional load() function that will be called during initialization
addons = [
    'API', # API integration
    'Features', # User features and registration
    'Brand', # White-label brand customization
    'Upload', # Core upload functionality
    'Tunnels', # Network tunneling capabilities
    'ShellIntegration', # OS context menu (right-click) integration
    'GUI', # GUI interface - loaded last as it may depend on other addons
    'Preview', # ZIP file browsing and preview
]

# I18n support for addons domain
# All addon modules can import these directly: from addons import _, ngettext
from functools import partial
from bases.I18n import _ as _base, ngettext as ngettext_base

_ = partial(_base, domain='addons')
ngettext = partial(ngettext_base, domain='addons')


# Asset template rendering — shared Jinja2 utility for all addons
import os

from jinja2 import Environment, FileSystemLoader

from bases.Kernel import Singleton

class AddonAssetsLoader:
    """Template loader scoped to one addon's impl/assets/<AddonName>/ directory."""

    def __init__(self, addonName: str, env: Environment):
        self._addonName = addonName
        self._env = env

    def get(self, templateName: str):
        return self._env.get_template(f'{self._addonName.lower()}/{templateName}')


class AddonAssetsLoaderFactory(Singleton):
    """
    Singleton factory vending per-addon template loaders from one shared Jinja2 Environment.

    The Environment is rooted at impl/assets/; each loader prepends its addon name,
    so Brand.py calls assets.get('Brand.css') and the loader resolves 'Brand/Brand.css'.

    Usage (inside any addon module):
        assets = assetsLoaderFactory.get(__name__)
        css = assets.get('Brand.css').render(color='#ff0000')
    """

    def initialize(self):
        self._env = None
        self._loaders: dict = {}

    def _buildEnv(self) -> Environment:
        from bases.Settings import SettingsGetter

        baseDir = SettingsGetter.getInstance().baseDir
        
        if baseDir is None:
            baseDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
        assetsDir = os.path.join(baseDir, 'addons', 'impl', 'assets')
            
        return Environment(
            loader=FileSystemLoader(assetsDir),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

    def get(self, moduleName: str) -> AddonAssetsLoader:
        addonName = moduleName.rsplit('.', 1)[-1]
        if addonName not in self._loaders:
            if self._env is None:
                self._env = self._buildEnv()
                
            self._loaders[addonName] = AddonAssetsLoader(addonName, self._env)

        return self._loaders[addonName]


assetsLoaderFactory = AddonAssetsLoaderFactory()
