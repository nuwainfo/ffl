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
    'API',       # API integration
    'Features',  # User features and registration
    'Upload',    # Core upload functionality
    'Tunnels',   # Network tunneling capabilities
    'GUI'        # GUI interface - loaded last as it may depend on other addons
]

# I18n support for addons domain
# All addon modules can import these directly: from addons import _, ngettext
from functools import partial
from bases.I18n import _ as _base, ngettext as ngettext_base

_ = partial(_base, domain='addons')
ngettext = partial(ngettext_base, domain='addons')
