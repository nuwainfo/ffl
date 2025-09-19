#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

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
