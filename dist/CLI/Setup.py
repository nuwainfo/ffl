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

# pylint: disable=E0015,E0013

import os
import sys

from setuptools import find_packages, setup

# base directory of this setup.py
baseDir = os.path.abspath(os.path.dirname(__file__))

# append FileShare folder to sys.path
fileShareDir = os.path.join(baseDir, "FileShare")
if fileShareDir not in sys.path:
    sys.path.append(fileShareDir)

from bases.Kernel import PUBLIC_VERSION # isort:skip

# safely define setup
setup(
    name="ffl",
    version=PUBLIC_VERSION,
    packages=find_packages(),
    package_data={
        "FileShare": ["static/**/*"],
    },
    entry_points={
        "console_scripts": ["ffl=FileShare.Core:main"],
    },
    include_package_data=True,
)
