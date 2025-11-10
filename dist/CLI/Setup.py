#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=E0015,E0013
# $Id: Setup.py 17197 2025-09-01 13:35:33Z Leona $
#
# Copyright (c) 2025 Nuwa Information Co., Ltd, All Rights Reserved.
#
# Licensed under the Proprietary License,
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at our web site.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# $Author: Leona $
# $Date: 2025-09-01 21:35:33 +0800 (週一, 01 九月 2025) $
# $Revision: 17197 $

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
