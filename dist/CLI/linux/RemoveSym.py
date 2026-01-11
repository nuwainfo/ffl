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
import shutil
import sys


def resolveSymlink(path):
    """如果 path 是 symlink，就解開成實體檔案/資料夾"""
    if not os.path.islink(path):
        return

    target = os.readlink(path)  # 讀出 symlink 指向的路徑（可能是相對的）
    absTarget = os.path.realpath(os.path.join(os.path.dirname(path), target))

    print(f"{path} -> {target}")

    # 刪掉舊的 symlink
    os.unlink(path)

    if not os.path.exists(absTarget):
        print(f"⚠️ target not found: {absTarget}")
        return

    try:
        if os.path.isfile(absTarget):
            # 如果目標是檔案，就複製檔案
            shutil.copy2(absTarget, path)
            print(f"copied file {absTarget} to {path}")
        elif os.path.isdir(absTarget):
            # 如果目標是資料夾，就整個複製
            shutil.copytree(absTarget, path, symlinks=False)
            print(f"copied dir {absTarget} to {path}")
    except Exception as e:
        print(f"failed to replace {path} with {absTarget}: {e}")


def walkAndFix(rootDir):
    """遞迴處理整個資料夾"""
    for currentRoot, dirs, files in os.walk(rootDir, topdown=True):
        # 注意：這裡 dirs 可能本身包含 symlink
        # 先處理目錄 symlink
        for d in dirs[:]:  # 複製一份，因為要改 dirs
            dirPath = os.path.join(currentRoot, d)
            if os.path.islink(dirPath):
                resolveSymlink(dirPath)
                # 處理完後，把它從 dirs 移掉，避免 os.walk 再往裡走
                dirs.remove(d)

        # 處理檔案 symlink
        for f in files:
            filePath = os.path.join(currentRoot, f)
            if os.path.islink(filePath):
                resolveSymlink(filePath)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python RemoveSym.py <target_dir>")
        sys.exit(1)

    targetDir = sys.argv[1]
    walkAndFix(targetDir)
