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

import io
import os
import shutil
import tempfile
import unittest
from typing import BinaryIO, Dict, Iterable, List, Set, Tuple

from bases.FileSystems import FileSystem, LocalFileSystem, Stat, VirtualFileSystem


# ---------------------------------------------------------------------------
# InMemoryFileSystem — test helper only, not the subject under test
# ---------------------------------------------------------------------------

class InMemoryFileSystem(FileSystem):
    """
    Pure in-memory FileSystem.  All paths are POSIX absolute strings.
    Parent directories are created automatically by addFile / addDir.
    """

    def __init__(self, rootPath: str = "/root"):
        self._rootPath = self._norm(rootPath)
        self._files: Dict[str, bytes] = {}
        self._dirs: Set[str] = {self._rootPath}

    def addFile(self, path: str, content: bytes = b"") -> None:
        path = self._norm(path)
        self._files[path] = content
        self._ensureParents(path)

    def addDir(self, path: str) -> None:
        path = self._norm(path)
        self._dirs.add(path)
        self._ensureParents(path)

    def _norm(self, path: str) -> str:
        path = (path or "/").strip()
        if not path.startswith("/"):
            path = "/" + path
        segments = [s for s in path.split("/") if s]
        return "/" + "/".join(segments) if segments else "/"

    def _parent(self, path: str) -> str:
        path = self._norm(path)
        if path == "/":
            return ""
        parent = "/".join(path.split("/")[:-1])
        return parent or "/"

    def _ensureParents(self, path: str) -> None:
        parent = self._parent(path)
        while parent and parent not in self._dirs:
            self._dirs.add(parent)
            parent = self._parent(parent)

    def _directChildren(self, dirPath: str) -> Tuple[List[str], List[str]]:
        prefix = dirPath.rstrip("/") + "/"
        childDirs  = sorted(d.split("/")[-1] for d in self._dirs  if d != dirPath and d.startswith(prefix) and "/" not in d[len(prefix):])
        childFiles = sorted(f.split("/")[-1] for f in self._files if f.startswith(prefix) and "/" not in f[len(prefix):])
        return childDirs, childFiles

    def rootName(self) -> str:
        return self._rootPath.rstrip("/").split("/")[-1] or "root"

    @property
    def rootPath(self) -> str:
        return self._rootPath

    @property
    def rootIsDir(self) -> bool:
        return True

    def walk(self, top: str) -> Iterable[Tuple[str, List[str], List[str]]]:
        top = self._norm(top)
        if top not in self._dirs:
            return
        dirNames, fileNames = self._directChildren(top)
        yield (top, dirNames, fileNames)
        for name in dirNames:
            yield from self.walk(self.joinPath(top, name))

    def stat(self, path: str) -> Stat:
        path = self._norm(path)
        if path in self._dirs:
            return Stat(size=0, mtime=0.0, isDir=True)
        if path in self._files:
            return Stat(size=len(self._files[path]), mtime=0.0, isDir=False)
        raise FileNotFoundError(path)

    def open(self, path: str) -> BinaryIO:
        path = self._norm(path)
        if path not in self._files:
            raise FileNotFoundError(path)
        return io.BytesIO(self._files[path])

    def exists(self, path: str) -> bool:
        path = self._norm(path)
        return path in self._dirs or path in self._files

    def isFile(self, path: str) -> bool:
        return self._norm(path) in self._files

    def isDir(self, path: str) -> bool:
        return self._norm(path) in self._dirs

    def getSize(self, path: str) -> int:
        path = self._norm(path)
        if path not in self._files:
            raise FileNotFoundError(path)
        return len(self._files[path])

    def joinPath(self, parent: str, name: str) -> str:
        return self._norm(parent).rstrip("/") + "/" + name

    def relPath(self, path: str, base: str) -> str:
        path = self._norm(path)
        base = self._norm(base).rstrip("/")
        if path == base:
            return ""
        prefix = base + "/"
        if path.startswith(prefix):
            return path[len(prefix):]
        return path.lstrip("/")

    def normPath(self, path: str) -> str:
        return self._norm(path)

    def baseName(self, path: str) -> str:
        return self._norm(path).rstrip("/").split("/")[-1]

    def dirName(self, path: str) -> str:
        path = self._norm(path).rstrip("/")
        if "/" not in path or path == "/":
            return "/"
        return "/".join(path.split("/")[:-1]) or "/"


# ---------------------------------------------------------------------------
# VirtualFileSystemTest — comprehensive, InMemoryFileSystem backing
# ---------------------------------------------------------------------------

class VirtualFileSystemTest(unittest.TestCase):
    """
    Comprehensive VirtualFileSystem tests using InMemoryFileSystem as backing.

    In-memory layout:
        /store/
            alpha.txt            b"alpha"
            beta.bin             b"\\xff" * 4
            subdir/
                gamma.txt        b"gamma"
                deep/
                    delta.txt    b"delta"

    VirtualFileSystem top-level entries: alpha.txt, beta.bin, subdir
    Plus two extra files named "report.txt" for duplicate-basename tests.
    """

    def setUp(self):
        self.mem = InMemoryFileSystem("/store")
        self.mem.addFile("/store/alpha.txt",           b"alpha")
        self.mem.addFile("/store/beta.bin",            b"\xff" * 4)
        self.mem.addDir("/store/subdir")
        self.mem.addFile("/store/subdir/gamma.txt",    b"gamma")
        self.mem.addDir("/store/subdir/deep")
        self.mem.addFile("/store/subdir/deep/delta.txt", b"delta")

        # Two extra dirs for duplicate-basename tests
        self.mem.addFile("/store/dir_a/report.txt",   b"report a")
        self.mem.addFile("/store/dir_b/report.txt",   b"report b")

        self.vfs = VirtualFileSystem(
            filePaths=["/store/alpha.txt", "/store/beta.bin", "/store/subdir"],
            rootName="pkg",
            backingFS=self.mem,
        )

    # --- root properties ---

    def testRootProperties(self):
        self.assertEqual(self.vfs.rootName(), "pkg")
        self.assertEqual(self.vfs.rootPath, "/pkg")
        self.assertTrue(self.vfs.rootIsDir)

    # --- walk structure ---

    def testWalkRootLevel(self):
        rootPath, rootDirs, rootFiles = next(iter(self.vfs.walk("/pkg")))
        self.assertEqual(rootPath, "/pkg")
        self.assertEqual(rootDirs, ["subdir"])
        self.assertEqual(sorted(rootFiles), ["alpha.txt", "beta.bin"])

    def testWalkIncludesAllNestedLevels(self):
        allPaths = [e[0] for e in self.vfs.walk("/pkg")]
        self.assertIn("/pkg",             allPaths)
        self.assertIn("/pkg/subdir",      allPaths)
        self.assertIn("/pkg/subdir/deep", allPaths)

    def testWalkNestedContents(self):
        entries = {e[0]: e for e in self.vfs.walk("/pkg")}
        self.assertEqual(entries["/pkg/subdir"][2],      ["gamma.txt"])
        self.assertEqual(entries["/pkg/subdir/deep"][2], ["delta.txt"])

    def testWalkIgnoresNonRootTop(self):
        self.assertEqual(list(self.vfs.walk("/other")), [])

    # --- existence and type ---

    def testRootIsDir(self):
        self.assertTrue(self.vfs.isDir("/pkg"))
        self.assertFalse(self.vfs.isFile("/pkg"))

    def testTopLevelFileIsFile(self):
        self.assertTrue(self.vfs.isFile("/pkg/alpha.txt"))
        self.assertFalse(self.vfs.isDir("/pkg/alpha.txt"))

    def testDirEntryIsDir(self):
        self.assertTrue(self.vfs.isDir("/pkg/subdir"))
        self.assertFalse(self.vfs.isFile("/pkg/subdir"))

    def testMissingPathDoesNotExist(self):
        self.assertFalse(self.vfs.exists("/pkg/ghost.txt"))
        with self.assertRaises(FileNotFoundError):
            self.vfs.stat("/pkg/ghost.txt")
        with self.assertRaises(FileNotFoundError):
            self.vfs.open("/pkg/ghost.txt")

    # --- stat / open / getSize at all levels ---

    def testTopLevelFile(self):
        self.assertEqual(self.vfs.stat("/pkg/alpha.txt").size, 5)
        with self.vfs.open("/pkg/alpha.txt") as f:
            self.assertEqual(f.read(), b"alpha")
        self.assertEqual(self.vfs.getSize("/pkg/alpha.txt"), 5)

    def testNestedFile(self):
        self.assertEqual(self.vfs.stat("/pkg/subdir/gamma.txt").size, 5)
        with self.vfs.open("/pkg/subdir/gamma.txt") as f:
            self.assertEqual(f.read(), b"gamma")

    def testDeeplyNestedFile(self):
        with self.vfs.open("/pkg/subdir/deep/delta.txt") as f:
            self.assertEqual(f.read(), b"delta")

    # --- duplicate basename resolution ---

    def testDuplicateBasenames(self):
        dupVfs = VirtualFileSystem(
            filePaths=["/store/dir_a/report.txt", "/store/dir_b/report.txt"],
            rootName="archive",
            backingFS=self.mem,
        )
        dirPath, dirNames, fileNames = next(iter(dupVfs.walk("/archive")))
        self.assertIn("report.txt",   fileNames)
        self.assertIn("report_1.txt", fileNames)

        with dupVfs.open("/archive/report.txt") as f:
            self.assertEqual(f.read(), b"report a")
        with dupVfs.open("/archive/report_1.txt") as f:
            self.assertEqual(f.read(), b"report b")

    # --- path operations ---

    def testPathOps(self):
        self.assertEqual(self.vfs.joinPath("/pkg", "x.txt"),        "/pkg/x.txt")
        self.assertEqual(self.vfs.relPath("/pkg/alpha.txt", "/pkg"), "alpha.txt")
        self.assertEqual(self.vfs.relPath("/pkg", "/pkg"),           "")
        self.assertEqual(self.vfs.baseName("/pkg/alpha.txt"),        "alpha.txt")
        self.assertEqual(self.vfs.dirName("/pkg/alpha.txt"),         "/pkg")

        for variant in ("", ".", "/", "pkg", "/pkg"):
            self.assertEqual(self.vfs.normPath(variant), "/pkg", f"normPath({variant!r})")


# ---------------------------------------------------------------------------
# VirtualFileSystemLocalFSTest — smoke test with default LocalFileSystem
# ---------------------------------------------------------------------------

class VirtualFileSystemLocalFSTest(unittest.TestCase):
    """
    Confirms that the default LocalFileSystem backing reaches real disk.
    VirtualFileSystem logic is already proven in VirtualFileSystemTest above,
    so only a minimal end-to-end check is needed here.
    """

    def setUp(self):
        self.tempDir = tempfile.mkdtemp()
        self.file1 = os.path.join(self.tempDir, "one.txt")
        self.subDir = os.path.join(self.tempDir, "sub")
        self.file2  = os.path.join(self.subDir,  "two.txt")
        os.makedirs(self.subDir)
        with open(self.file1, "wb") as f:
            f.write(b"one")
        with open(self.file2, "wb") as f:
            f.write(b"two")

    def tearDown(self):
        shutil.rmtree(self.tempDir, ignore_errors=True)

    def testDefaultBackingReadsDiskFiles(self):
        """Walk + open with no backingFS argument → LocalFileSystem reads real disk."""
        vfs = VirtualFileSystem([self.file1, self.subDir])

        allPaths = [e[0] for e in vfs.walk(vfs.rootPath)]
        self.assertIn("/archive",     allPaths)
        self.assertIn("/archive/sub", allPaths)

        with vfs.open("/archive/one.txt") as f:
            self.assertEqual(f.read(), b"one")
        with vfs.open("/archive/sub/two.txt") as f:
            self.assertEqual(f.read(), b"two")


if __name__ == "__main__":
    unittest.main()
