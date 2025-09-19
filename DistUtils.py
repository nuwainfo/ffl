#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
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

import argparse
import base64
import logging
import os
import platform
import re
import shutil
import struct
import sys
import zlib

from pathlib import Path
from typing import Optional, Tuple

# Create logger for this module
logger = logging.getLogger(__name__)

from bases.Kernel import PUBLIC_VERSION

excludedPackages = ['numpy.libs', "av", "av.lib", 'mbedtls']
if sys.platform == 'win32':
    excludedPackages.append('lief')

hiddenImports = ['addons.auth.Cryptography']

featuresSupported = True

try:
    from addons.Features import FREE_SERIAL_NUMBER, PayloadProcessor, PayloadReader
except ImportError:
    featuresSupported = False
    PayloadWriter = None
    PayloadReader = None
    FREE_SERIAL_NUMBER = '0123456789'

if featuresSupported:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    class PayloadWriter(PayloadProcessor):
        """Handles embedding payloads into binary files"""

        def detectBinaryFormat(self, filePath: str) -> str:
            """Detect binary format (PE/ELF) from file signature"""
            with open(filePath, "rb") as f:
                signature = f.read(4)

            if signature.startswith(b"\x7fELF"):
                return "ELF"
            elif signature[:2] == b"MZ":
                return "PE"
            else:
                return f"UNKNOWN {signature=}"

        def deriveEncryptionKey(self, secret: str, salt: bytes) -> bytes:
            """Derive AES-256 key from password using PBKDF2-HMAC-SHA256"""
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.AES_KEY_SIZE,
                salt=salt,
                iterations=self.PBKDF2_ITERATIONS,
            )
            return kdf.derive(secret.encode("utf-8"))

        def encryptPayload(self, plaintext: bytes, secret: Optional[str]) -> Tuple[bytes, int, bytes, bytes]:
            """Encrypt payload if secret provided. Returns (data, flags, salt, nonce)"""
            flags = 0
            if secret:
                salt = os.urandom(self.SALT_SIZE)
                nonce = os.urandom(self.NONCE_SIZE)
                key = self.deriveEncryptionKey(secret, salt)
                ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
                flags |= self.FLAG_ENCRYPTED
                return ciphertext, flags, salt, nonce
            return plaintext, flags, b"", b""

        def createPayloadEnvelope(self, rawData: bytes, compress: bool, secret: Optional[str]) -> bytes:
            """Create complete payload envelope with header"""
            flags = 0
            processedData = rawData

            # Compress if requested
            if compress:
                processedData = zlib.compress(processedData)
                flags |= self.FLAG_COMPRESSED

            # Encrypt if secret provided
            encryptedData, encFlags, salt, nonce = self.encryptPayload(processedData, secret)
            flags |= encFlags

            # Build header
            header = struct.pack(
                self.HEADER_FORMAT, self.PAYLOAD_MAGIC, self.PAYLOAD_VERSION, flags, len(salt), len(nonce),
                len(encryptedData)
            )

            return header + salt + nonce + encryptedData

        def alignUp(self, value: int, alignment: int) -> int:
            """Align value up to alignment boundary"""
            return (value + (alignment - 1)) & ~(alignment - 1)

        def truncatePeSectionName(self, name: str) -> str:
            """Truncate section name to PE 8-byte limit"""
            nameBytes = name.encode("ascii", "ignore")
            if len(nameBytes) > 8:
                self.log(f"Section name '{name}' truncated to 8 bytes")
                nameBytes = nameBytes[:8]
            return nameBytes.decode("ascii", "ignore")

        def writePeSection(self, inputPath: str, outputPath: str, sectionName: str, content: bytes) -> None:
            """Add new section to PE file using pefile"""
            import pefile

            # Load and parse PE
            with open(inputPath, 'rb') as f:
                fileData = bytearray(f.read())

            pe = pefile.PE(data=bytes(fileData))

            # Calculate alignments and offsets
            fileAlign = pe.OPTIONAL_HEADER.FileAlignment
            sectionAlign = pe.OPTIONAL_HEADER.SectionAlignment

            lastSection = pe.sections[-1]
            newHeaderOffset = lastSection.get_file_offset() + 40 # 40 bytes per section header

            # Check if we have space in headers
            headersEnd = pe.OPTIONAL_HEADER.SizeOfHeaders
            hasHeaderSpace = (headersEnd - newHeaderOffset) >= 40

            if not hasHeaderSpace:
                self.error("No space in PE headers for new section")

            # Prepare section name
            namePadded = sectionName.encode('ascii', 'ignore')[:8].ljust(8, b'\x00')

            # Calculate new section layout
            virtualSize = len(content)
            rawSize = self.alignUp(len(content), fileAlign)

            # Find new virtual address
            lastEndVa = lastSection.VirtualAddress + self.alignUp(
                max(lastSection.Misc_VirtualSize, lastSection.SizeOfRawData), sectionAlign
            )
            newVirtualAddress = self.alignUp(lastEndVa, sectionAlign)

            # Find new raw data pointer
            lastRawEnd = self.alignUp(lastSection.PointerToRawData + lastSection.SizeOfRawData, fileAlign)
            currentFileEnd = self.alignUp(len(fileData), fileAlign)
            newRawPointer = max(lastRawEnd, currentFileEnd)

            # Extend file to accommodate new section
            if len(fileData) < newRawPointer + rawSize:
                fileData.extend(b'\x00' * (newRawPointer + rawSize - len(fileData)))

            # Write section content
            fileData[newRawPointer:newRawPointer + len(content)] = content

            # Create section header
            characteristics = 0x00000040 | 0x40000000 # INITIALIZED_DATA | READABLE
            sectionHeader = struct.pack(
                '<8sIIIIIIHHI',
                namePadded, # Name
                virtualSize, # VirtualSize
                newVirtualAddress, # VirtualAddress
                rawSize, # SizeOfRawData
                newRawPointer, # PointerToRawData
                0,
                0, # RelocationsPointer, LinenumbersPointer
                0,
                0, # NumberOfRelocations, NumberOfLinenumbers
                characteristics # Characteristics
            )

            # Write section header
            fileData[newHeaderOffset:newHeaderOffset + 40] = sectionHeader

            # Update PE headers
            ntHeaderOffset = pe.DOS_HEADER.e_lfanew
            numSectionsOffset = ntHeaderOffset + 4 + 2 # NT signature + Machine field
            newSectionCount = pe.FILE_HEADER.NumberOfSections + 1
            struct.pack_into('<H', fileData, numSectionsOffset, newSectionCount)

            # Update SizeOfImage
            newImageEnd = self.alignUp(newVirtualAddress + self.alignUp(virtualSize, sectionAlign), sectionAlign)
            sizeOfImageOffset = pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage')
            struct.pack_into('<I', fileData, sizeOfImageOffset, newImageEnd)

            # Write modified file
            with open(outputPath, 'wb') as f:
                f.write(fileData)

        def writeElfSection(self, inputPath: str, outputPath: str, sectionName: str, content: bytes) -> None:
            """Add new section to ELF file using LIEF"""
            import lief

            elf = lief.ELF.parse(inputPath)
            if not isinstance(elf, lief.ELF.Binary):
                self.error("Failed to parse ELF file")

            # Create new section
            section = lief.ELF.Section(sectionName)
            section.type = lief.ELF.Section.TYPE.PROGBITS
            section.flags = 0 # Not loaded into memory
            section.content = list(content)

            # Add section and write
            elf.add(section, loaded=False)
            elf.write(outputPath)

        def writePayload(
            self,
            inputPath: str,
            outputPath: str,
            dataContent: Optional[str] = None,
            dataFile: Optional[str] = None,
            sectionName: Optional[str] = None,
            secret: Optional[str] = None,
            enableCompression: bool = True
        ) -> None:
            """Write payload to binary file"""
            binaryFormat = self.detectBinaryFormat(inputPath)
            if binaryFormat not in {"PE", "ELF"}:
                self.error(f"{inputPath} Unsupported binary format: {binaryFormat}")

            # Load payload data
            rawData = b'' # Initialize to avoid possibly-used-before-assignment
            if dataContent is not None:
                rawData = dataContent.encode('utf-8')
            elif dataFile is not None:
                with open(dataFile, 'rb') as f:
                    rawData = f.read()
            else:
                self.error("Either dataContent or dataFile must be specified")

            # Determine section name
            if sectionName:
                finalSectionName = sectionName
            else:
                finalSectionName = self.PE_DEFAULT_SECTION if binaryFormat == "PE" else self.ELF_DEFAULT_SECTION

            if binaryFormat == "PE":
                finalSectionName = self.truncatePeSectionName(finalSectionName)

            # Create envelope
            envelope = self.createPayloadEnvelope(rawData, enableCompression, secret)

            self.log(f"Format: {binaryFormat}")
            self.log(f"Section: {finalSectionName}")
            self.log(f"Raw data: {len(rawData)} bytes")
            self.log(f"Envelope: {len(envelope)} bytes")
            self.log(f"Compression: {'enabled' if enableCompression else 'disabled'}")
            self.log(f"Encryption: {'enabled' if secret else 'disabled'}")

            # Write to binary
            if binaryFormat == "PE":
                self.writePeSection(inputPath, outputPath, finalSectionName, envelope)
            else:
                self.writeElfSection(inputPath, outputPath, finalSectionName, envelope)

            inputSize = os.path.getsize(inputPath)
            outputSize = os.path.getsize(outputPath)
            self.log(f"Output written: {outputPath} (+{outputSize - inputSize} bytes)")


def getVersionInfo():
    """
    Format version from Settings.PUBLIC_VERSION for both Windows and Linux builds.

    Returns:
        tuple: (formattedVersion, serialNumber)
            - formattedVersion: Version in 4-digit format (e.g., "3.1.0.0")
            - serialNumber: FREE_SERIAL_NUMBER
    """
    # Get the version directly from Settings
    publicVersion = PUBLIC_VERSION

    # Format version to 4-digit format (e.g., "3.1" to "3.1.0.0")
    versionParts = publicVersion.split('.')
    while len(versionParts) < 4:
        versionParts.append('0')
    formattedVersion = '.'.join(versionParts)

    return formattedVersion, FREE_SERIAL_NUMBER


def cleanupTempFile(tempFile):
    """
    Register cleanup function to remove temporary file after build

    Args:
        tempFile (str): Path to temporary file
    """
    import atexit

    def cleanup():
        if os.path.exists(tempFile):
            try:
                os.remove(tempFile)
            except OSError as e:
                logger.warning(f"Failed to remove temporary file {tempFile}: {e}")

    atexit.register(cleanup)


def editELF(inputFile, outputFile):
    import lief

    file = os.path.join(os.getcwd(), inputFile)

    # Get version and serial number using our DistUtils module
    formattedVersion, serialNumber = getVersionInfo()

    binary = lief.parse(file)

    section = lief.ELF.Section('Comments')
    section.content = list(serialNumber.encode('utf-8'))
    section.size = len(section.content)

    section.type = lief.ELF.Section.TYPE.PROGBITS
    section.alignment = 1

    binary.add(section)

    section2 = lief.ELF.Section('Version')
    section2.content = list(formattedVersion.encode('utf-8'))
    section2.size = len(section2.content)

    section2.type = lief.ELF.Section.TYPE.PROGBITS
    section2.alignment = 1

    binary.add(section2)
    binary.write(outputFile)


def cleanPyappEnv(targetDir: str = None):
    system = platform.system()

    if system in ["Linux", "Darwin"] and targetDir:
        targetDir = Path(targetDir).resolve()
        if not targetDir.exists():
            print(f"Cleaning targetDir not found: {targetDir}")
            return
        print(f"cleaning {targetDir}")
    else:
        envRoot = Path(sys.prefix).resolve()
        targetDir = Path(os.getcwd()) / (envRoot.name + "_copy")

        print(f"Copy {envRoot} to {targetDir}")

        if targetDir.exists():
            print(f"Directory {targetDir} exist, delete it first.")
            shutil.rmtree(targetDir)

        shutil.copytree(envRoot, targetDir)
        print("Copy finish.")

    if system == "Windows":
        deleteFiles = Path(__file__).parent / "dist" / "CLI" / "windows" / "DeleteFiles.txt"
    elif system == "Linux":
        deleteFiles = Path(__file__).parent / "dist" / "CLI" / "linux" / "DeleteFiles.txt"
    elif system == "Darwin":
        deleteFiles = Path(__file__).parent / "dist" / "CLI" / "darwin" / "DeleteFiles.txt"
    else:
        print(f"Unsupported system: {system}")
        deleteFiles = None

    if deleteFiles and deleteFiles.exists():
        print("Read files/folders need to be deleted in the environment.")
        with deleteFiles.open() as f:
            deletePaths = [(targetDir / line.strip()).resolve() for line in f if line.strip()]

        print("Delete files/folders in list.")
        for targetPath in deletePaths:
            if targetPath.exists():
                try:
                    if targetPath.is_file():
                        targetPath.unlink()
                        print(f"Deleted file : {targetPath}")
                    elif targetPath.is_dir():
                        shutil.rmtree(targetPath)
                        print(f"Deleted folder : {targetPath}")
                except Exception as e:
                    logger.error(f"Delete failed : {targetPath}: {e}")
                    print(f"Delete failed : {targetPath}: {e}")
            else:
                print(f"Path not found (skip) : {targetPath}")

    print("Perform general cleanup: *.dist-info, __pycache__, *.pyi,*.pdb")
    for folder in targetDir.rglob("*"):
        try:
            if folder.is_dir() and (folder.name.endswith(".dist-info") or folder.name == "__pycache__"):
                shutil.rmtree(folder)
                print(f"Deleted folder: {folder}")
            elif folder.is_file() and folder.suffix == ".pyi":
                folder.unlink()
                print(f"Deleted file: {folder}")
            elif folder.is_file() and folder.suffix == ".pdb":
                folder.unlink()
                print(f"Deleted file: {folder}")
        except Exception as e:
            logger.error(f"Failed to delete {folder}: {e}")
            print(f"Failed to delete {folder}: {e}")


def compressPyappEnv(targetDir):

    targetPath = Path(targetDir)

    zipPath = targetPath.parent / "ffl_python.zip"

    print(f"Start compressing into {zipPath} ...")
    shutil.make_archive(base_name=str(zipPath.with_suffix('')), format='zip', root_dir=str(targetPath))

    print(f"Compress finish. Remove {targetPath}")
    os.chdir(targetPath.parent)
    shutil.rmtree(targetPath)


class CLIHandler:
    """Command line interface handler"""

    def __init__(self):
        self.writer = PayloadWriter(verbose=True, printOut=True)
        self.reader = PayloadReader(verbose=True, printOut=True)

    def handleWriteCommand(self, args: argparse.Namespace) -> None:
        """Handle write command from CLI"""
        if args.edit_elf:
            editELF(inputFile=args.edit_elf, outputFile=args.output)
        else:
            enableCompression = not args.noCompress
            self.writer.writePayload(
                inputPath=args.input,
                outputPath=args.output,
                dataContent=args.data,
                dataFile=args.dataFile,
                sectionName=args.section,
                secret=args.secret,
                enableCompression=enableCompression
            )

    def handleReadCommand(self, args: argparse.Namespace) -> None:
        """Handle read command from CLI"""
        payload = self.reader.readPayload(
            inputPath=args.input, sectionName=args.section, secret=args.secret, outputPath=args.output
        )

        if not args.output:
            try:
                text = payload.decode('utf-8')
                print(text)
            except UnicodeDecodeError:
                self.reader.log("Binary payload detected, printing as base64")
                print(base64.b64encode(payload).decode('ascii'))

    def handlePyappCommand(self, args: argparse.Namespace) -> None:
        if args.pyappCommand == "clean":
            cleanPyappEnv(targetDir=args.target_dir)
        elif args.pyappCommand == "compress":
            compressPyappEnv(targetDir=args.targetDir)


def createArgumentParser() -> argparse.ArgumentParser:
    """Create and configure argument parser"""

    formattedVersion, serialNumber = getVersionInfo()
    secret = f'{serialNumber}:{formattedVersion}'

    parser = argparse.ArgumentParser(
        description="FastFileLink Binary Data Embedder - Embed/extract data in PE/ELF files"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Write command
    writeParser = subparsers.add_parser("write", help="Embed data into binary file")
    writeParser.add_argument("input", help="Input binary file (PE/ELF)")
    writeParser.add_argument("-o", "--output", required=True, help="Output file path")
    writeParser.add_argument("--section", help="Custom section name")

    dataGroup = writeParser.add_mutually_exclusive_group(required=True)
    dataGroup.add_argument("--data", help="Data as UTF-8 string")
    dataGroup.add_argument("--data-file", dest="dataFile", help="Data from file (binary)")

    writeParser.add_argument("--secret", default=secret, help=f"Encryption secret (default: {secret})")
    writeParser.add_argument("--no-compress", dest="noCompress", action="store_true", help="Disable zlib compression")

    # FIXME: backward compatibility
    writeParser.add_argument('--edit-elf', metavar='ELF_FILE', help='Edit the specified ELF file')

    # Read command
    readParser = subparsers.add_parser("read", help="Extract data from binary file")
    readParser.add_argument("input", help="Input binary file (PE/ELF)")
    readParser.add_argument("--section", help="Custom section name")
    readParser.add_argument("--secret", default=secret, help=f"Decryption secret (default: {secret})")
    readParser.add_argument("-o", "--output", help="Output file (default: stdout)")

    # === 新增的命令 ===
    pyappParser = subparsers.add_parser("pyapp", help="PyApp environment operations")
    pyappSubparsers = pyappParser.add_subparsers(dest="pyappCommand", required=True)

    # pyapp clean
    pyappSubparsers.add_parser("clean", help="Copy python env to work folder and clean it") \
        .add_argument("--target-dir", help="Linux: specify target folder to clean")

    # pyapp compress
    pyappSubparsers.add_parser("compress", help="Compress python env folder") \
        .add_argument("targetDir", help="Folder to compress")

    return parser


def main() -> None:
    parser = createArgumentParser()
    args = parser.parse_args()

    cliHandler = CLIHandler()

    if args.command == "write":
        cliHandler.handleWriteCommand(args)
    elif args.command == "read":
        cliHandler.handleReadCommand(args)
    elif args.command == "pyapp":
        cliHandler.handlePyappCommand(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
