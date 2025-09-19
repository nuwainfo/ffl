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

import unittest
import os
import tempfile
import json
import shutil
from unittest.mock import patch, MagicMock

from bases.Kernel import EventService, EventTiming, AddonsManager, StorageLocator


class EventServiceTest(unittest.TestCase):
    """
    Test case for the singleton, signalslot-based EventService.
    """

    def setUp(self):
        """
        Get the singleton instance and reset its state for test isolation.
        """
        self.e = EventService.getInstance()
        # Call the reset method for better encapsulation.
        self.e.reset()

    def testIsSingleton(self):
        """
        Verify that the EventService is indeed a singleton.
        """
        e1 = EventService.getInstance()
        e2 = EventService.getInstance()
        self.assertIs(e1, e2)
        self.assertIs(self.e, e1)

    def testEventService(self):
        """
        Test for core attach, subscribe, unsubscribe, and detach functionality.
        """

        class TestTarget:

            def __init__(self):
                self.log = []

            def f(self, a, b):
                self.log.append('original_f_called')
                return a + b

        originalFunc = TestTarget.f

        def call(obj):
            obj.log = []
            obj.f(1, 2)

        def observer1(sender, context, **kwargs):
            sender.log.append(id(observer1))

        self.e.register("Event1")
        self.e.register("Event2")

        TestTarget.f = self.e.attach("Event1", TestTarget.f)
        self.e.subscribe("Event1", observer1)

        a = TestTarget()
        call(a)
        self.assertEqual(a.log, ['original_f_called', id(observer1)])

        def observer2(sender, context, **kwargs):
            sender.log.append(id(observer2))

        self.e.subscribe("Event1", observer2)
        call(a)
        self.assertEqual(a.log, ['original_f_called', id(observer1), id(observer2)])

        self.e.unsubscribe("Event1", observer2)
        call(a)
        self.assertEqual(a.log, ['original_f_called', id(observer1)])

        TestTarget.f = self.e.attach("Event2", TestTarget.f)
        self.e.subscribe("Event2", observer2)
        call(a)
        self.assertEqual(a.log, ['original_f_called', id(observer1), id(observer2)])

        TestTarget.f = self.e.detach("Event1", TestTarget.f)
        call(a)
        self.assertEqual(a.log, ['original_f_called', id(observer2)])

        TestTarget.f = self.e.original(TestTarget.f)
        self.assertIs(TestTarget.f, originalFunc)

        call(a)
        self.assertEqual(a.log, ['original_f_called'])

    def testTiming(self):
        """
        Test for EventService with EventTiming.BEFORE and EventTiming.AFTER timing features.
        """

        class B:

            def __init__(self):
                self.log = []

            def f(self):
                self.log.append('f_called')

        self.e.register("E1")
        B.f = self.e.attach("E1", B.f)

        def before(sender, context, **kwargs):
            sender.log.append('before_called')

        def after(sender, context, **kwargs):
            sender.log.append('after_called')

        self.e.subscribe("E1", after, EventTiming.AFTER)
        self.e.subscribe("E1", before, EventTiming.BEFORE)

        b = B()
        b.f()
        self.assertEqual(b.log, ['before_called', 'f_called', 'after_called'])

    def testTimingWithStrings(self):
        """
        Test for EventService with string timing parameters for backward compatibility.
        """

        class C:

            def __init__(self):
                self.log = []

            def f(self):
                self.log.append('f_called')

        self.e.register("E2")
        C.f = self.e.attach("E2", C.f)

        def before(sender, context, **kwargs):
            sender.log.append('before_called_str')

        def after(sender, context, **kwargs):
            sender.log.append('after_called_str')

        # Test with string parameters
        self.e.subscribe("E2", after, 'AFTER')
        self.e.subscribe("E2", before, 'BEFORE')

        c = C()
        c.f()
        self.assertEqual(c.log, ['before_called_str', 'f_called', 'after_called_str'])

    def testSubscribeAtFront(self):
        """
        Test for subscribe at front feature, enabled by wrapping signalslot.
        """
        log = []

        def s1(*args, **kwargs):
            log.append(id(s1))

        def s2(*args, **kwargs):
            log.append(id(s2))

        self.e.register('E')
        self.e.subscribe("E", s1)
        self.e.subscribe("E", s2, index=0)
        self.e.trigger('E')

        self.assertEqual(len(log), 2)
        self.assertEqual(log[0], id(s2))
        self.assertEqual(log[1], id(s1))

    def testFind(self):
        """
        Test for the find method with EventTiming constants.
        """

        def s1(**kwargs):
            pass

        def s2(**kwargs):
            pass

        def s3(**kwargs):
            pass

        self.e.register('E')
        self.e.subscribe("E", s1)
        self.e.subscribe("E", s2)
        self.e.subscribe("E", s3, EventTiming.BEFORE)

        self.assertEqual(self.e.find("E", s1, timing=EventTiming.AFTER), 0)
        self.assertEqual(self.e.find("E", s2, timing=EventTiming.AFTER), 1)
        self.assertEqual(self.e.find("E", s3, timing=EventTiming.AFTER), -1)
        self.assertEqual(self.e.find("E", s3, timing=EventTiming.BEFORE), 0)

    def testFindWithStrings(self):
        """
        Test for the find method with string timing parameters for backward compatibility.
        """

        def s1(**kwargs):
            pass

        def s2(**kwargs):
            pass

        self.e.register('E3')
        self.e.subscribe("E3", s1, 'AFTER')
        self.e.subscribe("E3", s2, 'BEFORE')

        self.assertEqual(self.e.find("E3", s1, timing='AFTER'), 0)
        self.assertEqual(self.e.find("E3", s2, timing='BEFORE'), 0)
        self.assertEqual(self.e.find("E3", s1, timing='BEFORE'), -1)

    def testTimingValidation(self):
        """
        Test timing parameter validation.
        """
        self.e.register('ValidateEvent')

        def dummy_observer(**kwargs):
            pass

        # Test valid enum values
        self.e.subscribe('ValidateEvent', dummy_observer, EventTiming.BEFORE)
        self.e.subscribe('ValidateEvent', dummy_observer, EventTiming.AFTER)

        # Test valid string values
        self.e.subscribe('ValidateEvent', dummy_observer, 'BEFORE')
        self.e.subscribe('ValidateEvent', dummy_observer, 'AFTER')

        # Test case insensitive strings
        self.e.subscribe('ValidateEvent', dummy_observer, 'before')
        self.e.subscribe('ValidateEvent', dummy_observer, 'after')

        # Test invalid timing values
        with self.assertRaises(ValueError):
            self.e.subscribe('ValidateEvent', dummy_observer, 'INVALID')

        with self.assertRaises(ValueError):
            self.e.subscribe('ValidateEvent', dummy_observer, 123)


class AddonsManagerTest(unittest.TestCase):
    """
    Test case for AddonsManager addon loading functionality with addons.json support.
    """

    def setUp(self):
        """
        Set up test environment with temporary directories and reset singleton state.
        """
        # Create temporary directory for test config files
        self.tempDir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tempDir)

        # Reset singleton instances for test isolation
        self.addonsManager = AddonsManager.getInstance()
        self.addonsManager.reset()

        # Create a fresh StorageLocator instance that uses our temp directory
        self.storageLocator = StorageLocator.getInstance()
        # We'll patch the findConfig method to use our temp directory

    def testGetDisabledAddonsFromJson(self):
        """
        Test reading disabled addons from addons.json config file.
        """
        # Create test addons.json file
        addonsConfig = {
            "disabled": ["GUI", "Tunnels", "Features"]
        }
        addonsJsonPath = os.path.join(self.tempDir, 'addons.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            json.dump(addonsConfig, f)

        # Mock StorageLocator to return our temp file
        with patch.object(self.storageLocator, 'findConfig', return_value=addonsJsonPath):
            disabledAddons = self.addonsManager._getDisabledAddons()

        expectedDisabled = {"GUI", "Tunnels", "Features"}
        self.assertEqual(disabledAddons, expectedDisabled)

    def testGetDisabledAddonsFromEnvironment(self):
        """
        Test reading disabled addons from DISABLE_ADDONS environment variable.
        """
        # Mock StorageLocator to return non-existent file so env var is used
        nonExistentPath = os.path.join(self.tempDir, 'nonexistent.json')

        with patch.dict(os.environ, {'DISABLE_ADDONS': 'GUI,Upload,API'}):
            with patch.object(self.storageLocator, 'findConfig', return_value=nonExistentPath):
                disabledAddons = self.addonsManager._getDisabledAddons()

        expectedDisabled = {"GUI", "Upload", "API"}
        self.assertEqual(disabledAddons, expectedDisabled)

    def testConfigOverridesEnvironment(self):
        """
        Test that addons.json config file has higher priority than DISABLE_ADDONS environment variable.
        """
        # Create addons.json with some disabled addons
        addonsConfig = {
            "disabled": ["GUI", "Tunnels"]
        }
        addonsJsonPath = os.path.join(self.tempDir, 'addons.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            json.dump(addonsConfig, f)

        # Set environment variable with different addons - should be ignored
        with patch.dict(os.environ, {'DISABLE_ADDONS': 'Upload,Features,API'}):
            with patch.object(self.storageLocator, 'findConfig', return_value=addonsJsonPath):
                disabledAddons = self.addonsManager._getDisabledAddons()

        # Should only use config file, ignore environment variable
        expectedDisabled = {"GUI", "Tunnels"}
        self.assertEqual(disabledAddons, expectedDisabled)

    def testGetDisabledAddonsWithMissingFile(self):
        """
        Test behavior when addons.json file doesn't exist.
        """
        nonExistentPath = os.path.join(self.tempDir, 'nonexistent.json')

        with patch.object(self.storageLocator, 'findConfig', return_value=nonExistentPath):
            disabledAddons = self.addonsManager._getDisabledAddons()

        # Should return empty set when no file exists and no env var
        self.assertEqual(disabledAddons, set())

    def testGetDisabledAddonsWithInvalidJson(self):
        """
        Test handling of invalid JSON in addons.json file.
        """
        # Create invalid JSON file
        addonsJsonPath = os.path.join(self.tempDir, 'invalid.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            f.write('{"disabled": ["GUI",}')  # Invalid JSON (trailing comma)

        with patch.object(self.storageLocator, 'findConfig', return_value=addonsJsonPath):
            disabledAddons = self.addonsManager._getDisabledAddons()

        # Should return empty set and handle error gracefully
        self.assertEqual(disabledAddons, set())

    def testGetDisabledAddonsWithInvalidFormat(self):
        """
        Test handling of valid JSON but invalid format in addons.json.
        """
        # Create JSON with wrong structure
        addonsConfig = {
            "disabled": "GUI,Tunnels"  # Should be array, not string
        }
        addonsJsonPath = os.path.join(self.tempDir, 'wrong_format.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            json.dump(addonsConfig, f)

        with patch.object(self.storageLocator, 'findConfig', return_value=addonsJsonPath):
            disabledAddons = self.addonsManager._getDisabledAddons()

        # Should return empty set when format is wrong
        self.assertEqual(disabledAddons, set())

    def testGetDisabledAddonsWithEmptyValues(self):
        """
        Test handling of empty and whitespace-only values in disabled list.
        """
        addonsConfig = {
            "disabled": ["GUI", "", "  ", "Tunnels", "   Features   "]
        }
        addonsJsonPath = os.path.join(self.tempDir, 'empty_values.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            json.dump(addonsConfig, f)

        with patch.object(self.storageLocator, 'findConfig', return_value=addonsJsonPath):
            disabledAddons = self.addonsManager._getDisabledAddons()

        # Should filter out empty values and strip whitespace
        expectedDisabled = {"GUI", "Tunnels", "Features"}
        self.assertEqual(disabledAddons, expectedDisabled)

    @patch('importlib.import_module')
    def testGetEnabledAddonsWithDisabledFromJson(self, mockImportModule):
        """
        Test that getEnabledAddons() properly filters out addons disabled via addons.json.
        """
        # Mock the addons module
        mockAddonsModule = MagicMock()
        mockAddonsModule.addons = ["GUI", "Upload", "Tunnels", "Features", "API"]
        mockImportModule.return_value = mockAddonsModule

        # Create addons.json with some disabled addons
        addonsConfig = {
            "disabled": ["GUI", "Features"]
        }
        addonsJsonPath = os.path.join(self.tempDir, 'filter_test.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            json.dump(addonsConfig, f)

        with patch.object(self.storageLocator, 'findConfig', return_value=addonsJsonPath):
            enabledAddons = self.addonsManager.getEnabledAddons()

        expectedEnabled = ["Upload", "Tunnels", "API"]
        self.assertEqual(enabledAddons, expectedEnabled)

    @patch('importlib.import_module')
    def testGetEnabledAddonsWithDisabledFromEnvironment(self, mockImportModule):
        """
        Test that getEnabledAddons() properly filters out addons disabled via environment variable.
        """
        # Mock the addons module
        mockAddonsModule = MagicMock()
        mockAddonsModule.addons = ["GUI", "Upload", "Tunnels", "Features", "API"]
        mockImportModule.return_value = mockAddonsModule

        # Mock StorageLocator to return non-existent file so env var is used
        nonExistentPath = os.path.join(self.tempDir, 'nonexistent.json')

        with patch.dict(os.environ, {'DISABLE_ADDONS': 'Upload,API'}):
            with patch.object(self.storageLocator, 'findConfig', return_value=nonExistentPath):
                enabledAddons = self.addonsManager.getEnabledAddons()

        expectedEnabled = ["GUI", "Tunnels", "Features"]
        self.assertEqual(enabledAddons, expectedEnabled)

    def testEnvironmentFallbackWhenNoConfig(self):
        """
        Test that DISABLE_ADDONS environment variable works as fallback when no config file exists.
        """
        nonExistentPath = os.path.join(self.tempDir, 'nonexistent.json')

        with patch.dict(os.environ, {'DISABLE_ADDONS': 'GUI,Upload'}):
            with patch.object(self.storageLocator, 'findConfig', return_value=nonExistentPath):
                disabledAddons = self.addonsManager._getDisabledAddons()

        expectedDisabled = {"GUI", "Upload"}
        self.assertEqual(disabledAddons, expectedDisabled)

    @patch('importlib.import_module')
    def testGetEnabledAddonsPriorityConfigOverEnvironment(self, mockImportModule):
        """
        Test that addons.json config file takes priority over environment variable when both are present.
        """
        # Mock the addons module
        mockAddonsModule = MagicMock()
        mockAddonsModule.addons = ["GUI", "Upload", "Tunnels", "Features", "API"]
        mockImportModule.return_value = mockAddonsModule

        # Create addons.json
        addonsConfig = {
            "disabled": ["GUI", "Features"]
        }
        addonsJsonPath = os.path.join(self.tempDir, 'priority_test.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            json.dump(addonsConfig, f)

        # Set environment variable - should be ignored when config file exists
        with patch.dict(os.environ, {'DISABLE_ADDONS': 'Upload,Tunnels'}):
            with patch.object(self.storageLocator, 'findConfig', return_value=addonsJsonPath):
                enabledAddons = self.addonsManager.getEnabledAddons()

        # Should only disable addons from config file, ignore environment variable
        expectedEnabled = ["Upload", "Tunnels", "API"]  # GUI and Features disabled by config
        self.assertEqual(enabledAddons, expectedEnabled)

    def testGetDisabledAddonsWithNonStringValues(self):
        """
        Test handling of non-string values in disabled array.
        """
        addonsConfig = {
            "disabled": ["GUI", 123, None, "Tunnels", {"invalid": "object"}]
        }
        addonsJsonPath = os.path.join(self.tempDir, 'non_string.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            json.dump(addonsConfig, f)

        with patch.object(self.storageLocator, 'findConfig', return_value=addonsJsonPath):
            disabledAddons = self.addonsManager._getDisabledAddons()

        # Should only include valid string values
        expectedDisabled = {"GUI", "Tunnels"}
        self.assertEqual(disabledAddons, expectedDisabled)


if __name__ == '__main__':
    unittest.main()
