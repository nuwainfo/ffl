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

        # Clear all signals, don't clear registered event because it will break other tests.
        for beforeSignal, afterSignal in self.e.signals.values():
            beforeSignal._slots.clear()
            afterSignal._slots.clear()

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

    def testWildcardSubscription(self):
        """Test subscribing to all events using '*'"""
        receivedEvents = []

        # Define wildcard handler
        def wildcardHandler(eventName, **kwargs):
            receivedEvents.append((eventName, kwargs))

        # Subscribe to wildcard event
        self.e.subscribe('*', wildcardHandler)

        # Register events first
        self.e.register('/test/event1')
        self.e.register('/test/event2')

        # Trigger some events
        self.e.trigger('/test/event1', data='value1')
        self.e.trigger('/test/event2', data='value2', number=123)

        # Verify wildcard handler received both events
        self.assertEqual(len(receivedEvents), 2)
        self.assertEqual(receivedEvents[0][0], '/test/event1')
        self.assertEqual(receivedEvents[0][1]['data'], 'value1')
        self.assertEqual(receivedEvents[1][0], '/test/event2')
        self.assertEqual(receivedEvents[1][1]['data'], 'value2')
        self.assertEqual(receivedEvents[1][1]['number'], 123)

        # Cleanup
        self.e.unsubscribe('*', wildcardHandler)

    def testWildcardWithNormalSubscribers(self):
        """Test wildcard doesn't interfere with normal subscribers"""
        normalEvents = []
        wildcardEvents = []

        def normalHandler(**kwargs):
            normalEvents.append(kwargs)

        def wildcardHandler(eventName, **kwargs):
            wildcardEvents.append((eventName, kwargs))

        # Register event first
        self.e.register('/test/event1')

        # Subscribe both normal and wildcard handlers
        self.e.subscribe('/test/event1', normalHandler)
        self.e.subscribe('*', wildcardHandler)

        # Trigger event
        self.e.trigger('/test/event1', key='value')

        # Verify both handlers received the event
        self.assertEqual(len(normalEvents), 1)
        self.assertEqual(normalEvents[0]['key'], 'value')

        self.assertEqual(len(wildcardEvents), 1)
        self.assertEqual(wildcardEvents[0][0], '/test/event1')
        self.assertEqual(wildcardEvents[0][1]['key'], 'value')

        # Cleanup
        self.e.unsubscribe('/test/event1', normalHandler)
        self.e.unsubscribe('*', wildcardHandler)

    def testWildcardDoesNotTriggerItself(self):
        """Test that triggering '*' doesn't cause infinite loop"""
        wildcardEvents = []

        def wildcardHandler(eventName, **kwargs):
            wildcardEvents.append(eventName)

        # Subscribe to wildcard
        self.e.subscribe('*', wildcardHandler)

        # Trigger wildcard event directly (should not trigger handler)
        self.e.trigger('*', data='test')

        # Verify wildcard handler was NOT called (no infinite loop)
        self.assertEqual(len(wildcardEvents), 0)

        # Cleanup
        self.e.unsubscribe('*', wildcardHandler)

    def testMultipleWildcardSubscribers(self):
        """Test multiple wildcard subscribers work correctly"""
        events1 = []
        events2 = []

        def handler1(eventName, **kwargs):
            events1.append(eventName)

        def handler2(eventName, **kwargs):
            events2.append(eventName)

        # Subscribe multiple wildcard handlers
        self.e.subscribe('*', handler1)
        self.e.subscribe('*', handler2)

        # Register and trigger event
        self.e.register('/test/event1')
        self.e.trigger('/test/event1')

        # Verify both handlers received the event
        self.assertEqual(len(events1), 1)
        self.assertEqual(events1[0], '/test/event1')
        self.assertEqual(len(events2), 1)
        self.assertEqual(events2[0], '/test/event1')

        # Cleanup
        self.e.unsubscribe('*', handler1)
        self.e.unsubscribe('*', handler2)

    def testWildcardUnsubscribe(self):
        """Test unsubscribing from wildcard event"""
        events = []

        def handler(eventName, **kwargs):
            events.append(eventName)

        # Subscribe and trigger
        self.e.subscribe('*', handler)
        self.e.register('/test/event1')
        self.e.trigger('/test/event1')

        self.assertEqual(len(events), 1)

        # Unsubscribe and trigger again
        self.e.unsubscribe('*', handler)
        self.e.trigger('/test/event1')

        # Verify handler was not called after unsubscribe
        self.assertEqual(len(events), 1)


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

        # Point StorageLocator.homeDir at our temp dir - _readAddonsConfig() resolves
        # addons.json from there directly, so this keeps every test isolated from
        # whatever real ~/.fastfilelink/addons.json happens to exist on the machine.
        self.storageLocator = StorageLocator.getInstance()
        homeDirPatcher = patch.object(self.storageLocator, '_homeDir', self.tempDir)
        homeDirPatcher.start()
        self.addCleanup(homeDirPatcher.stop)

    def _writeAddonsJson(self, config, inDir=None):
        """Write addons.json into the given directory (default: self.tempDir, the patched home)."""
        addonsJsonPath = os.path.join(inDir or self.tempDir, 'addons.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            json.dump(config, f)
        return addonsJsonPath

    def testGetDisabledAddonsFromJson(self):
        """
        Test reading disabled addons from addons.json config file.
        """
        self._writeAddonsJson({"disabled": ["GUI", "Tunnels", "Features"]})

        disabledAddons = self.addonsManager._getDisabledAddons()

        expectedDisabled = {"GUI", "Tunnels", "Features"}
        self.assertEqual(disabledAddons, expectedDisabled)

    def testGetDisabledAddonsFromEnvironment(self):
        """
        Test reading disabled addons from DISABLE_ADDONS environment variable.
        """
        # No addons.json written - env var should be used
        with patch.dict(os.environ, {'DISABLE_ADDONS': 'GUI,Upload,API'}):
            disabledAddons = self.addonsManager._getDisabledAddons()

        expectedDisabled = {"GUI", "Upload", "API"}
        self.assertEqual(disabledAddons, expectedDisabled)

    def testConfigOverridesEnvironment(self):
        """
        Test that addons.json config file has higher priority than DISABLE_ADDONS environment variable.
        """
        self._writeAddonsJson({"disabled": ["GUI", "Tunnels"]})

        # Set environment variable with different addons - should be ignored
        with patch.dict(os.environ, {'DISABLE_ADDONS': 'Upload,Features,API'}):
            disabledAddons = self.addonsManager._getDisabledAddons()

        # Should only use config file, ignore environment variable
        expectedDisabled = {"GUI", "Tunnels"}
        self.assertEqual(disabledAddons, expectedDisabled)

    def testGetDisabledAddonsWithMissingFile(self):
        """
        Test behavior when addons.json file doesn't exist.
        """
        disabledAddons = self.addonsManager._getDisabledAddons()

        # Should return empty set when no file exists and no env var
        self.assertEqual(disabledAddons, set())

    def testGetDisabledAddonsWithInvalidJson(self):
        """
        Test handling of invalid JSON in addons.json file.
        """
        addonsJsonPath = os.path.join(self.tempDir, 'addons.json')
        with open(addonsJsonPath, 'w', encoding='utf-8') as f:
            f.write('{"disabled": ["GUI",}') # Invalid JSON (trailing comma)

        disabledAddons = self.addonsManager._getDisabledAddons()

        # Should return empty set and handle error gracefully
        self.assertEqual(disabledAddons, set())

    def testGetDisabledAddonsWithInvalidFormat(self):
        """
        Test handling of valid JSON but invalid format in addons.json.
        """
        self._writeAddonsJson({"disabled": "GUI,Tunnels"}) # Should be array, not string

        disabledAddons = self.addonsManager._getDisabledAddons()

        # Should return empty set when format is wrong
        self.assertEqual(disabledAddons, set())

    def testGetDisabledAddonsWithEmptyValues(self):
        """
        Test handling of empty and whitespace-only values in disabled list.
        """
        self._writeAddonsJson({"disabled": ["GUI", "", "  ", "Tunnels", "   Features   "]})

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
        mockAddonsModule.__path__ = []
        mockImportModule.return_value = mockAddonsModule

        self._writeAddonsJson({"disabled": ["GUI", "Features"]})

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
        mockAddonsModule.__path__ = []
        mockImportModule.return_value = mockAddonsModule

        # No addons.json written - env var should be used
        with patch.dict(os.environ, {'DISABLE_ADDONS': 'Upload,API'}):
            enabledAddons = self.addonsManager.getEnabledAddons()

        expectedEnabled = ["GUI", "Tunnels", "Features"]
        self.assertEqual(enabledAddons, expectedEnabled)

    def testEnvironmentFallbackWhenNoConfig(self):
        """
        Test that DISABLE_ADDONS environment variable works as fallback when no config file exists.
        """
        with patch.dict(os.environ, {'DISABLE_ADDONS': 'GUI,Upload'}):
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
        mockAddonsModule.__path__ = []
        mockImportModule.return_value = mockAddonsModule

        self._writeAddonsJson({"disabled": ["GUI", "Features"]})

        # Set environment variable - should be ignored when config file exists
        with patch.dict(os.environ, {'DISABLE_ADDONS': 'Upload,Tunnels'}):
            enabledAddons = self.addonsManager.getEnabledAddons()

        # Should only disable addons from config file, ignore environment variable
        expectedEnabled = ["Upload", "Tunnels", "API"] # GUI and Features disabled by config
        self.assertEqual(enabledAddons, expectedEnabled)

    def testGetDisabledAddonsWithNonStringValues(self):
        """
        Test handling of non-string values in disabled array.
        """
        self._writeAddonsJson({"disabled": ["GUI", 123, None, "Tunnels", {"invalid": "object"}]})

        disabledAddons = self.addonsManager._getDisabledAddons()

        # Should only include valid string values
        expectedDisabled = {"GUI", "Tunnels"}
        self.assertEqual(disabledAddons, expectedDisabled)

    def testGetExtraAddonNamesFromJson(self):
        """
        Test reading extra addon names from addons.json 'extra_addons' field.
        """
        self._writeAddonsJson({"extra_addons": ["MyCustomAddon", "AnotherAddon"]})

        extraAddons = self.addonsManager._getExtraAddonNames()

        self.assertEqual(extraAddons, ["MyCustomAddon", "AnotherAddon"])

    def testGetExtraAddonNamesWithInvalidFormat(self):
        """
        Test handling of a non-array 'extra_addons' field.
        """
        self._writeAddonsJson({"extra_addons": "NotAnArray"})

        extraAddons = self.addonsManager._getExtraAddonNames()

        self.assertEqual(extraAddons, [])

    def testGetAddonFoldersIncludesConfiguredAndHomeFolders(self):
        """
        Test that _getAddonFolders() returns configured 'addon_folders' plus
        ~/.fastfilelink/addons when it exists, filtering out non-existent paths.
        """
        customAddonFolder = os.path.join(self.tempDir, 'custom_addons')
        os.makedirs(customAddonFolder)
        missingFolder = os.path.join(self.tempDir, 'missing_folder')
        homeAddonsFolder = os.path.join(self.tempDir, 'addons')
        os.makedirs(homeAddonsFolder)

        self._writeAddonsJson({"addon_folders": [customAddonFolder, missingFolder]})

        folders = self.addonsManager._getAddonFolders()

        self.assertIn(customAddonFolder, folders)
        self.assertIn(homeAddonsFolder, folders)
        self.assertNotIn(missingFolder, folders)

    def testGetAddonFoldersExcludesMissingHomeAddonsFolder(self):
        """
        Test that a non-existent ~/.fastfilelink/addons folder is silently excluded.
        """
        # self.tempDir (the patched home) has no 'addons' subfolder and no addons.json
        folders = self.addonsManager._getAddonFolders()

        self.assertEqual(folders, [])

    @patch('importlib.import_module')
    def testGetEnabledAddonsIncludesExtraAddons(self, mockImportModule):
        """
        Test that getEnabledAddons() appends addons.json 'extra_addons' after the built-in list.
        """
        mockAddonsModule = MagicMock()
        mockAddonsModule.addons = ["GUI", "Upload"]
        mockAddonsModule.__path__ = []
        mockImportModule.return_value = mockAddonsModule

        self._writeAddonsJson({"extra_addons": ["MyCustomAddon"]})

        enabledAddons = self.addonsManager.getEnabledAddons()

        self.assertEqual(enabledAddons, ["GUI", "Upload", "MyCustomAddon"])

    @patch('importlib.import_module')
    def testGetEnabledAddonsExtraAddonCanStillBeDisabled(self, mockImportModule):
        """
        Test that an addon listed in both 'extra_addons' and 'disabled' is filtered out.
        """
        mockAddonsModule = MagicMock()
        mockAddonsModule.addons = ["GUI", "Upload"]
        mockAddonsModule.__path__ = []
        mockImportModule.return_value = mockAddonsModule

        self._writeAddonsJson({"extra_addons": ["MyCustomAddon"], "disabled": ["MyCustomAddon"]})

        enabledAddons = self.addonsManager.getEnabledAddons()

        self.assertEqual(enabledAddons, ["GUI", "Upload"])

    @patch('importlib.import_module')
    def testExtendAddonSearchPathsAddsConfiguredFolder(self, mockImportModule):
        """
        Test that _extendAddonSearchPaths() appends configured addon folders to addons.__path__.
        """
        mockAddonsModule = MagicMock()
        mockAddonsModule.addons = []
        mockAddonsModule.__path__ = []
        mockImportModule.return_value = mockAddonsModule

        customAddonFolder = os.path.join(self.tempDir, 'custom_addons')
        os.makedirs(customAddonFolder)

        self._writeAddonsJson({"addon_folders": [customAddonFolder]})

        self.addonsManager._extendAddonSearchPaths()

        self.assertIn(customAddonFolder, mockAddonsModule.__path__)


if __name__ == '__main__':
    unittest.main()
