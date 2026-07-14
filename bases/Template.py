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

from typing import Optional

from jinja2 import Environment, FileSystemLoader


# Compiled Jinja2 Environments (parsed templates + loader), keyed by template
# directory -- parsing is expensive and purely a function of directory
# contents, so any number of hosts (or dynamically-recreated subclasses, see
# TemplateMixin's docstring) serving the same directory share one parse.
_baseJinja2EnvCache: dict = {}

# Per-_templateCacheKey overlay Environments -- see TemplateMixin.
_jinja2EnvCache: dict = {}


class TemplateMixin:
    """
    Jinja2 template rendering, reusable by any host class -- has no HTTP/
    socket dependency, unlike bases.HTTP's mixins. A host class configures
    where its templates live by overriding the _templateDirectory property,
    evaluated lazily (only when a template is first rendered) since the
    directory often depends on runtime configuration not ready at class-
    definition time.

    _jinja2Env is a cheap overlay() of that directory's compiled Environment
    (_baseJinja2Env), sharing its parsed templates but with its own `globals`
    dict -- so _updateTemplateGlobals on one host (e.g. binding a controller-
    bound method) can never leak into another host that happens to serve the
    same directory. The overlay is cached per _templateCacheKey, which
    defaults to _templateDirectory (every host serving one directory shares
    one globals namespace, matching pre-overlay behavior); override it when
    distinct instances of this host class can be alive at once and must not
    share globals, e.g. `return self` (see WebViewBridgeServer, whose globals
    bind a specific controller instance's methods).
    """

    @property
    def _templateDirectory(self) -> str:
        """Override to return the directory Jinja2 should load templates
        from for this host class."""
        raise NotImplementedError(f"{type(self).__name__} must override _templateDirectory")

    @property
    def _templateCacheKey(self):
        """Cache key for this host's own env.globals overlay -- see class
        docstring."""
        return self._templateDirectory

    @property
    def _templateEnvironment(self) -> Optional[Environment]:
        """The overlay Environment for this host's cache key, if one has
        been built yet (via _jinja2Env / _renderTemplate) -- None otherwise.
        A read-only lookup; unlike _jinja2Env, this never builds one lazily."""
        return _jinja2EnvCache.get(self._templateCacheKey)

    def _buildJinja2Environment(self, templateDirectory: str) -> Environment:
        """Override to customize Environment construction (autoescape, trim_blocks, ...)
        for this host class. Default matches the original DownloadHandler behavior."""
        return Environment(
            loader=FileSystemLoader(templateDirectory),
            autoescape=False,
            keep_trailing_newline=True,
        )

    @property
    def _baseJinja2Env(self) -> Environment:
        templateDirectory = self._templateDirectory
        env = _baseJinja2EnvCache.get(templateDirectory)
        if env is None:
            env = self._buildJinja2Environment(templateDirectory)
            _baseJinja2EnvCache[templateDirectory] = env

        return env

    @property
    def _jinja2Env(self) -> Environment:
        cacheKey = self._templateCacheKey
        env = _jinja2EnvCache.get(cacheKey)
        if env is None:
            env = self._baseJinja2Env.overlay()
            env.globals = dict(env.globals)  # overlay() shares the base env's globals dict by default -- decouple it
            _jinja2EnvCache[cacheKey] = env

        return env

    def _updateTemplateGlobals(self, values: dict):
        """Push values into env.globals -- available in every future render()
        of this host's templates without threading them through context each
        time (e.g. registering an i18n function once). Builds the environment
        lazily (like _jinja2Env/_renderTemplate) if it doesn't exist yet."""
        self._jinja2Env.globals.update(values)

    def _renderTemplate(self, templateName: str, **context) -> bytes:
        """Render templateName (relative to _templateDirectory) with context,
        encoded as utf-8 bytes."""
        return self._jinja2Env.get_template(templateName).render(**context).encode('utf-8')
