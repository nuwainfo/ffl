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

import json
import weakref

from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Optional

from bases.Kernel import getLogger
from bases.HTTP import HTTPRequestHandlerHelper, PathResolverMixin, StaticMixin
from bases.Template import TemplateMixin

logger = getLogger(__name__)


@dataclass
class HTTPResult:
    """A pending HTTP response a View wants DownloadHandler to send.

    Only carries headers beyond the two every response needs (Content-type,
    Content-Length) — those are always computed by BaseView.sendHTTPResult().
    """
    status: HTTPStatus
    body: bytes = b''
    headers: dict = field(default_factory=dict)
    contentType: Optional[str] = 'text/plain; charset=utf-8'


class BaseController:
    """
    Base class for a View's business logic. Pure logic — builds HTTPResult
    values, never touches a socket or a BaseHTTPRequestHandler, so subclasses
    can be tested without spinning up a real HTTP server.
    """

    def __init__(self, session):
        self.session = session

    def _buildJSONResult(self, data, status: HTTPStatus = HTTPStatus.OK, headers: dict = None) -> HTTPResult:
        return HTTPResult(
            status=status,
            body=json.dumps(data).encode('utf-8'),
            headers=headers or {},
            contentType='application/json; charset=utf-8',
        )

    def _buildNoContentResult(self) -> HTTPResult:
        return HTTPResult(status=HTTPStatus.NO_CONTENT)

    def _buildNotFoundResult(self, message: str = None) -> HTTPResult:
        if message:
            logger.debug(message)

        return HTTPResult(status=HTTPStatus.NOT_FOUND, body=str(HTTPStatus.NOT_FOUND.value).encode(), contentType='text/html')

    def getTemplateContext(self, **kwargs) -> dict:
        return {}


class ViewsHelper(StaticMixin, TemplateMixin, HTTPRequestHandlerHelper):
    """
    Shared utilities for DownloadHandler itself — raw request/response
    primitives (self.send_response/send_header/end_headers/wfile) plus generic
    query-param parsing (HTTPRequestHandlerHelper, see bases.HTTP) and Jinja2
    template rendering (TemplateMixin, see bases.Template). Mixed in via
    ViewsMixin(ViewsHelper) so these become DownloadHandler's own native
    methods; ViewsHelperAdapter gives Views the same interface by delegating
    to self.handler instead of implementing it again.
    """

    def sendHTTPResult(self, result: HTTPResult):
        self.send_response(result.status)

        if result.contentType:
            self.send_header('Content-type', result.contentType)

        for header, value in result.headers.items():
            self.send_header(header, value)

        self.send_header('Content-Length', str(len(result.body)))
        self.end_headers()

        if result.body:
            self.wfile.write(result.body)


class ViewsHelperAdapter:
    """
    Gives a View the same interface as ViewsHelper (and its superclasses
    StaticMixin/TemplateMixin/HTTPRequestHandlerHelper) without owning a
    socket itself: any name defined anywhere in ViewsHelper's MRO, and not
    otherwise found on this instance, resolves to
    self.handler's own attribute of that name — not a wrapper that calls it,
    so e.g. self._handleForbiddenHead IS self.handler._handleForbiddenHead
    (same bound method). That identity is what lets a view mount it directly
    (mapHEADRoute(path, self._handleForbiddenHead)) and still satisfy
    DownloadHandler._checkPathForbidden()'s identity comparison. Assumes the
    host class provides a `handler` property.
    """

    _DELEGATED_NAMES = frozenset(
        name
        for klass in ViewsHelper.__mro__
        if klass is not object
        for name in vars(klass)
        if not name.startswith('__')
    )

    def __getattr__(self, name):
        if name in self._DELEGATED_NAMES:
            return getattr(self.handler, name)

        raise AttributeError(name)


class BaseView(ViewsHelperAdapter):
    """
    Base class for a DownloadHandler feature module: mounts its own routes and
    can gate access to routes DownloadHandler still owns directly.

    Subclasses override mount() to register routes via _registerRoute(mapRoute,
    path, viewMethod) -- mapRoute is one of the mapHEADRoute/mapGETRoute/
    mapPOSTRoute bound methods mount() itself receives -- and/or override
    _checkAccess() to guard a route DownloadHandler still handles itself.

    A View is created once per DownloadHandler instance (one per TCP connection),
    but self.handler.session is only resolved per HTTP request (see
    DownloadHandler.parse_request()), so controllers must be built lazily, never
    cached across requests. checkAccess() and every route registered via
    _registerRoute() handle this the same way: this view's controller (if any)
    is built fresh and passed in as the `controller` keyword argument --
    subclasses never call _makeController() themselves.
    """

    controller = None

    def __init__(self, handler):
        # weakref: DownloadHandler owns its views, not the other way around.
        self._handlerRef = weakref.ref(handler)

    @property
    def handler(self):
        handler = self._handlerRef()
        if handler is None:
            raise RuntimeError("Request handler is no longer alive")

        return handler

    # Explicit handler accessors a View subclass needs — kept separate from
    # ViewsHelperAdapter's dynamic delegation, which is scoped to ViewsHelper's
    # own curated utility set, not DownloadHandler's full attribute surface.
    @property
    def headers(self):
        return self.handler.headers

    @property
    def path(self):
        return self.handler.path

    @property
    def server(self):
        return self.handler.server

    def _checkViewAccess(self, path, args) -> bool:
        return self.handler._checkViewAccess(path, args)

    def send_error(self, code, message=None):
        self.handler.send_error(code, message)

    def _getFileInfo(self, quoteName=True):
        return self.handler._getFileInfo(quoteName=quoteName)

    def _buildDownloadCompleteResponse(self, data):
        return self.handler._buildDownloadCompleteResponse(data)

    def mount(self, mapHEADRoute, mapGETRoute, mapPOSTRoute):
        """Override to register this view's own routes via _registerRoute(mapRoute, path, viewMethod)."""
        pass

    def checkAccess(self, path, args) -> Optional[HTTPResult]:
        """Called by DownloadHandler to guard a route it still owns directly.

        Builds this view's controller (if any) and delegates to _checkAccess() —
        override _checkAccess(), not this method.
        """
        return self._invokeWithController(self._checkAccess, path, args)

    def _checkAccess(self, path, args, **kwargs) -> Optional[HTTPResult]:
        """Override to guard a route DownloadHandler still owns directly.

        Return None to let the request proceed, or an HTTPResult for the caller
        to send instead (short-circuiting the request). If this view declares a
        `controller`, it is injected as the `controller` keyword argument.
        """
        return None

    def contributeTemplateContext(self, args) -> dict:
        """Called by DownloadHandler to add keys to the /static/index.html
        Jinja2 template context. Default: call this view's controller (if any)
        with no arguments.
        """
        controller = self._makeController()
        return controller.getTemplateContext() if controller is not None else {}

    def _makeController(self):
        if self.controller is None:
            return None

        return self.controller(self.handler.session)

    def _invokeWithController(self, func, *args, **kwargs):
        controller = self._makeController()
        if controller is not None:
            kwargs['controller'] = controller

        return func(*args, **kwargs)

    def _registerRoute(self, mapRoute, path, viewMethod):
        def dispatch(*args, **kwargs):
            # do_GET only wraps its own no-handler-found fallback in a
            # try/except, not the case where a handler exists (unlike
            # do_POST, which wraps every dispatched handler) — so a mounted
            # GET/HEAD route must catch its own connection errors here or an
            # unhandled exception propagates out of do_GET uncaught.
            try:
                self._invokeWithController(viewMethod, *args, **kwargs)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                logger.debug(f"Client disconnected in {path} handler")
            except Exception as e:
                logger.exception(f"Error handling {path}: {e}")
                self.handler.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

        mapRoute(path, dispatch)


class ViewsMixin(ViewsHelper, PathResolverMixin):
    """
    Mixin that gives a request-handler class a pluggable set of Views (see
    BaseView above) — feature modules that mount their own routes and/or guard
    routes the handler still owns directly. Path resolution against those
    route tables (self._resolveGETHandler/_resolveHEADHandler/_resolvePOSTHandler)
    is provided by PathResolverMixin (see bases.HTTP).

    Host classes must:
      - declare VIEWS: a tuple of BaseView subclasses
      - call self._mountViews() once self.paths exists (PathResolverMixin.__new__
        already guarantees that before __init__ runs), typically at the end of
        __init__ (BaseHTTPRequestHandler subclasses call super().__init__() to
        serve the connection synchronously, so mounting must happen before that
        call, not via a cooperative __init__)
    """

    VIEWS = ()

    def _mountViews(self):
        self._views = [viewClass(handler=self) for viewClass in self.VIEWS]

        for view in self._views:
            view.mount(self.mapHEADRoute, self.mapGETRoute, self.mapPOSTRoute)

    def _checkViewAccess(self, path, args) -> bool:
        """Return True if every mounted view allows this path; otherwise send the
        first blocking view's response and return False."""
        for view in self._views:
            result = view.checkAccess(path, args)
            if result is not None:
                view.sendHTTPResult(result)
                return False

        return True

    def _collectViewTemplateContext(self, args) -> dict:
        """Merge every mounted view's /static/index.html template-context
        contribution (see BaseView.contributeTemplateContext) into one dict."""
        context = {}
        for view in self._views:
            context.update(view.contributeTemplateContext(args))

        return context
