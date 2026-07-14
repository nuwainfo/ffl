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

import base64

from http import HTTPStatus
from typing import Mapping, Optional

import requests

from bases.Kernel import getLogger
from bases.Session import AuthRateLimiter, DownloadSessionStore
from bases.views import BaseController, BaseView, HTTPResult

logger = getLogger(__name__)


class RecipientAuthController(BaseController):
    """
    Recipient-auth decisions (pickup code / pubkey proof / email OTP / session
    cookie) for one ShareSession. Pure logic — builds HTTPResult values, never
    touches a socket or a BaseHTTPRequestHandler, so it can be tested without
    spinning up a real HTTP server.
    """

    @staticmethod
    def _parseCookie(headers: Mapping[str, str], name: str) -> Optional[str]:
        cookieHeader = headers.get('Cookie', '')
        for part in cookieHeader.split(';'):
            key, _, value = part.strip().partition('=')
            if key.strip() == name:
                return value.strip()

        return None

    def _buildAuthFailureResult(self, message: bytes) -> HTTPResult:
        return HTTPResult(status=HTTPStatus.UNAUTHORIZED, body=message)

    def _buildRateLimitExceededResult(self) -> HTTPResult:
        return HTTPResult(
            status=HTTPStatus.TOO_MANY_REQUESTS,
            body=b'Too many failed attempts. Try again in 5 minutes.',
            headers={'Retry-After': str(AuthRateLimiter.LOCKOUT_DURATION)},
        )

    def _buildAuthSessionResult(self, headers: Mapping[str, str]) -> HTTPResult:
        """Create a download session or reuse the caller's existing valid session.

        Keeps browser-side auth retries idempotent: if the same client already
        holds a valid ffl_dlk cookie, return 204 again instead of failing with
        an "already claimed" error. A different client without that cookie still
        cannot claim the single-use session after the first successful auth.
        """
        existingDlk = self._parseCookie(headers, 'ffl_dlk')
        if existingDlk and self.session.downloadSessionStore.validate(existingDlk):
            return self._buildNoContentResult()

        try:
            dlk = self.session.downloadSessionStore.create()
        except RuntimeError:
            return self._buildAuthFailureResult(b'Pickup already claimed.')

        return HTTPResult(
            status=HTTPStatus.NO_CONTENT,
            headers={
                'Set-Cookie': (
                    f'ffl_dlk={dlk}; HttpOnly; Secure; SameSite=Strict; '
                    f'Max-Age={DownloadSessionStore.SESSION_TTL}; Path=/'
                )
            },
        )

    def _verifyEmailOTP(self, email: str, otp: str, link: str) -> bool:
        """Verify email OTP by calling the FFL OTP verification API.

        The Python P2P server acts as a proxy: the browser sends the OTP it
        received via email, and the server forwards it to the FFL API for
        cryptographic verification.
        """
        recipientAuth = self.session.config.recipientAuth
        if not email or not otp or not recipientAuth or not recipientAuth.otpVerifyUrl:
            return False

        if not recipientAuth.isAllowedEmail(email):
            return False

        try:
            resp = requests.post(
                recipientAuth.otpVerifyUrl, json={
                    'email': email,
                    'otp': otp,
                    'link': link or ''
                }, timeout=10
            )
            return resp.ok and bool(resp.json().get('verificationToken'))
        except Exception as e:
            logger.warning(f'Email OTP verification failed: {e}')
            return False

    def requestEmailOTP(self, data: dict) -> HTTPResult:
        """POST /{uid}/email/request — proxy OTP send request to FFL API (avoids CORS).

        Browser posts {email, link} to the same-origin P2P server; this forwards
        the request to the FFL API server-side and relays the response.
        """
        recipientAuth = self.session.config.recipientAuth
        if not recipientAuth or not recipientAuth.requiresEmail() or not recipientAuth.otpRequestUrl:
            return HTTPResult(status=HTTPStatus.BAD_REQUEST, body=b'Email auth not enabled')

        email = data.get('email') or recipientAuth.getPrimaryRecipientEmail()
        if not recipientAuth.isAllowedEmail(email):
            return self._buildJSONResult(
                {'error': 'This email address is not allowed to download this file.'},
                status=HTTPStatus.FORBIDDEN,
            )

        link = data.get('link', '')
        language = data.get('language')
        try:
            resp = requests.post(
                recipientAuth.otpRequestUrl, json={
                    'email': email,
                    'link': link,
                    'language': language
                }, timeout=10
            )
            return HTTPResult(status=resp.status_code, body=resp.content, contentType='application/json; charset=utf-8')
        except Exception as e:
            logger.warning(f'Email OTP request proxy failed: {e}')
            return HTTPResult(status=HTTPStatus.BAD_GATEWAY, body=b'Failed to reach OTP service')

    def handleAuthExchange(self, headers: Mapping[str, str], data: dict) -> HTTPResult:
        """POST /{uid}/auth — exchange X-FFL-* credentials for a download session cookie.

        On success: 204 No Content (+ Set-Cookie when a session is created).
        On failure: 401 Unauthorized.
        """
        recipientAuth = self.session.config.recipientAuth
        if not recipientAuth or not recipientAuth.isEnabled():
            return self._buildNoContentResult()

        rateLimiter = self.session.authRateLimiter
        code = headers.get('X-FFL-Pickup')
        proof = headers.get('X-FFL-Proof')
        emailOtp = headers.get('X-FFL-EmailOTP')
        emailAddr = headers.get('X-FFL-EmailAddress')
        emailLink = headers.get('X-FFL-EmailLink')
        verifyParam = data.get('verify')

        # Check lockout before touching verify: verification can be expensive (RSA
        # proof check) or reach out to an external service (email OTP), and a locked
        # authType should not pay that cost — or let a lucky guess bypass the lockout
        # — on every hammered attempt.
        if verifyParam == 'code':
            if rateLimiter.isLocked('pickup'):
                return self._buildRateLimitExceededResult()
                
            if recipientAuth.verifyCode(code):
                rateLimiter.recordSuccess('pickup')
                return self._buildNoContentResult()
                
            rateLimiter.recordFailure('pickup')
            return self._buildAuthFailureResult(b'Invalid pickup code.')

        if verifyParam == 'proof':
            if rateLimiter.isLocked('pubkey'):
                return self._buildRateLimitExceededResult()
                
            if recipientAuth.verifyProof(proof):
                rateLimiter.recordSuccess('pubkey')
                return self._buildNoContentResult()
                
            rateLimiter.recordFailure('pubkey')
            return self._buildAuthFailureResult(b'Invalid pubkey proof.')

        if recipientAuth.requiresEmail():
            if rateLimiter.isLocked('email'):
                return self._buildRateLimitExceededResult()
                
            if self._verifyEmailOTP(emailAddr or recipientAuth.getPrimaryRecipientEmail(), emailOtp, emailLink):
                rateLimiter.recordSuccess('email')
                return self._buildAuthSessionResult(headers)
                
            rateLimiter.recordFailure('email')
            return self._buildAuthFailureResult(b'Invalid or expired email OTP.')

        authType = recipientAuth.mode.value
        if rateLimiter.isLocked(authType):
            return self._buildRateLimitExceededResult()
            
        if recipientAuth.verify(code=code, proof=proof):
            rateLimiter.recordSuccess(authType)
            return self._buildAuthSessionResult(headers)
            
        rateLimiter.recordFailure(authType)
        
        return self._buildAuthFailureResult(b'Invalid credentials.')

    def verifyDownloadRequest(self, headers: Mapping[str, str]) -> Optional[HTTPResult]:
        """Verify recipient credentials via session cookie or X-FFL-* headers.

        Accepts either:
        - ffl_dlk cookie (browser path — set after POST /auth)
        - X-FFL-Pickup / X-FFL-Proof headers (curl / CLI path)

        Returns None if the request may proceed, or the HTTPResult to send on failure.
        """
        recipientAuth = self.session.config.recipientAuth
        if not recipientAuth or not recipientAuth.isEnabled():
            return None

        # Cookie-based session (browser <a href> fallback path) — bypasses rate limit
        dlk = self._parseCookie(headers, 'ffl_dlk')
        if dlk and self.session.downloadSessionStore.validate(dlk):
            return None

        rateLimiter = self.session.authRateLimiter
        authType = recipientAuth.mode.value

        # Check lockout before verifying: a locked authType must not still pay for
        # verification (RSA proof check, or an external email-OTP API call) on every
        # hammered attempt, nor let a lucky guess bypass the lockout.
        if rateLimiter.isLocked(authType):
            return self._buildRateLimitExceededResult()

        # Direct header auth (curl / CLI path)
        if recipientAuth.requiresEmail():
            emailOtp = headers.get('X-FFL-EmailOTP')
            emailAddr = headers.get('X-FFL-EmailAddress') or recipientAuth.getPrimaryRecipientEmail()
            emailLink = headers.get('X-FFL-EmailLink')
            ok = self._verifyEmailOTP(emailAddr, emailOtp, emailLink)
        else:
            code = headers.get('X-FFL-Pickup')
            proof = headers.get('X-FFL-Proof')
            ok = recipientAuth.verify(code=code, proof=proof)

        if ok:
            rateLimiter.recordSuccess(authType)
            return None

        rateLimiter.recordFailure(authType)
        return self._buildAuthFailureResult(b'Invalid or missing credentials.')

    def getTemplateContext(self) -> dict:
        """Recipient-auth keys for the /static/index.html template context."""
        recipientAuth = self.session.config.recipientAuth
        pubkeyChallenges = []
        if recipientAuth and recipientAuth.requiresPubkey():
            pubkeyChallenges = [
                base64.b64encode(challengeCiphertext).decode('ascii')
                for challengeCiphertext in recipientAuth.getChallengeCiphertexts()
            ]

        return {
            'pickupRequired': bool(recipientAuth and recipientAuth.requiresPickup()),
            'pubkeyRequired': bool(recipientAuth and recipientAuth.requiresPubkey()),
            'pubkeyChallenges': pubkeyChallenges,
            'emailRequired': bool(recipientAuth and recipientAuth.requiresEmail()),
            'recipientEmails': list(recipientAuth.recipientEmails) if recipientAuth else [],
        }


class RecipientAuthView(BaseView):
    """Mounts POST /auth and guards GET /download + GET /offer with recipient auth."""

    controller = RecipientAuthController

    _GUARDED_PATHS = ('/download', '/offer')

    def mount(self, mapHEADRoute, mapGETRoute, mapPOSTRoute):
        self._registerRoute(mapPOSTRoute, '/auth', self.handleAuth)
        self._registerRoute(mapPOSTRoute, '/email/request', self.handleEmailOTPRequest)

    def handleAuth(self, data, *, controller):
        result = controller.handleAuthExchange(headers=self.headers, data=data)
        self.sendHTTPResult(result)

    def handleEmailOTPRequest(self, data, *, controller):
        result = controller.requestEmailOTP(data)
        self.sendHTTPResult(result)

    def _checkAccess(self, path, args, *, controller) -> Optional[HTTPResult]:
        if path not in self._GUARDED_PATHS:
            return None

        return controller.verifyDownloadRequest(headers=self.headers)
