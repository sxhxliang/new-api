/*
Copyright (C) 2025 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/

import React from 'react';
import { Navigate } from 'react-router-dom';
import { history } from './history';

const loginContinueToStorageKey = 'login_continue_to';

export function normalizeLoginContinueTo(value) {
  const trimmed = (value || '').trim();
  if (!trimmed) {
    return '';
  }
  if (trimmed.startsWith('/oauth/authorize')) {
    return trimmed;
  }
  if (trimmed.startsWith('/codex/device')) {
    return '/codex/device';
  }
  return '';
}

export function storeLoginContinueTo(value) {
  const normalized = normalizeLoginContinueTo(value);
  if (!normalized) {
    sessionStorage.removeItem(loginContinueToStorageKey);
    return '';
  }
  sessionStorage.setItem(loginContinueToStorageKey, normalized);
  return normalized;
}

export function consumeLoginContinueTo() {
  const normalized = normalizeLoginContinueTo(
    sessionStorage.getItem(loginContinueToStorageKey),
  );
  sessionStorage.removeItem(loginContinueToStorageKey);
  return normalized;
}

export function clearLoginContinueTo() {
  sessionStorage.removeItem(loginContinueToStorageKey);
}

export function authHeader() {
  // return authorization header with jwt token
  let user = JSON.parse(localStorage.getItem('user'));

  if (user && user.token) {
    return { Authorization: 'Bearer ' + user.token };
  } else {
    return {};
  }
}

export const AuthRedirect = ({ children }) => {
  if (normalizeLoginContinueTo(new URLSearchParams(window.location.search).get('continue_to'))) {
    return children;
  }

  const user = localStorage.getItem('user');

  if (user) {
    return <Navigate to='/console' replace />;
  }

  return children;
};

function PrivateRoute({ children }) {
  if (!localStorage.getItem('user')) {
    return <Navigate to='/login' state={{ from: history.location }} />;
  }
  return children;
}

export function AdminRoute({ children }) {
  const raw = localStorage.getItem('user');
  if (!raw) {
    return <Navigate to='/login' state={{ from: history.location }} />;
  }
  try {
    const user = JSON.parse(raw);
    if (user && typeof user.role === 'number' && user.role >= 10) {
      return children;
    }
  } catch (e) {
    // ignore
  }
  return <Navigate to='/forbidden' replace />;
}

export { PrivateRoute };
