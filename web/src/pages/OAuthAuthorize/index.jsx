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

import React, { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { API, getLogo, getSystemName, showError } from '../../helpers';
import Loading from '../../components/common/ui/Loading';
import { Card, Empty } from '@douyinfe/semi-ui';
import {
  IllustrationNoResult,
  IllustrationNoResultDark,
} from '@douyinfe/semi-illustrations';

const OAuthAuthorizePage = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [user, setUser] = useState(null);

  const logo = getLogo();
  const systemName = getSystemName();
  const currentPath = `${location.pathname}${location.search}`;
  const redirectURI = (searchParams.get('redirect_uri') || '').trim();
  const responseType = searchParams.get('response_type') || '';
  const state = searchParams.get('state') || '';
  const clientID = (searchParams.get('client_id') || '').trim();
  const scope = (searchParams.get('scope') || '').trim();
  const codeChallenge = (searchParams.get('code_challenge') || '').trim();
  const codeChallengeMethod = searchParams.get('code_challenge_method') || '';
  const idTokenAddOrganizations =
    searchParams.get('id_token_add_organizations') || '';
  const codexCliSimplifiedFlow =
    searchParams.get('codex_cli_simplified_flow') || '';
  const originator = searchParams.get('originator') || '';

  const scopes = useMemo(() => {
    const items = scope.split(/\s+/).filter(Boolean);
    if (items.length > 0) {
      return items;
    }
    return ['openid', 'profile', 'email'];
  }, [scope]);

  useEffect(() => {
    if (!redirectURI) {
      setError(t('缺少 redirect_uri 参数'));
      setLoading(false);
      return;
    }

    let active = true;
    const loadContext = async () => {
      try {
        const res = await API.get('/api/oauth/authorize/context', {
          skipErrorHandler: true,
        });
        const { success, data, message } = res.data;
        if (!active) {
          return;
        }
        if (!success) {
          const next = new URLSearchParams();
          next.set('continue_to', currentPath);
          if (message) {
            next.set('auth_message', message);
          }
          navigate(`/login?${next.toString()}`, { replace: true });
          return;
        }
        setUser(data || null);
      } catch (err) {
        if (!active) {
          return;
        }
        showError(err?.message || t('加载授权信息失败'));
        setError(t('加载授权信息失败'));
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    loadContext();
    return () => {
      active = false;
    };
  }, [currentPath, navigate, redirectURI, t]);

  if (loading) {
    return <Loading size='large' />;
  }

  if (error) {
    return (
      <div className='min-h-screen flex items-center justify-center p-6 bg-slate-50'>
        <Empty
          image={<IllustrationNoResult style={{ width: 220, height: 220 }} />}
          darkModeImage={
            <IllustrationNoResultDark style={{ width: 220, height: 220 }} />
          }
          title={t('无法完成授权')}
          description={error}
        />
      </div>
    );
  }

  const displayName = (user?.display_name || '').trim() || '-';
  const email = (user?.email || '').trim() || '-';
  const username = (user?.username || '').trim() || '-';
  const clientLabel = clientID || '-';

  return (
    <div className='min-h-screen bg-[radial-gradient(circle_at_top,#e0f2fe,transparent_35%),linear-gradient(180deg,#f8fafc_0%,#eef2ff_100%)] px-4 py-12'>
      <div className='mx-auto w-full max-w-2xl'>
        <div className='mb-6 flex items-center justify-center gap-3'>
          <img src={logo} alt='Logo' className='h-12 rounded-2xl shadow-sm' />
          <div className='text-left'>
            <div className='text-xs font-medium uppercase tracking-[0.2em] text-slate-500'>
              Codex OAuth
            </div>
            <div className='text-2xl font-semibold text-slate-900'>
              {systemName}
            </div>
          </div>
        </div>

        <Card className='border-0 !rounded-3xl shadow-[0_24px_80px_rgba(15,23,42,0.12)] overflow-hidden'>
          <div className='space-y-6 p-2'>
            <div>
              <div className='text-sm font-medium uppercase tracking-[0.18em] text-sky-700'>
                {t('授权确认')}
              </div>
              <h1 className='mt-2 text-3xl font-semibold text-slate-900'>
                {t('确认允许 Codex 访问此账户')}
              </h1>
              <p className='mt-2 text-base leading-7 text-slate-600'>
                {t('请确认本次授权请求使用的账户信息，并选择继续或取消。')}
              </p>
            </div>

            <div className='rounded-3xl border border-slate-200 bg-slate-50/90 p-5'>
              <div className='grid gap-4 md:grid-cols-[9rem_1fr] md:items-start'>
                <div className='text-sm font-medium text-slate-500'>
                  {t('用户名')}
                </div>
                <div className='text-sm text-slate-900'>{username}</div>

                <div className='text-sm font-medium text-slate-500'>
                  {t('显示名称')}
                </div>
                <div className='text-sm text-slate-900'>{displayName}</div>

                <div className='text-sm font-medium text-slate-500'>
                  {t('邮箱')}
                </div>
                <div className='text-sm text-slate-900'>{email}</div>

                <div className='text-sm font-medium text-slate-500'>
                  Client ID
                </div>
                <div className='text-sm text-slate-900'>
                  <code className='rounded-lg bg-sky-100 px-2 py-1 text-sky-900'>
                    {clientLabel}
                  </code>
                </div>
              </div>
            </div>

            <div className='rounded-3xl border border-slate-200 bg-white p-5'>
              <div className='text-sm font-medium text-slate-500'>
                {t('请求的权限范围')}
              </div>
              <div className='mt-3 flex flex-wrap gap-2'>
                {scopes.map((item) => (
                  <span
                    key={item}
                    className='rounded-full border border-sky-200 bg-sky-50 px-3 py-1 text-sm text-sky-900'
                  >
                    {item}
                  </span>
                ))}
              </div>
            </div>

            <form method='post' action='/oauth/authorize' className='space-y-4'>
              <input type='hidden' name='response_type' value={responseType} />
              <input type='hidden' name='redirect_uri' value={redirectURI} />
              <input type='hidden' name='state' value={state} />
              <input type='hidden' name='client_id' value={clientID} />
              <input type='hidden' name='scope' value={scope} />
              <input type='hidden' name='code_challenge' value={codeChallenge} />
              <input
                type='hidden'
                name='code_challenge_method'
                value={codeChallengeMethod}
              />
              <input
                type='hidden'
                name='id_token_add_organizations'
                value={idTokenAddOrganizations}
              />
              <input
                type='hidden'
                name='codex_cli_simplified_flow'
                value={codexCliSimplifiedFlow}
              />
              <input type='hidden' name='originator' value={originator} />

              <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-end'>
                <button
                  type='submit'
                  name='action'
                  value='cancel'
                  className='inline-flex min-h-11 items-center justify-center rounded-full border border-slate-300 bg-white px-5 text-sm font-medium text-slate-700 transition hover:bg-slate-50'
                >
                  {t('取消')}
                </button>
                <button
                  type='submit'
                  name='action'
                  value='approve'
                  className='inline-flex min-h-11 items-center justify-center rounded-full bg-slate-950 px-5 text-sm font-medium text-white transition hover:bg-slate-800'
                >
                  {t('确认授权')}
                </button>
              </div>
            </form>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default OAuthAuthorizePage;
