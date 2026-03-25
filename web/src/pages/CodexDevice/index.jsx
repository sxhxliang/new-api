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
import {
  API,
  getLogo,
  getSystemName,
  showError,
  showInfo,
  showSuccess,
} from '../../helpers';
import Loading from '../../components/common/ui/Loading';
import {
  Button,
  Card,
  Empty,
  Input,
  Table,
  Typography,
} from '@douyinfe/semi-ui';
import {
  IllustrationNoResult,
  IllustrationNoResultDark,
} from '@douyinfe/semi-illustrations';

const { Text } = Typography;

const CodexDevicePage = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [userCode, setUserCode] = useState('');
  const [user, setUser] = useState(null);
  const [deviceCodes, setDeviceCodes] = useState([]);

  const logo = getLogo();
  const systemName = getSystemName();
  const currentPath = `${location.pathname}${location.search}`;

  const columns = useMemo(
    () => [
      {
        title: t('User Code'),
        dataIndex: 'user_code',
        render: (value) => (
          <code className='rounded-lg bg-sky-100 px-2 py-1 text-sky-900'>
            {value}
          </code>
        ),
      },
      {
        title: t('Approved'),
        dataIndex: 'approved',
        render: (value) =>
          value ? (
            <span className='text-emerald-600 font-medium'>{t('Yes')}</span>
          ) : (
            <span className='text-slate-500'>{t('No')}</span>
          ),
      },
      {
        title: t('Polls'),
        dataIndex: 'polls',
      },
    ],
    [t],
  );

  const loadContext = async (showSpinner = false) => {
    if (showSpinner) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    try {
      const res = await API.get('/api/codex/device/context', {
        skipErrorHandler: true,
      });
      const { success, data, message } = res.data;
      if (!success) {
        const next = new URLSearchParams();
        next.set('continue_to', currentPath);
        if (message) {
          next.set('auth_message', message);
        }
        navigate(`/login?${next.toString()}`, { replace: true });
        return false;
      }
      setUser(data?.user || null);
      setDeviceCodes(Array.isArray(data?.device_codes) ? data.device_codes : []);
      return true;
    } catch (err) {
      showError(err?.message || t('加载设备授权信息失败'));
      setError(t('加载设备授权信息失败'));
      return false;
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadContext(false);
  }, [currentPath, navigate, t]);

  useEffect(() => {
    const message = searchParams.get('message');
    if (!message) {
      return;
    }
    showInfo(message);
    const nextSearchParams = new URLSearchParams(searchParams);
    nextSearchParams.delete('message');
    setSearchParams(nextSearchParams, { replace: true });
  }, [searchParams, setSearchParams]);

  const onApprove = async () => {
    const normalized = userCode.trim();
    if (!normalized) {
      showInfo(t('请输入设备码'));
      return;
    }

    setSubmitting(true);
    try {
      const res = await API.post(
        '/api/codex/device/approve',
        { user_code: normalized },
        { skipErrorHandler: true },
      );
      const { success, data, message } = res.data;
      if (!success) {
        showError(message || t('批准设备码失败'));
        return;
      }
      setDeviceCodes(Array.isArray(data?.device_codes) ? data.device_codes : []);
      setUserCode('');
      showSuccess(data?.message || t('已批准设备码'));
    } catch (err) {
      showError(err?.message || t('批准设备码失败'));
    } finally {
      setSubmitting(false);
    }
  };

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
          title={t('无法加载设备授权页')}
          description={error}
        />
      </div>
    );
  }

  const username = (user?.username || '').trim() || '-';

  return (
    <div className='min-h-screen bg-[radial-gradient(circle_at_top,#dbeafe,transparent_32%),linear-gradient(180deg,#f8fafc_0%,#eff6ff_100%)] px-4 py-12'>
      <div className='mx-auto w-full max-w-4xl'>
        <div className='mb-6 flex items-center justify-center gap-3'>
          <img src={logo} alt='Logo' className='h-12 rounded-2xl shadow-sm' />
          <div className='text-left'>
            <div className='text-xs font-medium uppercase tracking-[0.2em] text-slate-500'>
              Codex Device Auth
            </div>
            <div className='text-2xl font-semibold text-slate-900'>
              {systemName}
            </div>
          </div>
        </div>

        <Card className='border-0 !rounded-3xl shadow-[0_24px_80px_rgba(15,23,42,0.12)] overflow-hidden'>
          <div className='space-y-6 p-2'>
            <div className='flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between'>
              <div>
                <div className='text-sm font-medium uppercase tracking-[0.18em] text-sky-700'>
                  {t('设备授权')}
                </div>
                <h1 className='mt-2 text-3xl font-semibold text-slate-900'>
                  {t('批准 Codex CLI 显示的设备码')}
                </h1>
                <p className='mt-2 text-base leading-7 text-slate-600'>
                  {t('当 CLI 输出 user code 后，在这里输入并批准，即可完成当前登录流程。')}
                </p>
              </div>
              <div className='rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600'>
                <div className='font-medium text-slate-900'>{username}</div>
                <div>{t('当前登录账户')}</div>
              </div>
            </div>

            <div className='rounded-3xl border border-slate-200 bg-slate-50/90 p-5'>
              <div className='flex flex-col gap-3 sm:flex-row'>
                <Input
                  value={userCode}
                  onChange={setUserCode}
                  placeholder={t('输入 CLI 打印的 user code')}
                  size='large'
                  onEnterPress={onApprove}
                />
                <Button
                  theme='solid'
                  type='primary'
                  size='large'
                  className='!rounded-full sm:min-w-32'
                  loading={submitting}
                  onClick={onApprove}
                >
                  {t('批准')}
                </Button>
              </div>
            </div>

            <div className='rounded-3xl border border-slate-200 bg-white p-5'>
              <div className='mb-4 flex items-center justify-between gap-3'>
                <div>
                  <div className='text-lg font-semibold text-slate-900'>
                    {t('当前设备码')}
                  </div>
                  <Text type='secondary'>
                    {t('列表会显示当前仍有效的设备授权请求。')}
                  </Text>
                </div>
                <Button
                  theme='outline'
                  type='tertiary'
                  loading={refreshing}
                  onClick={() => loadContext(true)}
                >
                  {t('刷新')}
                </Button>
              </div>

              <Table
                rowKey='device_auth_id'
                columns={columns}
                dataSource={deviceCodes}
                pagination={false}
                empty={
                  <Empty
                    image={
                      <IllustrationNoResult style={{ width: 140, height: 140 }} />
                    }
                    darkModeImage={
                      <IllustrationNoResultDark
                        style={{ width: 140, height: 140 }}
                      />
                    }
                    description={t('当前没有活跃的设备码')}
                  />
                }
              />
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default CodexDevicePage;
