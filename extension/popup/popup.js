/**
 * ApiRed Popup - React Application
 */

(function() {
  'use strict';
  
  const { useState, useEffect, useCallback } = React || {};
  
  function App() {
    const [isCapturing, setIsCapturing] = useState(false);
    const [domain, setDomain] = useState('');
    const [stats, setStats] = useState({ totalRequests: 0, apiEndpoints: 0, sensitiveEndpoints: 0 });
    const [captures, setCaptures] = useState([]);
    const [selectedCapture, setSelectedCapture] = useState(null);
    const [loading, setLoading] = useState(true);
    
    useEffect(() => {
      initializePopup();
    }, []);
    
    async function initializePopup() {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
          try {
            const url = new URL(tab.url);
            setDomain(url.hostname);
            await loadData(url.hostname);
          } catch {}
        }
        
        const response = await chrome.runtime.sendMessage({ type: 'GET_STATUS' });
        if (response) {
          setIsCapturing(response.isCapturing);
        }
      } catch (e) {
        console.error('Init error:', e);
      } finally {
        setLoading(false);
      }
    }
    
    async function loadData(domain) {
      try {
        const [capturesRes, statsRes] = await Promise.all([
          chrome.runtime.sendMessage({ type: 'GET_CAPTURES', domain, limit: 50 }),
          chrome.runtime.sendMessage({ type: 'GET_STATS', domain })
        ]);
        
        if (capturesRes && capturesRes.captures) {
          setCaptures(capturesRes.captures);
        }
        if (statsRes && statsRes.stats) {
          setStats(statsRes.stats);
        }
      } catch (e) {
        console.error('Load data error:', e);
      }
    }
    
    async function toggleCapture() {
      try {
        const newState = !isCapturing;
        const response = await chrome.runtime.sendMessage({
          type: 'TOGGLE_CAPTURE',
          isCapturing: newState
        });
        if (response && response.success) {
          setIsCapturing(newState);
        }
      } catch (e) {
        console.error('Toggle error:', e);
      }
    }
    
    async function handleExport() {
      try {
        const response = await chrome.runtime.sendMessage({ type: 'EXPORT_HAR', domain });
        if (response && response.har) {
          const blob = new Blob([response.har], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `apired-${domain}-${Date.now()}.har`;
          a.click();
          URL.revokeObjectURL(url);
        }
      } catch (e) {
        console.error('Export error:', e);
      }
    }
    
    async function handleClear() {
      if (!confirm('确定清空所有捕获数据?')) return;
      try {
        await chrome.runtime.sendMessage({ type: 'CLEAR_CAPTURES', domain });
        setCaptures([]);
        setStats({ totalRequests: 0, apiEndpoints: 0, sensitiveEndpoints: 0 });
      } catch (e) {
        console.error('Clear error:', e);
      }
    }
    
    function formatUrl(url) {
      try {
        const parsed = new URL(url);
        return parsed.pathname + parsed.search;
      } catch {
        return url;
      }
    }
    
    function formatBody(body) {
      if (!body) return '(empty)';
      if (body.length > 500) return body.substring(0, 500) + '...';
      return body;
    }
    
    if (loading) {
      return React.createElement('div', { className: 'popup-container' },
        React.createElement('div', { className: 'empty-state' },
          React.createElement('div', { className: 'icon' }, '...')
        )
      );
    }
    
    return React.createElement('div', { className: 'popup-container' },
      React.createElement('div', { className: 'header' },
        React.createElement('h1', null, 'ApiRed'),
        React.createElement('span', { className: 'version' }, 'v4.0')
      ),
      
      React.createElement('div', { className: 'capture-toggle' },
        React.createElement('span', { className: 'label' }, isCapturing ? '捕获中' : '已暂停'),
        React.createElement('label', { className: 'toggle-switch' },
          React.createElement('input', {
            type: 'checkbox',
            checked: isCapturing,
            onChange: toggleCapture
          }),
          React.createElement('span', { className: 'toggle-slider' })
        )
      ),
      
      React.createElement('div', { className: 'stats-panel' },
        React.createElement('div', { className: 'stat-card' },
          React.createElement('div', { className: 'value' }, stats.totalRequests),
          React.createElement('div', { className: 'label' }, '请求数')
        ),
        React.createElement('div', { className: 'stat-card' },
          React.createElement('div', { className: 'value' }, stats.apiEndpoints),
          React.createElement('div', { className: 'label' }, 'API端点')
        ),
        React.createElement('div', { className: 'stat-card' },
          React.createElement('div', { className: 'value' }, stats.sensitiveEndpoints),
          React.createElement('div', { className: 'label' }, '敏感端点')
        )
      ),
      
      domain && React.createElement('div', { className: 'domain-info' }, domain),
      
      React.createElement('div', { className: 'api-list' },
        React.createElement('div', { className: 'api-list-header' },
          `捕获列表 (${captures.length})`
        ),
        captures.length === 0
          ? React.createElement('div', { className: 'empty-state' },
              React.createElement('div', { className: 'icon' }, '( )'),
              React.createElement('p', null, isCapturing ? '浏览网页开始捕获...' : '开启捕获开关开始捕获')
            )
          : captures.map(capture =>
              React.createElement('div', {
                key: capture.id,
                className: `api-item ${capture.isSensitive ? 'sensitive' : ''}`,
                onClick: () => setSelectedCapture(selectedCapture?.id === capture.id ? null : capture)
              },
                React.createElement('span', { className: `api-method ${capture.method.toLowerCase()}` },
                  capture.method
                ),
                React.createElement('span', { className: 'api-path' },
                  formatUrl(capture.url)
                ),
                React.createElement('div', { className: 'api-status' },
                  `${capture.responseStatus || 'pending'} • ${capture.duration || 0}ms`
                )
              )
            )
      ),
      
      selectedCapture && React.createElement('div', { className: 'api-detail-panel show' },
        React.createElement('div', { className: 'detail-header' },
          React.createElement('span', { className: 'detail-title' },
            `${selectedCapture.method} ${formatUrl(selectedCapture.url)}`
          ),
          React.createElement('button', {
            className: 'close-btn',
            onClick: () => setSelectedCapture(null)
          }, '×')
        ),
        React.createElement('div', { className: 'detail-section' },
          React.createElement('h4', null, 'Request Headers'),
          React.createElement('pre', null, JSON.stringify(selectedCapture.requestHeaders || {}, null, 2))
        ),
        selectedCapture.requestBody && React.createElement('div', { className: 'detail-section' },
          React.createElement('h4', null, 'Request Body'),
          React.createElement('pre', null, formatBody(selectedCapture.requestBody))
        ),
        React.createElement('div', { className: 'detail-section' },
          React.createElement('h4', null, 'Response Status'),
          React.createElement('pre', null, `${selectedCapture.responseStatus || 'N/A'}`)
        ),
        selectedCapture.responseBody && React.createElement('div', { className: 'detail-section' },
          React.createElement('h4', null, 'Response Body'),
          React.createElement('pre', null, formatBody(selectedCapture.responseBody))
        )
      ),
      
      React.createElement('div', { className: 'actions' },
        React.createElement('button', { className: 'btn btn-primary', onClick: handleExport }, '导出HAR'),
        React.createElement('button', { className: 'btn btn-danger', onClick: handleClear }, '清空')
      )
    );
  }
  
  function render() {
    const root = document.getElementById('root');
    if (root) {
      ReactDOM.render(React.createElement(App), root);
    }
  }
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', render);
  } else {
    render();
  }
})();
