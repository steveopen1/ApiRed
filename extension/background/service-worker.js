/**
 * ApiRed Background Service Worker
 * 处理扩展后台逻辑,协调content script和popup通信
 */

const DEFAULT_CONFIG = {
  isCapturing: false,
  maxPerDomain: 500,
  maxBodySize: 100 * 1024,
  domainFilter: {
    mode: 'blacklist',
    domains: []
  },
  proxy: {
    enabled: false,
    host: '127.0.0.1',
    port: 8080
  }
};

let config = { ...DEFAULT_CONFIG };
let currentSession = null;

// 初始化
chrome.runtime.onInstalled.addListener(() => {
  console.log('ApiRed Extension installed');
  chrome.storage.local.get(['config'], (result) => {
    if (result.config) {
      config = { ...DEFAULT_CONFIG, ...result.config };
    }
  });
});

// 监听来自popup的消息
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'GET_STATUS':
      sendResponse({ isCapturing: config.isCapturing });
      break;
    
    case 'TOGGLE_CAPTURE':
      config.isCapturing = message.isCapturing;
      saveConfig();
      broadcastToContentScripts({ type: 'CAPTURE_STATE', isCapturing: config.isCapturing });
      sendResponse({ success: true, isCapturing: config.isCapturing });
      break;
    
    case 'GET_CAPTURES':
      getCapturesForTab(message.domain, message.limit)
        .then(captures => sendResponse({ captures }))
        .catch(err => sendResponse({ error: err.message }));
      return true;
    
    case 'GET_STATS':
      getStatsForTab(message.domain)
        .then(stats => sendResponse({ stats }))
        .catch(err => sendResponse({ error: err.message }));
      return true;
    
    case 'CLEAR_CAPTURES':
      clearCapturesForTab(message.domain)
        .then(() => sendResponse({ success: true }))
        .catch(err => sendResponse({ error: err.message }));
      return true;
    
    case 'EXPORT_HAR':
      exportHAR(message.domain)
        .then(har => sendResponse({ har }))
        .catch(err => sendResponse({ error: err.message }));
      return true;
    
    case 'CAPTURE_API':
      handleCapturedAPI(message.capture, sender.tab)
        .then(() => sendResponse({ success: true }))
        .catch(err => sendResponse({ error: err.message }));
      return true;
    
    case 'GET_CONFIG':
      sendResponse({ config });
      break;
    
    case 'UPDATE_CONFIG':
      config = { ...config, ...message.config };
      saveConfig();
      sendResponse({ success: true, config });
      break;
    
    default:
      sendResponse({ error: 'Unknown message type' });
  }
});

// 保存配置到storage
function saveConfig() {
  chrome.storage.local.set({ config });
}

// 广播消息到所有content scripts
function broadcastToContentScripts(message) {
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, message).catch(() => {});
      }
    });
  });
}

// 获取指定域名的捕获数据
async function getCapturesForTab(domain, limit = 100) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(['captures'], (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
        return;
      }
      const captures = result.captures || {};
      const domainCaptures = captures[domain] || [];
      resolve(domainCaptures.slice(-limit).reverse());
    });
  });
}

// 获取指定域名的统计信息
async function getStatsForTab(domain) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(['captures', 'stats'], (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
        return;
      }
      const captures = result.captures || {};
      const domainCaptures = captures[domain] || [];
      const stats = result.stats || {};
      const domainStats = stats[domain] || { total: 0, apis: 0, sensitive: 0 };
      
      resolve({
        totalRequests: domainCaptures.length,
        apiEndpoints: domainStats.apis,
        sensitiveEndpoints: domainStats.sensitive
      });
    });
  });
}

// 清空指定域名的捕获数据
async function clearCapturesForTab(domain) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(['captures', 'stats'], (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
        return;
      }
      const captures = result.captures || {};
      const stats = result.stats || {};
      delete captures[domain];
      delete stats[domain];
      chrome.storage.local.set({ captures, stats }, () => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve();
        }
      });
    });
  });
}

// 导出HAR格式
async function exportHAR(domain) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(['captures'], (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
        return;
      }
      const captures = result.captures || {};
      const domainCaptures = domain ? (captures[domain] || []) : Object.values(captures).flat();
      
      const har = {
        log: {
          version: '1.2',
          creator: {
            name: 'ApiRed Extension',
            version: '4.0.0'
          },
          entries: domainCaptures.map(c => ({
            startedDateTime: new Date(c.timestamp).toISOString(),
            time: c.duration || 0,
            request: {
              method: c.method,
              url: c.url,
              httpVersion: 'HTTP/1.1',
              headers: Object.entries(c.requestHeaders || {}).map(([name, value]) => ({ name, value: String(value) })),
              queryString: [],
              cookies: [],
              headersSize: -1,
              bodySize: c.requestBody ? c.requestBody.length : 0,
              postData: c.requestBody ? {
                mimeType: c.requestHeaders?.['content-type'] || 'application/octet-stream',
                text: c.requestBody
              } : undefined
            },
            response: {
              status: c.responseStatus,
              statusText: '',
              httpVersion: 'HTTP/1.1',
              headers: Object.entries(c.responseHeaders || {}).map(([name, value]) => ({ name, value: String(value) })),
              cookies: [],
              content: {
                size: c.responseBody ? c.responseBody.length : 0,
                mimeType: c.responseHeaders?.['content-type'] || 'application/octet-stream',
                text: c.responseBody || ''
              },
              redirectURL: '',
              headersSize: -1,
              bodySize: c.responseBody ? c.responseBody.length : 0
            },
            cache: {},
            timings: {
              send: 0,
              wait: c.duration || 0,
              receive: 0
            }
          }))
        }
      };
      
      resolve(JSON.stringify(har, null, 2));
    });
  });
}

// 处理捕获的API
async function handleCapturedAPI(capture, tab) {
  const domain = new URL(capture.url).hostname;
  
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(['captures', 'stats'], (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
        return;
      }
      
      const captures = result.captures || {};
      const stats = result.stats || {};
      
      if (!captures[domain]) {
        captures[domain] = [];
      }
      if (!stats[domain]) {
        stats[domain] = { total: 0, apis: 0, sensitive: 0 };
      }
      
      captures[domain].push(capture);
      stats[domain].total++;
      
      if (isAPIPath(capture.url)) {
        stats[domain].apis++;
      }
      if (isSensitivePath(capture.url)) {
        stats[domain].sensitive++;
        capture.isSensitive = true;
      }
      
      if (captures[domain].length > config.maxPerDomain) {
        captures[domain] = captures[domain].slice(-config.maxPerDomain);
      }
      
      chrome.storage.local.set({ captures, stats }, () => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve();
        }
      });
    });
  });
}

// 判断是否为API路径
function isAPIPath(url) {
  const apiPatterns = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/gql/', '/rpc/'];
  const lowerUrl = url.toLowerCase();
  return apiPatterns.some(p => lowerUrl.includes(p));
}

// 判断是否为敏感路径
function isSensitivePath(url) {
  const sensitivePatterns = [
    '/admin', '/login', '/logout', '/auth', '/oauth',
    '/api_keys', '/apikey', '/secret', '/password',
    '/user', '/profile', '/account', '/settings',
    '/upload', '/download', '/debug', '/health',
    '/swagger', '/openapi', '/favicon'
  ];
  const lowerUrl = url.toLowerCase();
  return sensitivePatterns.some(p => lowerUrl.includes(p));
}

// 标签页更新时发送配置
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    chrome.tabs.sendMessage(tabId, {
      type: 'CONFIG_UPDATE',
      config: {
        isCapturing: config.isCapturing,
        maxBodySize: config.maxBodySize,
        domainFilter: config.domainFilter
      }
    }).catch(() => {});
  }
});
