/**
 * ApiRed Content Script - Interceptor
 * 拦截fetch和XHR请求
 */

(function() {
  'use strict';
  
  const CONFIG = {
    isCapturing: false,
    maxBodySize: 100 * 1024,
    domainFilter: {
      mode: 'blacklist',
      domains: []
    }
  };
  
  const EXCLUDED_TYPES = [
    'image/', 'font/', 'style/', 'audio/', 'video/', 
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.woff', '.woff2', '.ttf', '.ico'
  ];
  
  const SENSITIVE_PATTERNS = [
    '/admin', '/login', '/logout', '/auth', '/oauth',
    '/api_keys', '/apikey', '/secret', '/password',
    '/user', '/profile', '/account', '/settings'
  ];
  
  let originalFetch = window.fetch;
  let originalXHROpen = XMLHttpRequest.prototype.open;
  let originalXHRSend = XMLHttpRequest.prototype.send;
  
  function shouldCapture(url) {
    if (!CONFIG.isCapturing) return false;
    
    try {
      const parsed = new URL(url);
      
      if (CONFIG.domainFilter.mode === 'blacklist') {
        if (CONFIG.domainFilter.domains.includes(parsed.hostname)) {
          return false;
        }
      } else {
        if (!CONFIG.domainFilter.domains.includes(parsed.hostname)) {
          return false;
        }
      }
      
      for (const type of EXCLUDED_TYPES) {
        if (parsed.pathname.toLowerCase().includes(type)) {
          return false;
        }
      }
      
      return true;
    } catch {
      return false;
    }
  }
  
  function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  }
  
  function truncateBody(body, maxSize) {
    if (!body) return undefined;
    if (typeof body === 'string') {
      return body.length > maxSize ? body.substr(0, maxSize) : body;
    }
    return body;
  }
  
  function extractHeaders(xhr) {
    const headers = {};
    const headerStr = xhr.getAllResponseHeaders();
    if (headerStr) {
      const headerLines = headerStr.split('\r\n');
      for (const line of headerLines) {
        const idx = line.indexOf(': ');
        if (idx > 0) {
          const name = line.substring(0, idx).toLowerCase();
          const value = line.substring(idx + 2);
          headers[name] = value;
        }
      }
    }
    return headers;
  }
  
  async function captureRequest(requestInfo) {
    const capture = {
      id: generateId(),
      url: requestInfo.url,
      method: requestInfo.method,
      requestHeaders: requestInfo.headers,
      requestBody: truncateBody(requestInfo.body, CONFIG.maxBodySize),
      responseStatus: 0,
      responseHeaders: {},
      responseBody: undefined,
      timestamp: Date.now(),
      duration: 0,
      isSensitive: isSensitivePath(requestInfo.url)
    };
    
    try {
      chrome.runtime.sendMessage({
        type: 'CAPTURE_API',
        capture: capture
      });
    } catch (e) {
      console.error('ApiRed: Failed to send capture', e);
    }
  }
  
  function isSensitivePath(url) {
    const lower = url.toLowerCase();
    return SENSITIVE_PATTERNS.some(p => lower.includes(p));
  }
  
  function patchFetch() {
    window.fetch = async function(input, init = {}) {
      const requestInfo = {
        url: typeof input === 'string' ? input : input.url,
        method: init.method || (typeof input === 'object' ? input.method : 'GET') || 'GET',
        headers: {},
        body: init.body
      };
      
      if (init.headers) {
        if (init.headers instanceof Headers) {
          init.headers.forEach((value, key) => {
            requestInfo.headers[key.toLowerCase()] = value;
          });
        } else if (Array.isArray(init.headers)) {
          init.headers.forEach(([key, value]) => {
            requestInfo.headers[key.toLowerCase()] = value;
          });
        } else {
          Object.assign(requestInfo.headers, init.headers);
        }
      }
      
      if (shouldCapture(requestInfo.url)) {
        const startTime = Date.now();
        try {
          const response = await originalFetch.apply(this, arguments);
          
          requestInfo.responseStatus = response.status;
          response.headers.forEach((value, key) => {
            requestInfo.headers[key.toLowerCase()] = value;
          });
          
          const capture = {
            id: generateId(),
            url: requestInfo.url,
            method: requestInfo.method,
            requestHeaders: requestInfo.headers,
            requestBody: truncateBody(requestInfo.body, CONFIG.maxBodySize),
            responseStatus: response.status,
            responseHeaders: {},
            timestamp: startTime,
            duration: Date.now() - startTime,
            isSensitive: isSensitivePath(requestInfo.url)
          };
          
          response.headers.forEach((value, key) => {
            capture.responseHeaders[key.toLowerCase()] = value;
          });
          
          const contentType = capture.responseHeaders['content-type'] || '';
          if (!contentType.includes('image') && !contentType.includes('font')) {
            try {
              const clone = response.clone();
              const text = await clone.text();
              capture.responseBody = truncateBody(text, CONFIG.maxBodySize);
            } catch {}
          }
          
          chrome.runtime.sendMessage({
            type: 'CAPTURE_API',
            capture: capture
          }).catch(() => {});
          
          return response;
        } catch (error) {
          throw error;
        }
      }
      
      return originalFetch.apply(this, arguments);
    };
  }
  
  function patchXHR() {
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      this._apired_request = {
        url: url,
        method: method,
        headers: {},
        startTime: Date.now()
      };
      return originalXHROpen.call(this, method, url, ...rest);
    };
    
    XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
      if (this._apired_request) {
        this._apired_request.headers[name.toLowerCase()] = value;
      }
      return originalXHRSend.call(this, name, value);
    };
    
    XMLHttpRequest.prototype.send = function(body) {
      if (this._apired_request && shouldCapture(this._apired_request.url)) {
        this._apired_request.body = body;
        
        this.addEventListener('load', function() {
          const capture = {
            id: generateId(),
            url: this._apired_request.url,
            method: this._apired_request.method,
            requestHeaders: this._apired_request.headers,
            requestBody: truncateBody(this._apired_request.body, CONFIG.maxBodySize),
            responseStatus: this.status,
            responseHeaders: extractHeaders(this),
            responseBody: truncateBody(this.responseText, CONFIG.maxBodySize),
            timestamp: this._apired_request.startTime,
            duration: Date.now() - this._apired_request.startTime,
            isSensitive: isSensitivePath(this._apired_request.url)
          };
          
          chrome.runtime.sendMessage({
            type: 'CAPTURE_API',
            capture: capture
          }).catch(() => {});
        });
        
        this.addEventListener('error', function() {
          const capture = {
            id: generateId(),
            url: this._apired_request.url,
            method: this._apired_request.method,
            requestHeaders: this._apired_request.headers,
            requestBody: truncateBody(this._apired_request.body, CONFIG.maxBodySize),
            responseStatus: 0,
            responseHeaders: {},
            responseBody: undefined,
            timestamp: this._apired_request.startTime,
            duration: Date.now() - this._apired_request.startTime,
            isSensitive: isSensitivePath(this._apired_request.url),
            error: 'Network Error'
          };
          
          chrome.runtime.sendMessage({
            type: 'CAPTURE_API',
            capture: capture
          }).catch(() => {});
        });
      }
      
      return originalXHRSend.call(this, body);
    };
  }
  
  function init() {
    patchFetch();
    patchXHR();
    
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => {
      if (response) {
        CONFIG.isCapturing = response.isCapturing;
      }
    });
    
    chrome.runtime.onMessage.addListener((message) => {
      if (message.type === 'CAPTURE_STATE') {
        CONFIG.isCapturing = message.isCapturing;
      } else if (message.type === 'CONFIG_UPDATE') {
        CONFIG.isCapturing = message.config.isCapturing;
        CONFIG.maxBodySize = message.config.maxBodySize;
        CONFIG.domainFilter = message.config.domainFilter;
      }
    });
    
    console.log('ApiRed Interceptor initialized');
  }
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
