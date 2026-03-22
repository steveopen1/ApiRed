/**
 * ApiRed Options Page - Settings Management
 */

(function() {
  'use strict';
  
  const DEFAULT_CONFIG = {
    domainFilter: {
      mode: 'blacklist',
      domains: []
    },
    maxPerDomain: 500,
    maxBodySize: 100 * 1024,
    autoCleanup: true,
    proxy: {
      enabled: false,
      host: '127.0.0.1',
      port: 8080
    },
    certInstalled: false
  };
  
  let currentConfig = { ...DEFAULT_CONFIG };
  let domains = [];
  
  document.addEventListener('DOMContentLoaded', init);
  
  async function init() {
    await loadSettings();
    setupEventListeners();
    updateUI();
  }
  
  async function loadSettings() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
      if (response && response.config) {
        currentConfig = { ...DEFAULT_CONFIG, ...response.config };
        domains = currentConfig.domainFilter.domains || [];
      }
    } catch (e) {
      console.error('Failed to load settings:', e);
    }
  }
  
  function setupEventListeners() {
    document.getElementById('maxPerDomain').addEventListener('input', (e) => {
      document.getElementById('maxPerDomainValue').textContent = e.target.value;
    });
    
    document.getElementById('maxBodySize').addEventListener('input', (e) => {
      document.getElementById('maxBodySizeValue').textContent = e.target.value + ' KB';
    });
    
    document.getElementById('newDomain').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        addDomain();
      }
    });
  }
  
  function updateUI() {
    document.querySelectorAll('input[name="filterMode"]').forEach(radio => {
      radio.checked = radio.value === currentConfig.domainFilter.mode;
    });
    
    document.getElementById('maxPerDomain').value = currentConfig.maxPerDomain;
    document.getElementById('maxPerDomainValue').textContent = currentConfig.maxPerDomain;
    
    const maxBodySizeKB = Math.round(currentConfig.maxBodySize / 1024);
    document.getElementById('maxBodySize').value = maxBodySizeKB;
    document.getElementById('maxBodySizeValue').textContent = maxBodySizeKB + ' KB';
    
    document.getElementById('autoCleanup').checked = currentConfig.autoCleanup;
    document.getElementById('proxyEnabled').checked = currentConfig.proxy.enabled;
    document.getElementById('proxyHost').value = currentConfig.proxy.host;
    document.getElementById('proxyPort').value = currentConfig.proxy.port;
    
    updateDomainList();
    updateCertStatus();
  }
  
  function updateDomainList() {
    const container = document.getElementById('domainList');
    
    if (domains.length === 0) {
      container.innerHTML = '<span style="color: #666; font-size: 12px;">暂无域名</span>';
      return;
    }
    
    container.innerHTML = domains.map((domain, index) => `
      <span class="domain-tag">
        ${escapeHtml(domain)}
        <button onclick="removeDomain(${index})">&times;</button>
      </span>
    `).join('');
  }
  
  function updateCertStatus() {
    const statusEl = document.getElementById('certStatus');
    if (currentConfig.certInstalled) {
      statusEl.innerHTML = '<span class="status-badge success">已安装</span>';
    } else {
      statusEl.innerHTML = '<span class="status-badge warning">未安装</span>';
    }
  }
  
  window.addDomain = function() {
    const input = document.getElementById('newDomain');
    const domain = input.value.trim().toLowerCase();
    
    if (!domain) {
      showToast('请输入域名', 'error');
      return;
    }
    
    if (!isValidDomain(domain)) {
      showToast('请输入有效的域名', 'error');
      return;
    }
    
    if (domains.includes(domain)) {
      showToast('该域名已存在', 'error');
      return;
    }
    
    domains.push(domain);
    input.value = '';
    updateDomainList();
    showToast('域名已添加', 'success');
  };
  
  window.removeDomain = function(index) {
    if (index >= 0 && index < domains.length) {
      domains.splice(index, 1);
      updateDomainList();
      showToast('域名已移除', 'success');
    }
  };
  
  window.saveSettings = async function() {
    const filterMode = document.querySelector('input[name="filterMode"]:checked').value;
    const maxPerDomain = parseInt(document.getElementById('maxPerDomain').value);
    const maxBodySizeKB = parseInt(document.getElementById('maxBodySize').value);
    const autoCleanup = document.getElementById('autoCleanup').checked;
    const proxyEnabled = document.getElementById('proxyEnabled').checked;
    const proxyHost = document.getElementById('proxyHost').value.trim();
    const proxyPort = parseInt(document.getElementById('proxyPort').value);
    
    const newConfig = {
      domainFilter: {
        mode: filterMode,
        domains: domains
      },
      maxPerDomain: maxPerDomain,
      maxBodySize: maxBodySizeKB * 1024,
      autoCleanup: autoCleanup,
      proxy: {
        enabled: proxyEnabled,
        host: proxyHost || '127.0.0.1',
        port: proxyPort || 8080
      }
    };
    
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'UPDATE_CONFIG',
        config: newConfig
      });
      
      if (response && response.success) {
        currentConfig = newConfig;
        showToast('设置已保存', 'success');
      } else {
        showToast('保存失败', 'error');
      }
    } catch (e) {
      console.error('Failed to save settings:', e);
      showToast('保存失败: ' + e.message, 'error');
    }
  };
  
  window.resetSettings = async function() {
    if (!confirm('确定要重置所有设置为默认值吗?')) {
      return;
    }
    
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'UPDATE_CONFIG',
        config: DEFAULT_CONFIG
      });
      
      if (response && response.success) {
        currentConfig = { ...DEFAULT_CONFIG };
        domains = [];
        updateUI();
        showToast('已重置为默认设置', 'success');
      }
    } catch (e) {
      console.error('Failed to reset settings:', e);
      showToast('重置失败', 'error');
    }
  };
  
  window.installCert = function() {
    showToast('请在Chrome设置中搜索"证书",然后导入mitmproxy证书', 'success');
  };
  
  function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = 'toast show ' + type;
    
    setTimeout(() => {
      toast.className = 'toast';
    }, 3000);
  }
  
  function isValidDomain(domain) {
    const pattern = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
    return pattern.test(domain);
  }
  
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
})();
