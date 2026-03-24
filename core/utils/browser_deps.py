"""
Browser Dependency Installer
Playwright浏览器依赖自动安装器
自动检测并安装Chromium所需的系统依赖
"""

import os
import sys
import subprocess
import logging
import shutil
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


SYSTEM_DEPENDENCIES = {
    'debian': [
        'libglib2.0-0',
        'libnss3',
        'libnspr4',
        'libatk1.0-0',
        'libatk-bridge2.0-0',
        'libatspi2.0-0',
        'libxcomposite1',
        'libxdamage1',
        'libxfixes3',
        'libxrandr2',
        'libgbm1',
        'libpango-1.0-0',
        'libcairo2',
        'libasound2',
        'libxshmfence1',
    ],
    'ubuntu': [
        'libglib2.0-0',
        'libnss3',
        'libnspr4',
        'libatk1.0-0',
        'libatk-bridge2.0-0',
        'libatspi2.0-0',
        'libxcomposite1',
        'libxdamage1',
        'libxfixes3',
        'libxrandr2',
        'libgbm1',
        'libpango-1.0-0',
        'libcairo2',
        'libasound2',
    ],
    'centos': [
        'glibc',
        'nss',
        'nspr',
        'atk',
        'at-spi2-atk',
        'at-spi2-core',
        'libcomposite',
        'libXdamage',
        'libXfixes',
        'libXrandr',
        'gbm',
        'pango',
        'cairo',
        'alsa-lib',
    ],
    'rhel': [
        'glibc',
        'nss',
        'nspr',
        'atk',
        'at-spi2-atk',
        'at-spi2-core',
        'libcomposite',
        'libXdamage',
        'libXfixes',
        'libXrandr',
        'gbm',
        'pango',
        'cairo',
        'alsa-lib',
    ],
    'fedora': [
        'glibc',
        'nss',
        'nspr',
        'atk',
        'at-spi2-atk',
        'at-spi2-core',
        'libcomposite',
        'libXdamage',
        'libXfixes',
        'libXrandr',
        'mesa-libgbm',
        'pango',
        'cairo',
        'alsa-lib',
    ],
    'amzn': [
        'glibc',
        'nss',
        'nspr',
        'atk',
        'at-spi2-atk',
        'at-spi2-core',
        'libcomposite',
        'libXdamage',
        'libXfixes',
        'libXrandr',
        'mesa-libgbm',
        'pango',
        'cairo',
        'alsa-lib',
    ],
}


class DependencyChecker:
    """系统依赖检查器"""
    
    @staticmethod
    def get_os_info() -> Tuple[str, str]:
        """
        获取操作系统信息
        
        Returns:
            (os_name, os_version)
        """
        os_name = sys.platform.lower()
        
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith('ID='):
                        os_id = line.split('=')[1].strip().strip('"')
                        os_name = os_id.lower()
                        break
        
        if 'linux' in os_name:
            if os.path.exists('/etc/debian_version'):
                os_name = 'debian'
            elif os.path.exists('/etc/centos-release'):
                os_name = 'centos'
            elif os.path.exists('/etc/redhat-release'):
                os_name = 'rhel'
        
        return os_name, ''
    
    LIBRARY_NAME_MAPPING = {
        'libglib2.0-0': ['libglib-2.0.so.0', 'libglib-2.0.so', 'libglib2.0.so.0'],
        'libatk1.0-0': ['libatk-1.0.so.0', 'libatk.so.1', 'libatk-1.0.so'],
        'libatk-bridge2.0-0': ['libatk-bridge-2.0.so.0', 'libatk-bridge.so.2', 'libatk-bridge-2.0.so'],
        'libatspi2.0-0': ['libatspi.so.0', 'libatspi-2.0.so.0', 'libatspi.so.2'],
        'libxcomposite1': ['libxcomposite.so.1', 'libxcomposite.so', 'libXcomposite.so.1', 'libXcomposite.so'],
        'libxdamage1': ['libxdamage.so.1', 'libxdamage.so', 'libXdamage.so.1', 'libXdamage.so'],
        'libxfixes3': ['libxfixes.so.3', 'libxfixes.so', 'libXfixes.so.3', 'libXfixes.so'],
        'libxrandr2': ['libxrandr.so.2', 'libxrandr.so', 'libXrandr.so.2', 'libXrandr.so'],
        'libgbm1': ['libgbm.so.1', 'libgbm.so'],
        'libpango-1.0-0': ['libpango-1.0.so.0', 'libpango-1.0.so', 'libpango.so.0'],
        'libcairo2': ['libcairo.so.2', 'libcairo.so'],
        'libasound2': ['libasound.so.2', 'libasound.so', 'libasound.so.1'],
        'libxshmfence1': ['libxshmfence.so.1', 'libxshmfence.so'],
        'libnss3': ['libnss3.so', 'libnss3.so.1'],
        'libnspr4': ['libnspr4.so', 'libnspr4.so.0'],
    }
    
    @staticmethod
    def check_library(library_name: str) -> bool:
        """
        检查系统库是否存在
        
        Args:
            library_name: 库名称 (可以是包名或so名)
            
        Returns:
            是否存在
        """
        result = subprocess.run(
            ['ldconfig', '-p'],
            capture_output=True,
            text=True
        )
        
        ldconfig_output = result.stdout
        
        possible_names = DependencyChecker.LIBRARY_NAME_MAPPING.get(library_name, [library_name])
        
        for name in possible_names:
            if name in ldconfig_output:
                return True
        
        if library_name in ldconfig_output:
            return True
        
        return False
    
    @staticmethod
    def check_command(command: str) -> bool:
        """
        检查命令是否存在
        
        Args:
            command: 命令名称
            
        Returns:
            是否存在
        """
        return shutil.which(command) is not None


class BrowserDependencyInstaller:
    """
    浏览器依赖自动安装器
    
    功能:
    1. 自动检测缺失的系统依赖
    2. 提供安装命令
    3. 支持多种Linux发行版
    """
    
    def __init__(self):
        self.os_name, self.os_version = DependencyChecker.get_os_info()
        self.dependencies = self._get_dependencies()
        self.missing_dependencies: List[str] = []
        self.install_command: str = ""
    
    def _get_dependencies(self) -> List[str]:
        """获取当前系统的依赖列表"""
        for os_key in SYSTEM_DEPENDENCIES:
            if os_key in self.os_name:
                return SYSTEM_DEPENDENCIES[os_key]
        
        return SYSTEM_DEPENDENCIES.get('debian', [])
    
    def check_missing(self) -> List[str]:
        """
        检查缺失的依赖
        
        Returns:
            缺失的依赖列表
        """
        missing = []
        
        for dep in self.dependencies:
            if not DependencyChecker.check_library(dep):
                missing.append(dep)
        
        self.missing_dependencies = missing
        return missing
    
    def generate_install_command(self) -> str:
        """
        生成安装命令
        
        Returns:
            适合当前系统的安装命令
        """
        if not self.missing_dependencies:
            self.check_missing()
        
        packages = ' '.join(self.missing_dependencies)
        
        if self.os_name in ['debian', 'ubuntu']:
            cmd = f"sudo apt-get update && sudo apt-get install -y {packages}"
        elif self.os_name in ['centos', 'rhel', 'fedora']:
            cmd = f"sudo yum install -y {packages}"
        elif self.os_name == 'amzn':
            cmd = f"sudo amazon-linux-extras install -y epel && sudo yum install -y {packages}"
        else:
            cmd = f"# Please install manually: {packages}"
        
        self.install_command = cmd
        return cmd
    
    def get_status_report(self) -> Dict:
        """
        获取状态报告
        
        Returns:
            包含检查结果的字典
        """
        missing = self.check_missing()
        
        return {
            'os': self.os_name,
            'playwright_installed': self._is_playwright_installed(),
            'chromium_installed': self._is_chromium_installed(),
            'missing_dependencies': missing,
            'install_command': self.generate_install_command() if missing else "",
            'can_run_browser': len(missing) == 0 and self._is_chromium_installed()
        }
    
    def _is_playwright_installed(self) -> bool:
        """检查Playwright是否已安装"""
        try:
            import playwright
            return True
        except ImportError:
            return False
    
    def _is_chromium_installed(self) -> bool:
        """检查Chromium是否已安装"""
        try:
            from playwright.sync_api import sync_playwright
            return True
        except ImportError:
            return False
    
    @staticmethod
    def install_deps_automatically() -> Tuple[bool, str]:
        """
        尝试自动安装缺失的依赖
        
        Returns:
            (success, message)
        """
        installer = BrowserDependencyInstaller()
        missing = installer.check_missing()
        
        if not missing:
            return True, "All dependencies are already installed"
        
        cmd = installer.generate_install_command()
        
        logger.info(f"Attempting to install {len(missing)} missing dependencies...")
        
        try:
            if os.geteuid() == 0:
                result = subprocess.run(
                    cmd.split('&&'),
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            else:
                return False, f"Root privileges required. Please run:\n{cmd}"
            
            if result.returncode == 0:
                return True, f"Successfully installed {len(missing)} dependencies"
            else:
                return False, f"Installation failed: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            return False, "Installation timed out"
        except Exception as e:
            return False, f"Installation error: {str(e)}"


def check_and_install_browser_deps() -> Dict:
    """
    检查并安装浏览器依赖的主入口函数
    
    Returns:
        状态报告字典
    """
    installer = BrowserDependencyInstaller()
    return installer.get_status_report()


def auto_install_if_needed() -> bool:
    """
    如果需要且可能，自动安装依赖
    
    Returns:
        是否成功
    """
    installer = BrowserDependencyInstaller()
    missing = installer.check_missing()
    
    if not missing:
        logger.info("All browser dependencies are already installed")
        return True
    
    logger.warning(f"Missing {len(missing)} browser dependencies")
    
    if os.geteuid() == 0:
        success, msg = BrowserDependencyInstaller.install_deps_automatically()
        if success:
            logger.info(msg)
            return True
        else:
            logger.error(msg)
            return False
    else:
        cmd = installer.generate_install_command()
        logger.warning(f"Root privileges required for automatic installation.\nPlease run:\n{cmd}")
        return False
