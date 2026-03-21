#!/usr/bin/env python3
"""
ApiRed - Red Team API Security Scanner
Unified entry point
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import asyncio
from typing import Optional

from core.scanner import ChkApiScanner, ScannerConfig
from core.utils.config import Config
from core.dashboard.web_dashboard import WebDashboard


class CLI:
    """命令行界面"""
    
    def __init__(self):
        self.parser = self._build_parser()
        self.config_obj = Config()
    
    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog='ApiRed',
            description='Red Team API Security Scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  %(prog)s scan -u http://www.example.com
  %(prog)s scan -f targets.txt
  %(prog)s scan -u http://www.example.com -c "session=xxx"
  %(prog)s scan -u http://www.example.com --ai
  %(prog)s dashboard
            '''
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        scan_parser = subparsers.add_parser('scan', help='Run scan')
        
        target_group = scan_parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument('-u', '--url', metavar='URL', help='Single URL to scan')
        target_group.add_argument('-f', '--file', metavar='FILE', help='URL list file')
        
        scan_parser.add_argument('-c', '--cookies', metavar='COOKIES', help='Cookies')
        scan_parser.add_argument('--chrome', choices=['on', 'off'], default='on')
        scan_parser.add_argument('--concurrency', '-cn', type=int, default=50)
        scan_parser.add_argument('--js-depth', type=int, default=3)
        scan_parser.add_argument('--at', '--attack-type', dest='attack_type', choices=['0', '1'], default='0')
        scan_parser.add_argument('--na', '--no-api', dest='no_api', choices=['0', '1'], default='0')
        scan_parser.add_argument('--ai', action='store_true')
        scan_parser.add_argument('--proxy', help='Proxy server')
        scan_parser.add_argument('--output', '-o', help='Output directory')
        scan_parser.add_argument('--format', '-fmt', choices=['json', 'html'], default='json')
        scan_parser.add_argument('--verbose', '-v', action='store_true')
        
        dash_parser = subparsers.add_parser('dashboard', help='Start Web Dashboard')
        dash_parser.add_argument('--host', default='0.0.0.0')
        dash_parser.add_argument('--port', type=int, default=8080)
        
        return parser
    
    def parse_args(self, args=None) -> ScannerConfig:
        parsed = self.parser.parse_args(args)
        
        if parsed.command == 'dashboard':
            return None
        
        target = parsed.url
        
        if parsed.file:
            with open(parsed.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            if targets:
                target = targets[0]
        
        config = ScannerConfig(
            target=target,
            cookies=parsed.cookies or '',
            chrome=(parsed.chrome == 'on'),
            attack_mode='collect' if parsed.attack_type == '1' else 'all',
            no_api_scan=(parsed.no_api == '1'),
            proxy=parsed.proxy,
            js_depth=parsed.js_depth,
            ai_scan=parsed.ai,
            concurrency=parsed.concurrency,
            output_format=parsed.format
        )
        
        return config
    
    async def run_scan(self, config: ScannerConfig) -> int:
        scanner = ChkApiScanner(config)
        result = await scanner.run()
        
        print(f"\n{'='*60}")
        print(f"Scan Complete")
        print(f"{'='*60}")
        print(f"Target: {result.target_url}")
        print(f"Duration: {result.duration:.2f}s")
        print(f"Total APIs: {result.total_apis}")
        print(f"Alive APIs: {result.alive_apis}")
        print(f"High Value APIs: {result.high_value_apis}")
        print(f"Vulnerabilities: {len(result.vulnerabilities)}")
        print(f"Sensitive Data: {len(result.sensitive_data)}")
        
        if result.errors:
            print(f"\nErrors: {len(result.errors)}")
            for error in result.errors[:5]:
                print(f"  - {error}")
        
        return 0
    
    async def run(self, args=None) -> int:
        parsed = self.parser.parse_args(args)
        
        if parsed.command == 'dashboard':
            self.run_dashboard(parsed.host, parsed.port)
            return 0
        
        if parsed.command == 'scan' or parsed.command is None:
            config = self.parse_args(args)
            if config:
                return await self.run_scan(config)
        
        self.parser.print_help()
        return 1
    
    def run_dashboard(self, host: str, port: int):
        dashboard = WebDashboard(host=host, port=port)
        dashboard.start()


def main():
    """主入口"""
    cli = CLI()
    exit_code = asyncio.run(cli.run())
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
