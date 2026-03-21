#!/usr/bin/env python3
"""
ChkApi CLI
重构后的命令行界面
"""

import sys
import argparse
import asyncio
import os
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import ChkApiScanner, ScannerConfig
from core.utils.config import Config


class CLI:
    """命令行界面"""
    
    def __init__(self):
        self.parser = self._build_parser()
        self.config_obj = Config()
    
    def _build_parser(self) -> argparse.ArgumentParser:
        """构建命令行解析器"""
        parser = argparse.ArgumentParser(
            prog='ChkApi',
            description='API Security Scanner - Automated API security detection tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  %(prog)s -u http://www.example.com
  %(prog)s -u http://www.example.com -c "session=xxx"
  %(prog)s -f urls.txt --chrome off
  %(prog)s -u http://www.example.com --ai --concurrency 100
            '''
        )
        
        parser.add_argument(
            '--version',
            action='version',
            version='ChkApi v2.0.0'
        )
        
        target_group = parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument(
            '-u', '--url',
            metavar='URL',
            help='Single URL to scan'
        )
        target_group.add_argument(
            '-f', '--file',
            metavar='FILE',
            help='File containing URLs to scan'
        )
        
        parser.add_argument(
            '-c', '--cookies',
            metavar='COOKIES',
            help='Cookies for authenticated scanning'
        )
        
        mode_group = parser.add_argument_group('Scan Mode')
        mode_group.add_argument(
            '--at', '--attack-type',
            dest='attack_type',
            choices=['0', '1'],
            default='0',
            help='0: collect+scan (default), 1: collect only'
        )
        mode_group.add_argument(
            '--na', '--no-api',
            dest='no_api',
            choices=['0', '1'],
            default='0',
            help='0: scan APIs (default), 1: skip API scanning'
        )
        
        perf_group = parser.add_argument_group('Performance Options')
        perf_group.add_argument(
            '--concurrency', '-cn',
            type=int,
            default=50,
            help='Max concurrent requests (default: 50)'
        )
        perf_group.add_argument(
            '--chrome',
            choices=['on', 'off'],
            default='on',
            help='Use Chrome for JS extraction (default: on)'
        )
        perf_group.add_argument(
            '--js-depth',
            type=int,
            default=3,
            help='JS crawling depth (default: 3)'
        )
        
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument(
            '--output', '-o',
            metavar='DIR',
            help='Output directory'
        )
        output_group.add_argument(
            '--format', '-fmt',
            choices=['json', 'html', 'markdown'],
            default='json',
            help='Output format (default: json)'
        )
        output_group.add_argument(
            '--dedupe',
            choices=['on', 'off'],
            default='on',
            help='URL deduplication (default: on)'
        )
        output_group.add_argument(
            '--store',
            choices=['db', 'txt', 'excel', 'all'],
            default='all',
            help='Storage format (default: all)'
        )
        
        ai_group = parser.add_argument_group('AI Options')
        ai_group.add_argument(
            '--ai',
            action='store_true',
            help='Enable AI analysis'
        )
        ai_group.add_argument(
            '--ai-model',
            metavar='MODEL',
            help='AI model to use'
        )
        ai_group.add_argument(
            '--ai-api-key',
            metavar='KEY',
            help='AI API key'
        )
        
        proxy_group = parser.add_argument_group('Proxy Options')
        proxy_group.add_argument(
            '--proxy',
            metavar='PROXY',
            help='Proxy server (e.g., http://127.0.0.1:8080)'
        )
        proxy_group.add_argument(
            '--proxy-mode',
            choices=['js', 'api', 'all'],
            default='all',
            help='Proxy mode (default: all)'
        )
        
        adv_group = parser.add_argument_group('Advanced Options')
        adv_group.add_argument(
            '--config',
            metavar='FILE',
            help='Custom config file'
        )
        adv_group.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Verbose output'
        )
        adv_group.add_argument(
            '--debug',
            action='store_true',
            help='Debug mode'
        )
        
        return parser
    
    def parse_args(self, args: Optional[list] = None) -> ScannerConfig:
        """解析参数并构建扫描配置"""
        parsed = self.parser.parse_args(args)
        
        if parsed.config:
            os.environ['CHKAPI_CONFIG'] = parsed.config
        
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
            dedupe=(parsed.dedupe == 'on'),
            store=parsed.store,
            proxy=parsed.proxy,
            js_depth=parsed.js_depth,
            ai_scan=parsed.ai,
            concurrency=parsed.concurrency,
            output_format=parsed.format
        )
        
        if parsed.output:
            os.makedirs(parsed.output, exist_ok=True)
        
        return config
    
    async def run(self, args: Optional[list] = None) -> int:
        """运行扫描"""
        try:
            config = self.parse_args(args)
            
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
            
        except KeyboardInterrupt:
            print("\n\nScan interrupted by user")
            return 130
        except Exception as e:
            print(f"\nError: {e}")
            if '--debug' in sys.argv:
                import traceback
                traceback.print_exc()
            return 1


def main():
    """主入口"""
    cli = CLI()
    exit_code = asyncio.run(cli.run())
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
