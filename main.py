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
from typing import Optional, List

from core.engine import ScanEngine
from core.config import ScanConfig
from core.scanner import ChkApiScanner, ScannerConfig, ScanResultAggregator, MultiTargetConfig
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
        scan_parser.add_argument('--no-ssl-verify', action='store_true',
                                  help='Disable SSL verification (not recommended)')
        scan_parser.add_argument('--resume', action='store_true',
                                  help='Resume from previous scan checkpoint')
        scan_parser.add_argument('--concurrent-targets', '-ct', type=int, default=5,
                                  help='Maximum concurrent targets for multi-target scan')
        scan_parser.add_argument('--aggregate', action='store_true',
                                  help='Aggregate results from multiple targets')
        scan_parser.add_argument('--output', '-o', help='Output directory')
        scan_parser.add_argument('--format', '-fmt', choices=['json', 'html'], default='json')
        scan_parser.add_argument('--verbose', '-v', action='store_true')
        scan_parser.add_argument('--engine', action='store_true',
                                  help='Use new ScanEngine (recommended)')
        
        dash_parser = subparsers.add_parser('dashboard', help='Start Web Dashboard')
        dash_parser.add_argument('--host', default='0.0.0.0')
        dash_parser.add_argument('--port', type=int, default=8080)
        
        return parser
    
    def parse_args(self, args=None):
        parsed = self.parser.parse_args(args)
        
        if parsed.command == 'dashboard':
            return None
        
        targets = []
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
            output_format=parsed.format,
            resume=parsed.resume,
            verify_ssl=not parsed.no_ssl_verify
        )
        
        config.targets = targets
        config.concurrent_targets = getattr(parsed, 'concurrent_targets', 5)
        config.aggregate = getattr(parsed, 'aggregate', False)
        
        return config
    
    async def run_scan(self, parsed_args) -> int:
        """执行扫描"""
        use_engine = getattr(parsed_args, 'engine', False)
        
        if use_engine:
            return await self._run_engine_scan(parsed_args)
        else:
            return await self._run_scanner_scan(parsed_args)
    
    async def _run_engine_scan(self, parsed_args) -> int:
        """使用 ScanEngine 执行扫描"""
        targets = []
        target = parsed_args.url
        
        if parsed_args.file:
            with open(parsed_args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            if targets:
                target = targets[0]
        
        scan_config = ScanConfig(
            target=target,
            cookies=parsed_args.cookies or '',
            collectors=['js', 'api'],
            analyzers=['scorer', 'sensitive'],
            testers=['fuzz', 'vuln'],
            ai_scan=parsed_args.ai,
            checkpoint_enabled=True,
            concurrency=parsed_args.concurrency,
            proxy=parsed_args.proxy,
            js_depth=parsed_args.js_depth,
            verify_ssl=not parsed_args.no_ssl_verify,
            resume=parsed_args.resume,
            output_dir=parsed_args.output or './results'
        )
        
        if targets and len(targets) > 1:
            return await self._run_multi_target_scan_engine(targets, scan_config)
        
        engine_config = scan_config.to_engine_config()
        engine = ScanEngine(engine_config)
        result = await engine.run()
        
        self._print_single_result(result)
        return 0
    
    async def _run_multi_target_scan_engine(self, targets: List[str], base_config: ScanConfig) -> int:
        """多目标扫描（使用 Engine）"""
        print(f"\n{'='*60}")
        print(f"Multi-Target Scan (Engine)")
        print(f"{'='*60}")
        print(f"Targets: {len(targets)}")
        print(f"{'='*60}\n")
        
        results = []
        for target in targets:
            config = ScanConfig(
                target=target,
                cookies=base_config.cookies,
                collectors=base_config.collectors,
                analyzers=base_config.analyzers,
                testers=base_config.testers,
                ai_scan=base_config.ai_scan,
                checkpoint_enabled=base_config.checkpoint_enabled,
                concurrency=base_config.concurrency,
                proxy=base_config.proxy,
                js_depth=base_config.js_depth,
                verify_ssl=base_config.verify_ssl
            )
            engine_config = config.to_engine_config()
            engine = ScanEngine(engine_config)
            result = await engine.run()
            results.append(result)
            print(f"Target: {target} - APIs: {result.total_apis}, Vulns: {len(result.vulnerabilities)}")
        
        print(f"\n{'='*60}")
        print(f"Multi-Target Scan Complete")
        print(f"{'='*60}")
        print(f"Total Targets: {len(results)}")
        print(f"Total APIs Found: {sum(r.total_apis for r in results)}")
        print(f"Total Vulnerabilities: {sum(len(r.vulnerabilities) for r in results)}")
        
        return 0
    
    async def _run_scanner_scan(self, parsed_args) -> int:
        """使用 ChkApiScanner 执行扫描"""
        targets = []
        target = parsed_args.url
        
        if parsed_args.file:
            with open(parsed_args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            if targets:
                target = targets[0]
        
        config = ScannerConfig(
            target=target,
            cookies=parsed_args.cookies or '',
            chrome=(parsed_args.chrome == 'on'),
            attack_mode='collect' if parsed_args.attack_type == '1' else 'all',
            no_api_scan=(parsed_args.no_api == '1'),
            proxy=parsed_args.proxy,
            js_depth=parsed_args.js_depth,
            ai_scan=parsed_args.ai,
            concurrency=parsed_args.concurrency,
            output_format=parsed_args.format,
            resume=parsed_args.resume,
            verify_ssl=not parsed_args.no_ssl_verify
        )
        
        config.targets = targets
        config.concurrent_targets = getattr(parsed_args, 'concurrent_targets', 5)
        config.aggregate = getattr(parsed_args, 'aggregate', False)
        
        if config.targets and len(config.targets) > 1:
            return await self._run_multi_target_scan(config)
        else:
            scanner = ChkApiScanner(config)
            result = await scanner.run()
            
            self._print_single_result(result)
            return 0
    
    async def _run_multi_target_scan(self, config: ScannerConfig) -> int:
        """执行多目标扫描"""
        print(f"\n{'='*60}")
        print(f"Multi-Target Scan")
        print(f"{'='*60}")
        print(f"Targets: {len(config.targets)}")
        print(f"Concurrent: {config.concurrent_targets}")
        print(f"{'='*60}\n")
        
        multi_config = MultiTargetConfig(
            targets=config.targets,
            max_concurrent_targets=config.concurrent_targets,
            share_cache=False
        )
        
        scanner = ChkApiScanner(config)
        results = await scanner.run_multiple(config.targets)
        
        print(f"\n{'='*60}")
        print(f"Multi-Target Scan Complete")
        print(f"{'='*60}")
        print(f"Total Targets: {len(results)}")
        print(f"Successful: {sum(1 for r in results if not r.errors)}")
        print(f"Failed: {sum(1 for r in results if r.errors)}")
        print(f"Total APIs Found: {sum(r.total_apis for r in results)}")
        print(f"Total Vulnerabilities: {sum(len(r.vulnerabilities) for r in results)}")
        
        if config.aggregate:
            aggregator = ScanResultAggregator()
            aggregated = aggregator.aggregate(results)
            print(f"\n{'='*60}")
            print(f"Aggregated Results")
            print(f"{'='*60}")
            print(f"High Value Endpoints: {len(aggregated['high_value_endpoints'])}")
            print(f"Vulnerabilities by Type: {aggregated['vulnerability_summary']['by_type']}")
            print(f"Vulnerabilities by Severity: {aggregated['vulnerability_summary']['by_severity']}")
        
        for i, result in enumerate(results):
            print(f"\n--- Target {i+1}: {result.target_url} ---")
            if result.errors:
                print(f"Failed: {result.errors[0]}")
            else:
                print(f"APIs: {result.total_apis}, Vulnerabilities: {len(result.vulnerabilities)}")
        
        return 0
    
    def _print_single_result(self, result) -> None:
        """打印单目标扫描结果"""
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
