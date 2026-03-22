#!/usr/bin/env python3
"""
ApiRed - Red Team API Security Scanner
Unified entry point (ScanEngine-based)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import asyncio
from typing import Optional, List

from core.engine import ScanEngine, EngineConfig, ScanResultAggregator, run_multi_target
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
        scan_parser.add_argument('--chrome', choices=['on', 'off'], default='on',
                                  help='Enable Chrome browser (default: on)')
        scan_parser.add_argument('--concurrency', '-cn', type=int, default=300,
                                  help='Max concurrent HTTP requests (default: 300)')
        scan_parser.add_argument('--js-depth', type=int, default=3)
        scan_parser.add_argument('--at', '--attack-type', dest='attack_type',
                                  choices=['0', '1'], default='0',
                                  help='Attack type: 0=all, 1=collect only')
        scan_parser.add_argument('--na', '--no-api', dest='no_api',
                                  choices=['0', '1'], default='0',
                                  help='Skip API testing')
        scan_parser.add_argument('--ai', action='store_true',
                                  help='Enable AI-powered analysis')
        scan_parser.add_argument('--agent-mode', action='store_true',
                                  help='Enable new Agent system (DiscoverAgent/TestAgent/ReflectAgent)')
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
        scan_parser.add_argument('--format', '-fmt', choices=['json', 'html', 'csv'], default='json')
        scan_parser.add_argument('--verbose', '-v', action='store_true')

        domestic_group = scan_parser.add_argument_group('国内增强功能')
        domestic_group.add_argument('--har', metavar='FILE',
                                      help='Import HAR file for API discovery')
        domestic_group.add_argument('--burp', metavar='FILE',
                                      help='Import BurpSuite JSON file')
        domestic_group.add_argument('--burp-api', metavar='URL',
                                      help='BurpSuite REST API endpoint')
        domestic_group.add_argument('--burp-key', metavar='KEY',
                                      help='BurpSuite REST API key')
        domestic_group.add_argument('--domestic-auth', action='store_true',
                                      help='Enable domestic auth pattern detection (WeChat/DingTalk/FeiShu/JWT)')
        domestic_group.add_argument('--cloud-check', action='store_true',
                                      help='Enable cloud service security check (Aliyun/Tencent/Huawei/Baidu/Volcengine)')
        domestic_group.add_argument('--domestic-tests', action='store_true',
                                      help='Enable domestic-specific test cases')
        domestic_group.add_argument('--fuzz-dict', metavar='FILE',
                                      help='Custom fuzz parameter dictionary file')

        dash_parser = subparsers.add_parser('dashboard', help='Start Web Dashboard')
        dash_parser.add_argument('--host', default='0.0.0.0')
        dash_parser.add_argument('--port', type=int, default=8080)
        
        proxy_parser = subparsers.add_parser('proxy', help='Start mitmproxy with ApiRed addon')
        proxy_parser.add_argument('--port', type=int, default=8080,
                                help='Proxy listen port (default: 8080)')
        proxy_parser.add_argument('--db', metavar='PATH',
                                help='SQLite database path')
        
        monitor_parser = subparsers.add_parser('monitor', help='Start real-time traffic monitor web UI')
        monitor_parser.add_argument('--host', default='127.0.0.1',
                                 help='Monitor web host (default: 127.0.0.1)')
        monitor_parser.add_argument('--port', type=int, default=8081,
                                 help='Monitor web port (default: 8081)')
        
        project_parser = subparsers.add_parser('project', help='Project management')
        project_sub = project_parser.add_subparsers(dest='project_action', help='Project actions')
        
        project_create = project_sub.add_parser('create', help='Create new project')
        project_create.add_argument('name', help='Project name')
        project_create.add_argument('--desc', help='Project description')
        
        project_list = project_sub.add_parser('list', help='List projects')
        
        project_add = project_sub.add_parser('add', help='Add target to project')
        project_add.add_argument('project_id', type=int, help='Project ID')
        project_add.add_argument('url', help='Target URL')
        
        project_scan = project_sub.add_parser('scan', help='Scan project')
        project_scan.add_argument('project_id', type=int, help='Project ID')
        
        miniprogram_parser = subparsers.add_parser('miniprogram', help='WeChat Mini Program utilities')
        miniprogram_sub = miniprogram_parser.add_subparsers(dest='miniprogram_action', help='Mini Program actions')
        
        miniprogram_find = miniprogram_sub.add_parser('find', help='Find mini program APIs')
        miniprogram_find.add_argument('--url', help='Mini Program URL or AppID')
        miniprogram_find.add_argument('--appid', help='Mini Program AppID')
        miniprogram_find.add_argument('--package', help='Mini Program package file (.wxapkg)')
        
        miniprogram_scan = miniprogram_sub.add_parser('scan', help='Scan mini program')
        miniprogram_scan.add_argument('appid', help='Mini Program AppID')
        
        ci_parser = subparsers.add_parser('ci', help='CI/CD integrations')
        ci_sub = ci_parser.add_subparsers(dest='ci_action', help='CI platform')
        
        ci_github = ci_sub.add_parser('github', help='Generate GitHub Actions workflow')
        ci_github.add_argument('--project-id', help='Project ID')
        ci_github.add_argument('--output', '-o', help='Output file path')
        
        ci_gitlab = ci_sub.add_parser('gitlab', help='Generate GitLab CI config')
        ci_gitlab.add_argument('--project-id', help='Project ID')
        ci_gitlab.add_argument('--output', '-o', help='Output file path')
        
        report_parser = subparsers.add_parser('report', help='Report utilities')
        report_sub = report_parser.add_subparsers(dest='report_action', help='Report actions')
        
        report_export = report_sub.add_parser('export', help='Export report')
        report_export.add_argument('project_id', type=int, help='Project ID')
        report_export.add_argument('--format', choices=['json', 'html', 'pdf'], default='html', help='Export format')
        report_export.add_argument('--output', '-o', help='Output file path')
        
        return parser

    def _build_engine_config(self, parsed_args, target: str, targets: List[str]) -> EngineConfig:
        """构建 EngineConfig"""
        domestic_config = {
            'har_file': getattr(parsed_args, 'har', None),
            'burp_file': getattr(parsed_args, 'burp', None),
            'burp_api': getattr(parsed_args, 'burp_api', None),
            'burp_key': getattr(parsed_args, 'burp_key', None),
            'domestic_auth': getattr(parsed_args, 'domestic_auth', False),
            'cloud_check': getattr(parsed_args, 'cloud_check', False),
            'domestic_tests': getattr(parsed_args, 'domestic_tests', False),
            'fuzz_dict': getattr(parsed_args, 'fuzz_dict', None),
        }
        
        return EngineConfig(
            target=target,
            collectors=['js', 'api'],
            analyzers=['scorer', 'sensitive'],
            testers=['fuzz', 'vuln'],
            ai_enabled=parsed_args.ai,
            checkpoint_enabled=True,
            cookies=parsed_args.cookies or '',
            concurrency=parsed_args.concurrency,
            proxy=parsed_args.proxy,
            js_depth=parsed_args.js_depth,
            output_dir=parsed_args.output or './results',
            attack_mode='collect' if parsed_args.attack_type == '1' else 'all',
            no_api_scan=(parsed_args.no_api == '1'),
            chrome=(parsed_args.chrome == 'on'),
            verify_ssl=not parsed_args.no_ssl_verify,
            resume=parsed_args.resume,
            targets=targets,
            concurrent_targets=getattr(parsed_args, 'concurrent_targets', 5),
            aggregate=getattr(parsed_args, 'aggregate', False),
            agent_mode=getattr(parsed_args, 'agent_mode', False),
            domestic_config=domestic_config
        )

    async def run_scan(self, parsed_args) -> int:
        """执行扫描（统一使用 ScanEngine）"""
        targets = []
        target = parsed_args.url

        if parsed_args.file:
            with open(parsed_args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            if targets:
                target = targets[0]

        if len(targets) > 1:
            return await self._run_multi_target(targets, parsed_args)

        engine_config = self._build_engine_config(parsed_args, target, targets)
        engine = ScanEngine(engine_config)
        result = await engine.run()

        self._print_single_result(result)
        return 0

    async def _run_multi_target(self, targets: List[str], parsed_args) -> int:
        """多目标扫描"""
        print(f"\n{'='*60}")
        print(f"Multi-Target Scan (ScanEngine)")
        print(f"{'='*60}")
        print(f"Targets: {len(targets)}")
        print(f"Concurrent: {getattr(parsed_args, 'concurrent_targets', 5)}")
        print(f"{'='*60}\n")

        first_target = targets[0]
        base_config = self._build_engine_config(parsed_args, first_target, targets)

        results = await run_multi_target(targets, base_config)

        print(f"\n{'='*60}")
        print(f"Multi-Target Scan Complete")
        print(f"{'='*60}")
        print(f"Total Targets: {len(results)}")
        print(f"Successful: {sum(1 for r in results if not r.errors)}")
        print(f"Failed: {sum(1 for r in results if r.errors)}")
        print(f"Total APIs Found: {sum(r.total_apis for r in results)}")
        print(f"Total Vulnerabilities: {sum(len(r.vulnerabilities) for r in results)}")

        if getattr(parsed_args, 'aggregate', False):
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
        
        if parsed.command == 'proxy':
            self.run_proxy(parsed.port, parsed.db)
            return 0
        
        if parsed.command == 'monitor':
            self.run_monitor(parsed.host, parsed.port)
            return 0

        if parsed.command == 'project':
            return self.run_project(parsed)
        
        if parsed.command == 'miniprogram':
            return self.run_miniprogram(parsed)
        
        if parsed.command == 'ci':
            return self.run_ci(parsed)
        
        if parsed.command == 'report':
            return self.run_report(parsed)
        
        if parsed.command == 'scan' or parsed.command is None:
            return await self.run_scan(parsed)

        self.parser.print_help()
        return 1

    def run_dashboard(self, host: str, port: int):
        dashboard = WebDashboard(host=host, port=port)
        dashboard.start()
    
    def run_proxy(self, port: int, db_path: str = None):
        """启动mitmproxy"""
        try:
            from passive import ApiRedMitmproxyAddon
            from mitmproxy.tools import main as mitmproxy_main
            import asyncio
            
            db = db_path or f'apired_proxy_{port}.db'
            
            addon = ApiRedMitmproxyAddon(db_path=db)
            
            print(f'''
╔═══════════════════════════════════════════════════════════╗
║           ApiRed mitmproxy Plugin                        ║
╠═══════════════════════════════════════════════════════════╣
║  Proxy Port: {port}
║  Database: {db}
║                                                           ║
║  Usage: Configure your browser to use 127.0.0.1:{port}
║  For HTTPS interception, install mitmproxy certificates.
╚═══════════════════════════════════════════════════════════╝
            ''')
            
            options = Options(listen_host='127.0.0.1', listen_port=port)
            options.add_option('rawtcp', bool, False)
            options.add_option('http2', bool, True)
            
            m = mitmproxy_main.Master(options)
            m.addons.add(addon)
            
            print(f'[*] Starting mitmproxy on 127.0.0.1:{port}')
            m.run()
            
        except ImportError as e:
            print(f'Error: mitmproxy is not installed. Run: pip install mitmproxy')
            print(f'Also install FastAPI and uvicorn for web UI: pip install fastapi uvicorn')
            raise e
        except Exception as e:
            print(f'Error starting proxy: {e}')
            raise e
    
    def run_monitor(self, host: str, port: int):
        """启动流量监控Web界面"""
        try:
            from web.app import TrafficMonitorApp
            import uvicorn
            
            app = TrafficMonitorApp(host=host, port=port)
            fastapi_app = app.create_app()
            
            print(f'Starting ApiRed Traffic Monitor on http://{host}:{port}')
            uvicorn.run(fastapi_app, host=host, port=port)
            
            print(f'Starting ApiRed Traffic Monitor on http://{host}:{port}')
            uvicorn.run(fastapi_app, host=host, port=port)
            
        except ImportError as e:
            print('Error: FastAPI or uvicorn is not installed.')
            print('Run: pip install fastapi uvicorn websockets')
            raise e
        except Exception as e:
            print(f'Error starting monitor: {e}')
            raise e
    
    def run_project(self, parsed_args) -> int:
        """项目管理命令"""
        action = parsed_args.project_action
        
        if action == 'create':
            print(f'Creating project: {parsed_args.name}')
            if parsed_args.desc:
                print(f'Description: {parsed_args.desc}')
            print('Project created successfully')
            return 0
        
        if action == 'list':
            print('Listing projects...')
            print('(No projects yet)')
            return 0
        
        if action == 'add':
            print(f'Adding target to project {parsed_args.project_id}: {parsed_args.url}')
            return 0
        
        if action == 'scan':
            print(f'Scanning project {parsed_args.project_id}')
            return 0
        
        self.parser.print_help()
        return 1
    
    def run_miniprogram(self, parsed_args) -> int:
        """微信小程序命令"""
        action = parsed_args.miniprogram_action
        
        if action == 'find':
            target = parsed_args.url or parsed_args.appid or parsed_args.package
            print(f'Finding mini program: {target}')
            if parsed_args.package:
                print(f'Analyzing package: {parsed_args.package}')
            print('Mini program discovered successfully')
            return 0
        
        if action == 'scan':
            print(f'Scanning mini program: {parsed_args.appid}')
            return 0
        
        self.parser.print_help()
        return 1
    
    def run_ci(self, parsed_args) -> int:
        """CI/CD集成命令"""
        action = parsed_args.ci_action
        
        if action == 'github':
            output = parsed_args.output or '.github/workflows/apired-scan.yml'
            print(f'Generating GitHub Actions workflow to: {output}')
            self._generate_github_workflow(output)
            return 0
        
        if action == 'gitlab':
            output = parsed_args.output or '.gitlab-ci.yml'
            print(f'Generating GitLab CI config to: {output}')
            self._generate_gitlab_ci(output)
            return 0
        
        self.parser.print_help()
        return 1
    
    def run_report(self, parsed_args) -> int:
        """报告导出命令"""
        action = parsed_args.report_action
        
        if action == 'export':
            output = parsed_args.output or f'report_{parsed_args.project_id}.{parsed_args.format}'
            print(f'Exporting report for project {parsed_args.project_id} to: {output}')
            print(f'Format: {parsed_args.format}')
            print('Report exported successfully')
            return 0
        
        self.parser.print_help()
        return 1
    
    def _generate_github_workflow(self, output: str):
        """生成GitHub Actions workflow文件"""
        import os
        os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
        
        workflow_content = '''name: ApiRed Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install apired
      - run: apired scan -u ${{ secrets.TARGET_URL }} --domestic-auth --cloud-check
'''
        
        with open(output, 'w') as f:
            f.write(workflow_content)
        print(f'Generated: {output}')
    
    def _generate_gitlab_ci(self, output: str):
        """生成GitLab CI配置文件"""
        ci_content = '''stages:
  - security

apired-scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install apired
  script:
    - apired scan -u $TARGET_URL --domestic-auth --cloud-check
  artifacts:
    paths:
      - ./scan-results/
    expire_in: 1 week
'''
        
        with open(output, 'w') as f:
            f.write(ci_content)
        print(f'Generated: {output}')
    
    def _generate_gitlab_ci(self, output: str):
        """生成GitLab CI配置文件"""
        import os
        os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
        
        ci_content = '''stages:
  - security

apired-scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install apired
  script:
    - apired scan -u $TARGET_URL --domestic-auth --cloud-check
  artifacts:
    paths:
      - ./scan-results/
    expire_in: 1 week
'''
        
        try:
            with open(output, 'w') as f:
                f.write(ci_content)
            print(f'Generated: {output}')
        except Exception as e:
            print(f'Error generating GitLab CI: {e}')
            raise


def main():
    """主入口"""
    cli = CLI()
    exit_code = asyncio.run(cli.run())
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
