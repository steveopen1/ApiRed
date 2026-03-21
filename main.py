#!/usr/bin/env python3
"""
ApiRed - Red Team API Security Scanner
Main entry point
"""

import sys
import argparse


def run_cli():
    """Run CLI mode"""
    from cli import main as cli_main
    cli_main()


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    """Run Web Dashboard mode"""
    from core.dashboard.web_dashboard import WebDashboard
    
    dashboard = WebDashboard(host=host, port=port)
    dashboard.start(blocking=True)


def main():
    parser = argparse.ArgumentParser(
        prog='ApiRed',
        description='Red Team API Security Scanner'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    scan_parser = subparsers.add_parser('scan', help='Run CLI scan')
    scan_parser.add_argument('-u', '--url', help='Target URL')
    scan_parser.add_argument('-f', '--file', help='URL file')
    scan_parser.add_argument('-c', '--cookies', help='Cookies')
    scan_parser.add_argument('--chrome', choices=['on', 'off'], default='on')
    scan_parser.add_argument('--concurrency', type=int, default=50)
    scan_parser.add_argument('--ai', action='store_true')
    scan_parser.add_argument('--proxy', help='Proxy server')
    scan_parser.add_argument('--output', help='Output directory')
    
    dash_parser = subparsers.add_parser('dashboard', help='Start Web Dashboard')
    dash_parser.add_argument('--host', default='0.0.0.0', help='Dashboard host')
    dash_parser.add_argument('--port', type=int, default=8080, help='Dashboard port')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        sys.argv = ['apired.py']
        if args.url:
            sys.argv.extend(['-u', args.url])
        if args.file:
            sys.argv.extend(['-f', args.file])
        if args.cookies:
            sys.argv.extend(['-c', args.cookies])
        if args.concurrency:
            sys.argv.extend(['--concurrency', str(args.concurrency)])
        if args.ai:
            sys.argv.append('--ai')
        if args.proxy:
            sys.argv.extend(['--proxy', args.proxy])
        if args.output:
            sys.argv.extend(['--output', args.output])
        
        run_cli()
    
    elif args.command == 'dashboard':
        run_dashboard(host=args.host, port=args.port)
    
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python3 main.py scan -u https://target.com")
        print("  python3 main.py scan -f urls.txt --ai")
        print("  python3 main.py dashboard --port 8080")
        print("  python3 main.py dashboard --host 0.0.0.0 --port 9000")


if __name__ == '__main__':
    main()
