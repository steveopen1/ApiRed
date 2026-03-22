#!/usr/bin/env python3
"""
ApiRed-GF CLI
GF 风格的命令行安全扫描工具

用法:
    # 扫描文件
    python gf.py -f target.js sqli xss
    
    # 扫描目录
    python gf.py -d ./js_files --recursive
    
    # 从 stdin 输入
    cat urls.txt | python gf.py
    
    # 列出所有模式
    python gf.py --list
    
    # JSON 输出
    python gf.py -f target.js -o json
    
    # 指定分类
    python gf.py -f target.js -c sqli -c xss
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils.gf import GFLibrary, OutputFormatter, create_gf_cli


def main():
    """主函数"""
    parser = create_gf_cli()
    args = parser.parse_args()
    
    if args.list:
        from core.utils.gf import PatternLoader
        loader = PatternLoader(args.patterns_dir)
        print("\nAvailable Categories:")
        for cat in loader.get_categories():
            patterns = loader.get_patterns(cat)
            print(f"\n  {cat.upper()} ({len(patterns)} patterns):")
            for p in patterns[:10]:
                print(f"    - {p.name}: {p.description} [{p.severity}]")
            if len(patterns) > 10:
                print(f"    ... and {len(patterns) - 10} more")
        return
    
    gf = GFLibrary(args.patterns_dir)
    results = []
    
    if args.file:
        result = gf.scan_file(args.file, args.patterns, args.category)
        if result:
            results.append(result)
    
    elif args.directory:
        for result in gf.scan_directory(
            args.directory,
            args.patterns,
            args.category,
            args.recursive
        ):
            results.append(result)
    
    else:
        input_text = sys.stdin.read()
        if input_text.strip():
            result = gf.scan_text(input_text, args.patterns, args.category, "stdin")
            if result:
                results.append(result)
    
    if not results:
        print("No matches found.")
        return
    
    if args.output == 'json':
        print(OutputFormatter.to_json(results))
    elif args.output == 'csv':
        print(OutputFormatter.to_csv(results))
    elif args.output == 'summary':
        print(OutputFormatter.format_summary(results))
    else:
        print(OutputFormatter.to_text(results, not args.no_color))


if __name__ == '__main__':
    main()
