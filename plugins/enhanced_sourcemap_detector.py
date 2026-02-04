import os
import re
import json
import time
import requests
import sqlite3
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Tuple, Set, Optional
try:
    from plugins.ast_analyzer import ASTAnalyzer
except ImportError:
    from ast_analyzer import ASTAnalyzer

class EnhancedSourceMapDetector:
    """基于SourceDetector插件原理的增强版检测器"""
    
    def __init__(self, headers: Dict = None, timeout: int = 10, delay: int = 300):
        self.headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.timeout = timeout
        self.delay = delay / 1000  # 转换为秒
        self.found_maps = {}
        
    def detect_from_js_url(self, js_url: str) -> Optional[Dict]:
        """从JS URL检测SourceMap - 模拟插件的tryGetMap逻辑"""
        try:
            print(f"[INFO] 开始检测JS文件的SourceMap: {js_url}")
            
            # 模拟插件的延迟机制
            time.sleep(self.delay)
            
            # 1. 直接拼接.map尝试访问
            map_url = js_url + '.map'
            print(f"[INFO] 尝试访问SourceMap文件: {map_url}")
            
            response = requests.get(
                map_url, 
                headers=self.headers, 
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            
            print(f"[INFO] SourceMap请求状态码: {response.status_code}")
            
            if response.status_code == 200:
                content = response.text
                print(f"[INFO] 成功获取SourceMap内容，大小: {len(content)} 字节")
                
                # 2. 使用类似插件的验证机制
                print(f"[INFO] 开始验证SourceMap格式...")
                if self._is_valid_sourcemap(content):
                    print(f"[INFO] SourceMap格式验证通过")
                    
                    result = {
                        'js_url': js_url,
                        'map_url': response.url,  # 考虑重定向
                        'content': content,
                        'size': len(content),
                        'validation': self._validate_sourcemap_structure(content)
                    }
                    
                    # 输出解包结果摘要
                    self._print_sourcemap_summary(result)
                    
                    self.found_maps[js_url] = result
                    print(f"[SUCCESS] SourceMap检测完成，已保存结果")
                    return result
                else:
                    print(f"[WARNING] SourceMap格式验证失败")
            else:
                print(f"[INFO] SourceMap文件不存在或无法访问")
                    
        except Exception as e:
            print(f"[ERROR] 检测失败 {js_url}: {str(e)}")
            
        return None
    
    def _is_valid_sourcemap(self, content: str) -> bool:
        """模拟插件的isValidSourceMap验证 - 严格验证"""
        try:
            print(f"[INFO] 开始验证SourceMap格式...")
            
            # 1. 基础JSON解析
            print(f"[INFO] 步骤1: JSON格式解析...")
            sourcemap_data = json.loads(content)
            print(f"[INFO] ✓ JSON解析成功")
            
            # 2. 必需字段验证（类似Mozilla库的验证）
            print(f"[INFO] 步骤2: 必需字段验证...")
            required_fields = ['version', 'sources', 'mappings']
            for field in required_fields:
                if field not in sourcemap_data:
                    print(f"[WARNING] ✗ 缺少必需字段: {field}")
                    return False
            print(f"[INFO] ✓ 所有必需字段存在")
            
            # 3. 版本验证
            print(f"[INFO] 步骤3: 版本验证...")
            version = sourcemap_data['version']
            if version != 3:
                print(f"[WARNING] ✗ 版本号不正确: {version} (需要 3)")
                return False
            print(f"[INFO] ✓ 版本号正确: {version}")
                
            # 4. sources字段验证
            print(f"[INFO] 步骤4: sources字段验证...")
            sources = sourcemap_data.get('sources', [])
            if not isinstance(sources, list) or len(sources) == 0:
                print(f"[WARNING] ✗ sources字段无效: {sources}")
                return False
            print(f"[INFO] ✓ sources字段有效，包含 {len(sources)} 个源文件")
                
            # 5. mappings字段验证（基本格式检查）
            print(f"[INFO] 步骤5: mappings字段验证...")
            mappings = sourcemap_data.get('mappings', '')
            if not mappings or not isinstance(mappings, str):
                print(f"[WARNING] ✗ mappings字段无效: {mappings}")
                return False
            print(f"[INFO] ✓ mappings字段有效，长度: {len(mappings)} 字符")
                
            # 6. 内容完整性检查（模拟hasContentsOfAllSources）
            print(f"[INFO] 步骤6: 内容完整性检查...")
            sources_content = sourcemap_data.get('sourcesContent', [])
            if sources_content:
                # 如果有sourcesContent，检查是否完整
                valid_content_count = sum(1 for content in sources_content if content is not None)
                if valid_content_count == 0:
                    print(f"[WARNING] ✗ sourcesContent中没有有效内容")
                    return False
                print(f"[INFO] ✓ sourcesContent有效，包含 {valid_content_count}/{len(sources_content)} 个有效内容")
            else:
                print(f"[INFO] - 没有sourcesContent字段")
                    
            # 7. 文件名验证
            print(f"[INFO] 步骤7: 文件名验证...")
            for source in sources:
                if not source or not isinstance(source, str):
                    print(f"[WARNING] ✗ 无效的文件名: {source}")
                    return False
            print(f"[INFO] ✓ 所有文件名有效")
            
            print(f"[SUCCESS] SourceMap格式验证通过!")
            return True
            
        except json.JSONDecodeError as e:
            print(f"[ERROR] ✗ JSON解析失败: {str(e)}")
            return False
        except Exception as e:
            print(f"[ERROR] ✗ 验证过程中出错: {str(e)}")
            return False
    
    def _print_sourcemap_summary(self, result: Dict) -> None:
        """输出SourceMap解包结果的摘要信息"""
        try:
            content = result['content']
            data = json.loads(content)
            
            print(f"[INFO] SourceMap解包结果摘要:")
            print(f"  - 版本: {data.get('version', 'unknown')}")
            print(f"  - 源文件数量: {len(data.get('sources', []))}")
            print(f"  - 源文件列表: {data.get('sources', [])}")
            print(f"  - 内容大小: {result['size']} 字节")
            
            # 检查是否包含源代码内容
            sources_content = data.get('sourcesContent', [])
            if sources_content:
                valid_content_count = sum(1 for content in sources_content if content is not None)
                print(f"  - 包含源代码内容: {valid_content_count}/{len(sources_content)} 个文件")
                
                # 如果包含源代码，显示前几个文件的内容预览
                for i, source in enumerate(data.get('sources', [])[:3]):  # 只显示前3个
                    if i < len(sources_content) and sources_content[i]:
                        content_preview = sources_content[i][:200]  # 预览前200字符
                        print(f"  - 文件 {source} 预览:")
                        print(f"    {content_preview}...")
            
            # 显示验证结果
            validation = result.get('validation', {})
            if validation:
                print(f"  - 验证状态: {'通过' if validation.get('is_valid') else '失败'}")
                if validation.get('errors'):
                    print(f"  - 错误信息: {validation['errors']}")
                    
        except Exception as e:
            print(f"[ERROR] 输出摘要信息失败: {str(e)}")
    
    def _validate_sourcemap_structure(self, content: str) -> Dict:
        """深度验证SourceMap结构 - 类似Mozilla库的内部验证"""
        try:
            data = json.loads(content)
            validation = {
                'is_valid': True,
                'version': data.get('version'),
                'sources_count': len(data.get('sources', [])),
                'has_sources_content': 'sourcesContent' in data,
                'has_file_field': 'file' in data,
                'has_source_root': 'sourceRoot' in data,
                'mappings_length': len(data.get('mappings', '')),
                'names_count': len(data.get('names', []))
            }
            
            # 验证mappings格式（基本VLQ格式检查）
            mappings = data.get('mappings', '')
            if mappings:
                # 检查是否包含有效的VLQ字符
                valid_vlq_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
                has_valid_chars = any(c in valid_vlq_chars for c in mappings)
                validation['has_valid_vlq_chars'] = has_valid_chars
                validation['has_separators'] = ';' in mappings or ',' in mappings
                
            return validation
            
        except Exception as e:
            return {'is_valid': False, 'error': str(e)}

class IntelligentSourceMapDiscoverer:
    """智能SourceMap发现器 - 结合插件策略和主动探测"""
    
    def __init__(self, detector: EnhancedSourceMapDetector):
        self.detector = detector
        self.discovered_maps = []
        
    def discover_from_js_content(self, js_url: str, js_content: str) -> List[Dict]:
        """从JS内容智能发现SourceMap - 多重策略"""
        print(f"\n[INFO] ===== 开始智能发现SourceMap: {js_url} =====")
        found_maps = []

        # 策略1: 从JS内容提取sourceMappingURL（类似浏览器插件的content-script方法）
        print(f"[INFO] 策略1: 从JS内容提取sourceMappingURL...")
        sourcemap_urls = self._extract_sourcemap_urls(js_content, js_url)
        print(f"[INFO] 从内容中发现 {len(sourcemap_urls)} 个sourceMappingURL")

        # 策略2: 主动拼接.map（类似插件的tryGetMap）
        print(f"[INFO] 策略2: 主动拼接.map文件...")
        direct_map_url = js_url + '.map'
        if direct_map_url not in sourcemap_urls:
            sourcemap_urls.append(direct_map_url)
            print(f"[INFO] 添加直接拼接的URL: {direct_map_url}")

        # 策略3: Webpack特殊模式识别
        print(f"[INFO] 策略3: Webpack特殊模式识别...")
        webpack_patterns = [
            r'//# sourceMappingURL=(.+\.map)',
            r'//# sourceMappingURL=(.+\.map\?.+)',
            r'sourceMappingURL=(chunk\.\w+\.js\.map)',
            r'sourceMappingURL=([^\s]+\.js\.map)'
        ]

        webpack_found = 0
        for pattern in webpack_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith('http'):
                    # 相对路径处理
                    full_url = urljoin(js_url, match)
                    if full_url not in sourcemap_urls:
                        sourcemap_urls.append(full_url)
                        webpack_found += 1
        print(f"[INFO] Webpack模式发现 {webpack_found} 个新URL")

        # 输出所有发现的URL
        print(f"[INFO] 总共发现 {len(sourcemap_urls)} 个潜在的SourceMap URL:")
        for i, url in enumerate(sourcemap_urls, 1):
            print(f"  {i}. {url}")

        # 对所有发现的URL进行检测
        print(f"[INFO] 开始检测所有发现的SourceMap URL...")
        success_count = 0
        for map_url in sourcemap_urls:
            try:
                print(f"[INFO] 检测URL: {map_url}")
                result = self.detector.detect_from_js_url(map_url.replace('.map', ''))
                if result:
                    found_maps.append(result)
                    success_count += 1
                    print(f"[SUCCESS] ✓ 成功检测到有效SourceMap")
                else:
                    print(f"[INFO] - 未检测到有效SourceMap")
            except Exception as e:
                print(f"[ERROR] ✗ 检测失败: {str(e)}")
                continue

        print(f"\n[INFO] ===== SourceMap智能发现完成 =====")
        print(f"[INFO] 检测结果: {success_count}/{len(sourcemap_urls)} 个有效SourceMap")
        print(f"[INFO] 成功发现 {len(found_maps)} 个SourceMap\n")

        return found_maps
    
    def _extract_sourcemap_urls(self, js_content: str, base_url: str) -> List[str]:
        """从JS内容提取sourceMappingURL - 增强版"""
        urls = []
        
        # 标准sourceMappingURL注释
        patterns = [
            r'//# sourceMappingURL=(.+\.map(?:\?[^\s]*)?)',
            r'//\# sourceMappingURL=(.+\.map(?:\?[^\s]*)?)',  # 转义版本
            r'/\*# sourceMappingURL=(.+\.map(?:\?[^\s]*)?) \*/',  # 多行注释版本
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match:
                    # URL规范化处理
                    if match.startswith('http'):
                        urls.append(match)
                    elif match.startswith('//'):
                        # 协议相对URL
                        parsed = urlparse(base_url)
                        urls.append(f"{parsed.scheme}:{match}")
                    elif match.startswith('/'):
                        # 绝对路径
                        parsed = urlparse(base_url)
                        urls.append(f"{parsed.scheme}://{parsed.netloc}{match}")
                    else:
                        # 相对路径
                        urls.append(urljoin(base_url, match))
        
        return list(set(urls))  # 去重

import os
import yaml
import re

class SourceMapRestorer:
    """SourceMap还原与敏感信息扫描器"""

    def __init__(self, headers: Dict = None, timeout: int = 10):
        self.headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.timeout = timeout
        self.rules = self._load_rules()
        self.ast_analyzer = ASTAnalyzer()

    def _load_rules(self):
        """加载敏感信息扫描规则"""
        rules = []
        try:
            # 尝试加载规则文件
            base_dir = os.path.dirname(os.path.abspath(__file__))
            rules_path = os.path.join(base_dir, 'rules.yaml')

            # 如果当前目录没有，尝试上级目录
            if not os.path.exists(rules_path):
                rules_path = os.path.join(os.path.dirname(base_dir), 'rules.yaml')

            if os.path.exists(rules_path):
                print(f"[INFO] 加载扫描规则: {rules_path}")
                with open(rules_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    for rule in data.get('rules', []):
                        if rule.get('enabled', True):
                            try:
                                rule['compiled_pattern'] = re.compile(rule['pattern'], re.IGNORECASE)
                                rules.append(rule)
                            except Exception as e:
                                print(f"[WARNING] 规则编译失败 {rule.get('id')}: {e}")
                print(f"[INFO] 成功加载 {len(rules)} 条敏感信息扫描规则")
            else:
                print(f"[WARNING] 未找到规则文件 rules.yaml")
        except Exception as e:
            print(f"[ERROR] 加载规则失败: {e}")
        return rules

    def restore_and_scan(self, map_url: str, output_base_dir: str, db_path: str = None) -> List[str]:
        """还原SourceMap并扫描敏感信息，返回还原的文件路径列表"""
        print(f"[INFO] 开始还原SourceMap: {map_url}")
        restored_files = []
        
        try:
            # 1. 下载SourceMap
            response = requests.get(map_url, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code != 200:
                print(f"[ERROR] 下载SourceMap失败: {response.status_code}")
                return []
            
            content = response.text
            try:
                map_json = json.loads(content)
            except:
                print(f"[ERROR] 解析SourceMap JSON失败")
                return []
                
            sources = map_json.get('sources', [])
            sources_content = map_json.get('sourcesContent', [])
            
            if not sources_content:
                print(f"[WARNING] SourceMap不包含sourcesContent，无法还原源码")
                return []
                
            # 2. 准备输出目录
            # 使用URL的文件名作为子目录
            parsed_url = urlparse(map_url)
            map_name = os.path.basename(parsed_url.path) or 'unknown_map'
            restore_dir = os.path.join(output_base_dir, 'sourcemap_restored', map_name.replace('.', '_'))
            
            if not os.path.exists(restore_dir):
                os.makedirs(restore_dir)
                
            print(f"[INFO] 还原目录: {restore_dir}")
            
            # 3. 还原文件
            restored_count = 0
            for index, source_path in enumerate(sources):
                if index >= len(sources_content):
                    break
                    
                content = sources_content[index]
                if not content:
                    continue
                    
                # 清理路径
                clean_path = source_path
                clean_path = clean_path.replace('webpack://', '')
                clean_path = clean_path.replace('webpack-internal://', '')
                clean_path = clean_path.lstrip('/')
                
                # 防止路径遍历
                while '../' in clean_path:
                    clean_path = clean_path.replace('../', '')
                while './' in clean_path:
                    clean_path = clean_path.replace('./', '')
                    
                # 移除特殊前缀
                clean_path = clean_path.replace('webpack_build/', '', 1)
                
                # 忽略 node_modules
                if 'node_modules' in clean_path:
                    continue
                    
                full_path = os.path.join(restore_dir, clean_path)
                dir_name = os.path.dirname(full_path)
                
                if not os.path.exists(dir_name):
                    os.makedirs(dir_name)
                    
                # 写入文件
                try:
                    with open(full_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    restored_files.append(full_path)
                    restored_count += 1
                except Exception as e:
                    # print(f"[ERROR] 写入文件失败 {full_path}: {e}")
                    pass
                
                # 4. 立即扫描敏感信息
                findings = self._check_sensitive(content, clean_path)
                if findings:
                    print(f"[敏感信息] 发现 {len(findings)} 条敏感信息: {clean_path}")
                    if db_path:
                        self._save_sensitive_to_db(db_path, findings, map_url, clean_path)
                    else:
                        for f in findings:
                            print(f"[!] POTENTIAL LEAK [{f['severity']}]: {f['name']} in {clean_path}")
            
            print(f"[INFO] 成功还原 {restored_count} 个文件")
            
            # Perform AST Analysis on restored files
            ast_findings = self._perform_ast_analysis(restored_files)
            
            return restored_files, ast_findings
            
        except Exception as e:
            print(f"[ERROR] 还原过程发生异常: {str(e)}")
            return restored_files, []

    def _perform_ast_analysis(self, files: List[str]) -> List[Dict]:
        """对还原的文件进行AST分析"""
        print(f"[INFO] 开始对 {len(files)} 个文件进行AST深度分析...")
        total_apis = 0
        total_urls = 0
        all_findings = []
        
        for file_path in files:
            if not file_path.endswith('.js') and not file_path.endswith('.jsx') and not file_path.endswith('.ts') and not file_path.endswith('.tsx'):
                continue
                
            try:
                res = self.ast_analyzer.analyze_file(file_path)
                
                apis = res.get('apis', [])
                urls = res.get('urls', [])
                
                if apis or urls:
                    all_findings.append({
                        'file': file_path,
                        'apis': apis,
                        'urls': urls
                    })
                    
                    print(f"[AST] 文件 {os.path.basename(file_path)} 分析结果:")
                    
                    if apis:
                        print(f"  - 发现 {len(apis)} 个接口调用:")
                        for api in apis:
                            print(f"    * {api['tool']} {api['method']} {api['url']}")
                            total_apis += 1
                            
                    if urls:
                        # 过滤掉太多短的或无意义的
                        valid_urls = [u for u in urls if len(u['value']) > 5]
                        if valid_urls:
                            print(f"  - 发现 {len(valid_urls)} 个潜在URL:")
                            for url in valid_urls[:10]: # 只显示前10个
                                print(f"    * {url['value']} ({url['type']})")
                            if len(valid_urls) > 10:
                                print(f"    ... 等共 {len(valid_urls)} 个")
                            total_urls += len(valid_urls)
            except Exception as e:
                print(f"[ERROR] AST分析出错 {file_path}: {e}")
                
        print(f"[INFO] AST分析完成: 总计发现 {total_apis} 个接口调用, {total_urls} 个潜在URL")
        return all_findings

    def _check_sensitive(self, content: str, filename: str) -> List[Dict]:
        findings = []
        lower_content = content.lower()
        lower_name = filename.lower()
        
        # 1. 检查文件名 (简单的启发式)
        if any(x in lower_name for x in ['config.', 'secret', 'credential', 'password']):
             findings.append({
                 'name': 'Sensitive Filename',
                 'matches': filename,
                 'severity': 'Medium',
                 'evidence': f"Filename contains sensitive keyword: {filename}"
             })

        # 2. 检查内容 (优先使用规则库)
        if self.rules:
            for rule in self.rules:
                try:
                    if rule.get('compiled_pattern'):
                        match = rule['compiled_pattern'].search(content)
                        if match:
                            findings.append({
                                'name': rule.get('name', rule.get('id')),
                                'matches': match.group(0),
                                'severity': 'High',
                                'evidence': content[max(0, match.start()-50):min(len(content), match.end()+50)]
                            })
                except Exception:
                    pass
        
        # 3. 降级：默认关键词检测 (如果没有规则库或规则库没匹配到，作为补充)
        # 注意：为了避免重复，如果规则库已经匹配了，这里可能需要权衡。这里简单起见都扫一遍。
        fallback_keywords = ['password', 'secret', 'access_key', 'api_key', 'authorization', 'bearer ', 'private_key']
        for keyword in fallback_keywords:
            if keyword in lower_content:
                # 简单寻找上下文
                idx = lower_content.find(keyword)
                start = max(0, idx - 30)
                end = min(len(content), idx + len(keyword) + 50)
                evidence = content[start:end]
                
                # 简单的误报过滤 (例如 key in keyboard)
                # 这里不做太复杂的，主要依靠人工确认
                findings.append({
                    'name': f"Keyword: {keyword}",
                    'matches': keyword,
                    'severity': 'Medium',
                    'evidence': evidence
                })
                
        return findings

    def _save_sensitive_to_db(self, db_path, findings, url, file_path):
        if not db_path:
            print(f"[警告] db_path 为空，无法保存敏感信息到数据库")
            return
        print(f"[敏感信息] 准备保存 {len(findings)} 条敏感信息到数据库: {db_path}")
        try:
            conn = sqlite3.connect(db_path)
            # 确保表存在
            conn.execute("CREATE TABLE IF NOT EXISTS step8_sensitive (name TEXT, matches TEXT, url TEXT, file TEXT, severity TEXT, evidence TEXT)")
            
            # 尝试添加列 (如果表已存在且缺少列)
            try:
                conn.execute("ALTER TABLE step8_sensitive ADD COLUMN severity TEXT")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE step8_sensitive ADD COLUMN evidence TEXT")
            except Exception:
                pass
            
            data = []
            for f in findings:
                # 避免插入重复数据 (简单根据 name + file 判断? 还是全量?)
                # 这里直接全量插入，数据库侧没有唯一约束
                data.append((
                    f['name'],
                    f['matches'],
                    url,
                    file_path,
                    f['severity'],
                    f['evidence']
                ))
            
            conn.executemany("INSERT INTO step8_sensitive (name, matches, url, file, severity, evidence) VALUES (?, ?, ?, ?, ?, ?)", data)
            conn.commit()
            conn.close()
            # print(f"[INFO] 已保存 {len(findings)} 条敏感信息到数据库")
        except Exception as e:
            print(f"[ERROR] 保存敏感信息失败: {e}")

class SourceMapIntegration:
    """SourceMap集成模块 - 与现有ChkApi框架整合"""
    
    def __init__(self):
        self.detector = EnhancedSourceMapDetector()
        self.discoverer = IntelligentSourceMapDiscoverer(self.detector)
        self.restorer = SourceMapRestorer(headers=self.detector.headers, timeout=self.detector.timeout)

    def restore_and_scan(self, map_url: str, output_base_dir: str, db_path: str = None) -> List[str]:
        """还原并扫描SourceMap"""
        return self.restorer.restore_and_scan(map_url, output_base_dir, db_path)
        
    def detect_sourcemap_urls_enhanced(self, js_url: str, js_content: str) -> List[str]:
        """增强版SourceMap发现 - 基于SourceDetector策略"""
        print(f"\n[INFO] ===== 开始增强SourceMap发现: {js_url} =====")
        sourcemap_urls = []
        
        # 1. 从JS内容提取（类似插件的content-script方法）
        print(f"[INFO] 步骤1: 从JS内容提取sourceMappingURL...")
        content_urls = self._extract_from_js_content(js_content, js_url)
        print(f"[INFO] 从内容中发现 {len(content_urls)} 个sourceMappingURL")
        sourcemap_urls.extend(content_urls)
        
        # 2. 主动拼接探测（类似插件的tryGetMap方法）
        print(f"[INFO] 步骤2: 主动拼接探测...")
        if js_url.endswith('.js'):
            # 直接拼接.map
            direct_map = js_url + '.map'
            print(f"[INFO] 尝试直接拼接: {direct_map}")
            
            # 3. 使用增强验证器验证
            print(f"[INFO] 验证直接拼接的URL...")
            if self._validate_map_exists(direct_map):
                if direct_map not in sourcemap_urls:
                    sourcemap_urls.append(direct_map)
                    print(f"[SUCCESS] ✓ 直接拼接验证成功: {direct_map}")
            else:
                print(f"[INFO] - 直接拼接验证失败或不存在")
        
        # 4. Webpack特殊模式（基于插件观察到的模式）
        print(f"[INFO] 步骤3: Webpack特殊模式识别...")
        webpack_patterns = [
            r'chunk\.\w+\.js\.map$',  # Webpack chunk模式
            r'\w+-\w+\.js\.map$',      # 哈希模式
            r'bundle\.\w+\.js\.map$'  # Bundle模式
        ]
        
        webpack_found = 0
        for pattern in webpack_patterns:
            if re.search(pattern, js_url):
                print(f"[INFO] 检测到Webpack模式: {pattern}")
                # 尝试多种变体
                base_url = js_url.replace('.js', '')
                variants = [
                    base_url + '.map',
                    base_url + '.min.js.map',
                    base_url.replace('.min', '') + '.js.map'
                ]
                
                print(f"[INFO] 尝试Webpack变体...")
                for variant in variants:
                    if variant not in sourcemap_urls:
                        print(f"[INFO] 验证变体: {variant}")
                        if self._validate_map_exists(variant):
                            sourcemap_urls.append(variant)
                            print(f"[SUCCESS] ✓ Webpack变体验证成功: {variant}")
                            webpack_found += 1
                            break
                        else:
                            print(f"[INFO] - 变体验证失败: {variant}")
        
        if webpack_found == 0:
            print(f"[INFO] - 未检测到有效的Webpack模式")
        else:
            print(f"[SUCCESS] ✓ Webpack模式发现 {webpack_found} 个有效SourceMap")
        
        # 输出发现的URL摘要
        print(f"\n[INFO] SourceMap发现摘要:")
        print(f"  - 总共发现: {len(sourcemap_urls)} 个SourceMap URL")
        for i, url in enumerate(sourcemap_urls, 1):
            print(f"  {i}. {url}")
        
        print(f"\n[INFO] ===== 增强SourceMap发现完成 =====")
        
        return list(set(sourcemap_urls))
    
    def _extract_from_js_content(self, js_content: str, base_url: str) -> List[str]:
        """从JS内容提取sourceMappingURL"""
        return self.discoverer._extract_sourcemap_urls(js_content, base_url)
    
    def _validate_map_exists(self, map_url: str) -> bool:
        """增强验证 - 类似插件的isValidSourceMap"""
        try:
            print(f"[INFO] 验证SourceMap存在性: {map_url}")
            
            # 首先使用HEAD请求检查存在性
            print(f"[INFO] 发送HEAD请求检查存在性...")
            response = requests.head(map_url, headers=self.detector.headers, 
                                   timeout=self.detector.timeout, verify=False)
            
            print(f"[INFO] HEAD请求状态码: {response.status_code}")
            
            if response.status_code == 200:
                print(f"[INFO] HEAD请求成功，开始获取内容...")
                # 获取内容进行深度验证
                content_resp = requests.get(map_url, headers=self.detector.headers,
                                          timeout=self.detector.timeout, verify=False)
                
                print(f"[INFO] GET请求状态码: {content_resp.status_code}")
                
                if content_resp.status_code == 200:
                    print(f"[INFO] 获取内容成功，大小: {len(content_resp.text)} 字节")
                    is_valid = self._is_valid_sourcemap_format(content_resp.text)
                    if is_valid:
                        print(f"[SUCCESS] ✓ SourceMap格式验证通过: {map_url}")
                    else:
                        print(f"[WARNING] ✗ SourceMap格式验证失败: {map_url}")
                    return is_valid
                else:
                    print(f"[WARNING] ✗ GET请求失败: {content_resp.status_code}")
            else:
                print(f"[INFO] - HEAD请求失败或文件不存在: {response.status_code}")
                    
        except Exception as e:
            print(f"[ERROR] ✗ 验证过程中出错: {str(e)}")
            pass
        
        return False
    
    def _is_valid_sourcemap_format(self, content: str) -> bool:
        """严格格式验证 - 基于Mozilla SourceMap库逻辑"""
        try:
            print(f"[INFO] 开始SourceMap格式验证...")
            
            # 1. JSON解析验证
            print(f"[INFO] 步骤1: JSON解析验证...")
            data = json.loads(content)
            print(f"[INFO] ✓ JSON解析成功")
            
            # 2. 必需字段检查
            print(f"[INFO] 步骤2: 必需字段检查...")
            required = ['version', 'sources', 'mappings']
            for field in required:
                if field not in data:
                    print(f"[WARNING] ✗ 缺少必需字段: {field}")
                    return False
            print(f"[INFO] ✓ 所有必需字段存在")
            
            # 3. 版本验证
            print(f"[INFO] 步骤3: 版本验证...")
            version = data['version']
            if version != 3:
                print(f"[WARNING] ✗ 版本号不正确: {version} (需要 3)")
                return False
            print(f"[INFO] ✓ 版本号正确: {version}")
                
            # 4. sources验证
            print(f"[INFO] 步骤4: sources验证...")
            sources = data.get('sources', [])
            if not sources or not isinstance(sources, list):
                print(f"[WARNING] ✗ sources字段无效: {sources}")
                return False
            print(f"[INFO] ✓ sources有效，包含 {len(sources)} 个源文件")
                
            # 5. mappings验证
            print(f"[INFO] 步骤5: mappings验证...")
            mappings = data.get('mappings', '')
            if not mappings or not isinstance(mappings, str):
                print(f"[WARNING] ✗ mappings字段无效: {mappings}")
                return False
            print(f"[INFO] ✓ mappings有效，长度: {len(mappings)} 字符")
                
            # 6. VLQ格式基础验证
            print(f"[INFO] 步骤6: VLQ格式验证...")
            if not self._validate_vlq_format(mappings):
                print(f"[WARNING] ✗ VLQ格式验证失败")
                return False
            print(f"[INFO] ✓ VLQ格式验证通过")
                
            print(f"[SUCCESS] ✓ SourceMap格式验证通过!")
            return True
            
        except json.JSONDecodeError as e:
            print(f"[ERROR] ✗ JSON解析失败: {str(e)}")
            return False
        except Exception as e:
            print(f"[ERROR] ✗ 验证过程中出错: {str(e)}")
            return False
    
    def _validate_vlq_format(self, mappings: str) -> bool:
        """VLQ格式验证 - 确保是有效的SourceMap编码"""
        # 基础VLQ字符集
        vlq_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
        
        # 检查是否包含有效的VLQ字符和分隔符
        has_valid_chars = any(c in vlq_chars for c in mappings)
        has_separators = ';' in mappings or ',' in mappings
        
        return has_valid_chars and has_separators