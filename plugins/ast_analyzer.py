import os
import json
import subprocess
import platform
import tempfile

class ASTAnalyzer:
    def __init__(self):
        # 获取当前文件所在目录
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.parser_script = os.path.join(self.base_dir, 'js_analysis', 'ast_parser.js')
        
    def analyze_file(self, file_path):
        """调用Node.js脚本分析JS文件"""
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
            
        try:
            # 构建命令
            cmd = ['node', self.parser_script, file_path]
            
            # 执行命令
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8'
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                # 忽略一些警告，只关注严重错误
                if not stdout and stderr:
                    print(f"[ASTAnalyzer] Error analyzing {file_path}: {stderr}")
                    return {'error': stderr}
            
            if not stdout:
                return {'apis': [], 'urls': []}

            try:
                # 解析JSON输出
                result = json.loads(stdout)
                return result
            except json.JSONDecodeError:
                # print(f"[ASTAnalyzer] Invalid JSON output for {file_path}: {stdout[:100]}...")
                return {'error': 'Invalid JSON output'}
                
        except Exception as e:
            print(f"[ASTAnalyzer] Exception: {e}")
            return {'error': str(e)}

    def analyze_files_batch(self, file_paths):
        """批量调用Node.js脚本分析JS文件，减少进程启动开销"""
        if not file_paths:
            return []
            
        valid_paths = [p for p in file_paths if os.path.exists(p)]
        if not valid_paths:
            return []
            
        temp_file_path = None
        try:
            # 创建临时文件存储文件列表
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8') as f:
                json.dump(valid_paths, f)
                temp_file_path = f.name
            
            # 构建命令
            cmd = ['node', self.parser_script, '--batch', temp_file_path]
            
            # 执行命令
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8'
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                if stderr:
                    print(f"[ASTAnalyzer] Batch Error: {stderr}")
                return []
            
            if not stdout:
                return []

            try:
                # 解析JSON输出
                results = json.loads(stdout)
                return results
            except json.JSONDecodeError:
                print(f"[ASTAnalyzer] Invalid JSON output in batch mode")
                return []
                
        except Exception as e:
            print(f"[ASTAnalyzer] Batch Exception: {e}")
            return []
        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except:
                    pass
