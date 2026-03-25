try:
    from plugins.nodeCommon import *
except Exception as e:
    from nodeCommon import *

import sqlite3
import concurrent.futures
import re
import os
import json

english_parameter_list = [
    r"'([a-zA-Z]+)' parameter",
    r'"([a-zA-Z]+)" parameter',
    r'([a-zA-Z]+) parameter',
    r'\(([a-zA-Z]+)[=]*\) parameter',

    r"parameter '([a-zA-Z]+)'",
    r'parameter "([a-zA-Z]+)"',
    r'parameter ([a-zA-Z]+)',
    r'parameter \(([a-zA-Z]+)[=]*\)',

    r"'([a-zA-Z]+)' param",
    r'"([a-zA-Z]+)" param',
    r'([a-zA-Z]+) param',
    r'\(([a-zA-Z]+)[=]*\) param',

    r"param '([a-zA-Z]+)'",
    r'param "([a-zA-Z]+)"',
    r'param ([a-zA-Z]+)',
    r'param \(([a-zA-Z]+)[=]*\)',

    r'parameter ([a-zA-Z]+) ',
    r'param\[([a-zA-Z]+)\] required',
    r'parameter\[([a-zA-Z]+)\] required',
]

# 预编译正则表达式以提升性能
compiled_english_patterns = [re.compile(p) for p in english_parameter_list]

chinese_parameter_list = ["不能为空", "非法的", "参数"]
chinese_paramete_patterns = r"(['\"]?)([a-zA-Z]+)\1\s*(?:{})|(?:(?:{})\s*['\"]?([a-zA-Z]+)['\"]?)".format('|'.join(chinese_parameter_list), '|'.join(chinese_parameter_list))
compiled_chinese_pattern = re.compile(chinese_paramete_patterns)

# 定义用于检查是否包含中文字符的正则表达式
chinese_char_pattern = re.compile(r'[\u4e00-\u9fff]+')

def _extract_response_body_from_full_log(content):
    try:
        if not content or not isinstance(content, str):
            return ""
        sep = "\n" + "=" * 50 + "\n"
        if sep in content:
            parts = content.split(sep, 1)
            res_part = parts[1] if len(parts) > 1 else ""
            if "\n\n" in res_part:
                return res_part.split("\n\n", 1)[1].strip()
            return res_part.strip()
        mark = "-------------------- Response Body --------------------"
        if mark in content:
            return content.split(mark, 1)[1].strip()
        return content.strip()
    except Exception:
        return ""

def _extract_params_from_plain_text(text):
    try:
        if not text:
            return []
        out = []
        if chinese_char_pattern.search(text):
            extracted = compiled_chinese_pattern.findall(text)
            for match in extracted:
                if isinstance(match, tuple):
                    out.extend([p for p in match if p])
                else:
                    out.append(match)
        
        # 即使有中文也可能包含英文格式的参数，所以继续匹配英文正则
        # (原逻辑是互斥的，但合并可能更好？为了保持兼容性，这里保持原逻辑结构，但做性能优化)
        if not out: # 如果中文没匹配到，或者原逻辑就是互斥的
             for pattern in compiled_english_patterns:
                matches = pattern.findall(text)
                out.extend(matches)
        return out
    except Exception:
        return []

def extract_info_from_nested_data(data, current_depth=1, target_depth=2):
    # 初始化用来存储找到的键和参数的列表
    keys = []
    params = []

    # 判断当前数据点是否为字典类型
    if isinstance(data, dict):
        # 如果当前深度已达到或超过目标深度，则收集当前层的所有键
        if current_depth >= target_depth:
            keys.extend(data.keys())
        # 遍历字典中的每一个键值对
        for key, value in data.items():
            # 如果键是'param'或'parameter'且值为字符串，将该值添加到参数列表中
            if key in ['param', 'parameter'] and isinstance(value, str):
                params.append(value)
            # 如果值是字典或列表，递归调用此函数以深入处理
            if isinstance(value, (dict, list)):
                nested_keys, nested_params = extract_info_from_nested_data(value, current_depth + 1, target_depth)
                keys.extend(nested_keys)
                params.extend(nested_params)
            # 如果值是字符串，检查字符串中是否包含参数
            elif isinstance(value, str):
                # 使用正则表达式检测是否含有中文字符，并提取参数
                if chinese_char_pattern.search(value):
                    extracted_params = compiled_chinese_pattern.findall(value)
                    for match in extracted_params:
                        if isinstance(match, tuple):
                            params.extend([param for param in match if param])
                        else:
                            params.append(match)
                else:
                    # 独立处理每个英文正则表达式以查找匹配项
                    for pattern in compiled_english_patterns:
                        matches = pattern.findall(value)
                        params.extend(matches)
                        
    # 如果当前数据点是列表，遍历列表中的每一个元素
    elif isinstance(data, list):
        for item in data:
            # 为列表中的每一项递归调用此函数
            nested_keys, nested_params = extract_info_from_nested_data(item, current_depth + 1, target_depth)
            # 收集更深层次的键
            keys.extend(nested_keys)
            # 收集更深层次的参数
            params.extend(nested_params)
    # 返回去重后的键和参数，保持顺序不变
    return remove_duplicates(keys), remove_duplicates(params)

def getParameter_api(folder_path):
    return getParameter_db(os.path.join(folder_path, "results.db"))

def _extract_params_from_response_text(resp_text):
    try:
        if not resp_text:
            return [], []
        if not isinstance(resp_text, str):
            resp_text = str(resp_text)
        try:
            text = json.loads(resp_text)
        except Exception:
            try:
                text = eval(resp_text)
            except Exception:
                text = None
        if isinstance(text, (dict, list)):
            result_keys, result_params = extract_info_from_nested_data(text)
            if not result_params:
                result_params = result_keys
            return result_keys, result_params
        return [], _extract_params_from_plain_text(resp_text)
    except Exception:
        return [], []

def process_response_batch(batch_responses):
    """处理一批响应，返回提取出的所有参数"""
    batch_keys = []
    batch_params = []
    for resp in batch_responses:
        ks, ps = _extract_params_from_response_text(resp or "")
        if ks:
            batch_keys.extend(ks)
        if ps:
            batch_params.extend(ps)
    return batch_keys, batch_params

def getParameter_db(db_path):
    try:
        if not db_path or not os.path.isfile(db_path):
            return []
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        candidates = set() # 使用 set 自动去重
        
        # 优化查询：只查询非空的 response
        try:
            cur.execute("SELECT response FROM response_log WHERE response IS NOT NULL AND response != '' ORDER BY timestamp DESC LIMIT 20000")
            candidates.update([r[0] for r in cur.fetchall()])
        except Exception:
            pass
        for t in ["step5_no_param_responses", "step5_xml_json_responses", "step7_with_param_responses"]:
            try:
                cur.execute(f"SELECT response FROM {t} WHERE response IS NOT NULL AND response != '' LIMIT 20000")
                candidates.update([r[0] for r in cur.fetchall()])
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass

        if not candidates:
            return []

        candidates_list = list(candidates)
        keys_all = []
        params_all = []
        
        # 使用线程池并行处理
        # 根据 CPU 核心数决定线程数，IO 密集型可以多一点，但这里也是 CPU 密集型（正则），所以 conservative
        max_workers = min(os.cpu_count() or 4, 8)
        batch_size = max(1, len(candidates_list) // (max_workers * 4)) # 将任务切分为多个小批次
        
        batches = [candidates_list[i:i + batch_size] for i in range(0, len(candidates_list), batch_size)]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_batch = {executor.submit(process_response_batch, batch): batch for batch in batches}
            for future in concurrent.futures.as_completed(future_to_batch):
                try:
                    ks, ps = future.result()
                    keys_all.extend(ks)
                    params_all.extend(ps)
                except Exception as exc:
                    pass

        out = remove_duplicates(params_all if params_all else keys_all)
        return out
    except Exception:
        return []
