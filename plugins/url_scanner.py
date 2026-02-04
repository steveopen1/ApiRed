try:
    from plugins.nodeCommon import logger_print_content
except Exception:
    from nodeCommon import logger_print_content

def scan_urls_for_sensitive_info(alive_urls, rules_compact):
    """
    扫描存活的JS和静态资源URL，检测其中包含的敏感信息
    """
    findings = []
    
    if not alive_urls:
        return findings
        
    logger_print_content(f"[敏感信息扫描] 开始扫描 {len(alive_urls)} 个存活JS/静态资源URL...")
    
    for url in alive_urls:
        if not url: continue
        
        for rule in rules_compact:
            try:
                for match in rule['compiled_pattern'].finditer(url):
                    ms = match.group()
                    if not ms: continue
                    findings.append({
                        "id": rule['id'], "name": rule['name'], "match": ms,
                        "url": url, "file": url, "severity": rule['severity'],
                        "context": f"[URL Match] {url}",
                        "line": 0, "group": rule['group'], "source": rule['source']
                    })
            except Exception:
                pass
                
    return findings
