import os
import json
from plugins.ai_engine import AIEngine

def analyze_logic_flaws(api_urls, output_dir):
    ai_engine = AIEngine()
    if not ai_engine.api_key:
        print("[AI] No API Key found, skipping Logic Analysis.")
        return

    print(f"[AI] Analyzing {len(api_urls)} APIs for logic flaws...")
    
    results = []
    # Limit to first 20 APIs to avoid excessive cost in this POC
    # Prioritize APIs that look like they have parameters or ID-like structures
    interesting_urls = [u for u in api_urls if any(x in u for x in ['id', 'user', 'admin', 'order', 'account'])]
    if not interesting_urls:
        interesting_urls = api_urls
        
    for url in interesting_urls[:20]: 
        print(f"[AI] Analyzing: {url}")
        analysis = ai_engine.analyze_api_logic(url)
        if analysis and analysis.get('risk_level') in ['high', 'medium']:
            results.append({
                "url": url,
                "analysis": analysis
            })
    
    if results:
        report_path = os.path.join(output_dir, "ai_logic_analysis.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# AI API Logic Analysis Report\n\n")
            for item in results:
                f.write(f"## {item['url']}\n")
                f.write(f"**Risk Level:** {item['analysis'].get('risk_level')}\n")
                f.write(f"**Potential Vulns:** {', '.join(item['analysis'].get('potential_vulns', []))}\n")
                f.write(f"**Reason:** {item['analysis'].get('reason')}\n")
                f.write("**Suggested Test Cases:**\n")
                for test in item['analysis'].get('test_cases', []):
                    f.write(f"- {test}\n")
                f.write("\n---\n")
        print(f"[AI] Logic Analysis Report saved to {report_path}")
    else:
        print("[AI] No high/medium risk logic flaws detected.")
