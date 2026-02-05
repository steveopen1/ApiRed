import requests
import json
import os
import yaml

class AIEngine:
    def __init__(self, api_key=None, base_url=None, model=None):
        # Load config from config.yaml if exists
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
        file_config = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    yaml_config = yaml.safe_load(f)
                    if yaml_config and 'ai_config' in yaml_config:
                        file_config = yaml_config['ai_config']
            except Exception as e:
                print(f"[Warning] Failed to load config.yaml: {e}")

        self.api_key = api_key or os.environ.get("AI_API_KEY") or file_config.get('api_key') or ""
        self.base_url = base_url or os.environ.get("AI_BASE_URL") or file_config.get('base_url') or "https://api.openai.com/v1"
        
        # Sanitize base_url: remove trailing slash and /chat/completions if present
        self.base_url = self.base_url.rstrip('/')
        if self.base_url.endswith('/chat/completions'):
            self.base_url = self.base_url[:-17] # Remove /chat/completions
            self.base_url = self.base_url.rstrip('/')
            
        self.model = model or os.environ.get("AI_MODEL") or file_config.get('model') or "gpt-3.5-turbo"
        
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def chat_completion(self, messages, temperature=0.7):
        if not self.api_key:
            return {"error": "No API Key provided"}
        
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def test_connectivity(self):
        """
        Test connectivity to the LLM service.
        """
        print("[AI] Testing LLM connectivity...")
        try:
            messages = [{"role": "user", "content": "Hello"}]
            result = self.chat_completion(messages)
            if "error" in result:
                print(f"[AI] Connectivity test failed: {result['error']}")
                return False
            print("[AI] Connectivity test passed.")
            return True
        except Exception as e:
            print(f"[AI] Connectivity test failed with exception: {e}")
            return False

    def verify_sensitive_info(self, content, context):
        """
        Verify if the detected content is truly sensitive.
        """
        prompt = f"""
        You are a cybersecurity expert. Analyze the following code snippet which was flagged as potentially containing sensitive information.
        
        Flagged Content: {content}
        
        Context (surrounding code):
        {context}
        
        Determine if this is a FALSE POSITIVE (e.g., example code, test data, variable name without value) or TRUE POSITIVE (actual hardcoded secret, phone number, etc.).
        
        Respond in JSON format:
        {{
            "is_sensitive": boolean,
            "confidence": "high"|"medium"|"low",
            "reason": "short explanation"
        }}
        """
        
        messages = [{"role": "user", "content": prompt}]
        result = self.chat_completion(messages, temperature=0.1)
        
        if "error" in result:
            return None
            
        try:
            content = result['choices'][0]['message']['content']
            # Try to extract JSON if there's extra text
            if "{" in content and "}" in content:
                start = content.find("{")
                end = content.rfind("}") + 1
                json_str = content[start:end]
                return json.loads(json_str)
            return None
        except:
            return None

    def analyze_api_logic(self, url, method="GET"):
        """
        Analyze API URL for potential logic flaws (IDOR, Unauth).
        """
        prompt = f"""
        Analyze the following API endpoint for potential logic vulnerabilities (Unauthorized Access, IDOR).
        
        URL: {url}
        Method: {method}
        
        Identify:
        1. Is it likely an administrative interface?
        2. Does it contain predictable resource IDs (IDOR risk)?
        3. Suggest 1-2 test cases to verify vulnerabilities.
        
        Respond in JSON format:
        {{
            "risk_level": "high"|"medium"|"low",
            "potential_vulns": ["IDOR", "Unauth", ...],
            "test_cases": ["description 1", "description 2"],
            "reason": "explanation"
        }}
        """
         
        messages = [{"role": "user", "content": prompt}]
        result = self.chat_completion(messages, temperature=0.2)
        
        if "error" in result:
            return None
            
        try:
            content = result['choices'][0]['message']['content']
            if "{" in content and "}" in content:
                start = content.find("{")
                end = content.rfind("}") + 1
                json_str = content[start:end]
                return json.loads(json_str)
            return None
        except:
            return None
