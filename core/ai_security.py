#!/usr/bin/env python3
"""
AI基础设施安全检测模块 - 基于 FLUX v5.2.1
检测 Ollama/vLLM/ComfyUI/n8n/Dify 等AI组件
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AIVulnResult:
    """AI安全漏洞结果"""
    vuln_type: str
    severity: str
    url: str
    component: str
    version: str = ""
    detail: str = ""
    evidence: str = ""
    cve_id: str = ""
    remediation: str = ""


class AISecurityTester:
    """AI基础设施安全测试器"""

    AI_COMPONENTS = {
        "Ollama": {
            "fingerprints": ["/api/tags", "/api/generate", "ollama", "Ollama is running"],
            "endpoints": ["/api/tags", "/api/generate", "/api/version", "/api/pull", "/api/create"],
            "unauthorized_test": "/api/tags",
            "version_test": "/api/version",
            "severity": "High"
        },
        "vLLM": {
            "fingerprints": ["vllm", "/v1/completions", "/v1/models", "openai_compatible"],
            "endpoints": ["/v1/models", "/v1/completions", "/v1/chat/completions", "/health"],
            "unauthorized_test": "/v1/models",
            "severity": "High"
        },
        "ComfyUI": {
            "fingerprints": ["comfyui", "/prompt", "workflow", "ComfyUI"],
            "endpoints": ["/prompt", "/object_info", "/history", "/api/systemstats"],
            "unauthorized_test": "/object_info",
            "severity": "High"
        },
        "OpenWebUI": {
            "fingerprints": ["openwebui", "OpenWebUI", "/api/v1/", "chat-completion"],
            "endpoints": ["/api/v1/models", "/api/v1/chat/completions", "/api/v1/config"],
            "unauthorized_test": "/api/v1/models",
            "severity": "High"
        },
        "LangServe": {
            "fingerprints": ["langserve", "LangServe", "/playground", "runnable"],
            "endpoints": ["/playground", "/invoke", "/batch", "/status"],
            "unauthorized_test": "/invoke",
            "severity": "Medium"
        },
        "FastChat": {
            "fingerprints": ["fastchat", "FastChat", "/v1/chat/completions", "model_worker"],
            "endpoints": ["/v1/models", "/v1/chat/completions", "/v1/models/list"],
            "unauthorized_test": "/v1/models",
            "severity": "Medium"
        },
        "Text Generation Inference": {
            "fingerprints": ["text-generation-inference", "tgi", "/generate", "/generate_stream"],
            "endpoints": ["/info", "/generate", "/health", "/metrics"],
            "unauthorized_test": "/info",
            "severity": "Medium"
        },
        "Stable Diffusion WebUI": {
            "fingerprints": ["stable-diffusion-webui", "sd-webui", "/sdapi/v1/", "txt2img"],
            "endpoints": ["/sdapi/v1/sd-models", "/sdapi/v1/txt2img", "/sdapi/v1/img2img", "/sdapi/v1/options"],
            "unauthorized_test": "/sdapi/v1/sd-models",
            "severity": "High"
        },
        "Jupyter Notebook": {
            "fingerprints": ["jupyter", "Jupyter Notebook", "/api/contents", "kernelspecs"],
            "endpoints": ["/api/contents", "/api/sessions", "/tree", "/api/kernels"],
            "unauthorized_test": "/api/contents",
            "severity": "Critical"
        },
        "JupyterLab": {
            "fingerprints": ["jupyterlab", "JupyterLab", "/lab", "/api"],
            "endpoints": ["/api/kernels", "/api/sessions", "/api/terminals"],
            "unauthorized_test": "/api/kernels",
            "severity": "Critical"
        },
        "MLflow": {
            "fingerprints": ["mlflow", "MLflow", "#/experiments", "tracking"],
            "endpoints": ["/api/2.0/mlflow/experiments/list", "/ajax-api/2.0/mlflow/runs/search", "/tracking/"],
            "unauthorized_test": "/api/2.0/mlflow/experiments/list",
            "severity": "High"
        },
        "n8n": {
            "fingerprints": ["n8n", "n8n-workflow", "/rest/workflows", "workflow-maker"],
            "endpoints": ["/rest/workflows", "/rest/executions", "/rest/credentials", "/webhook"],
            "unauthorized_test": "/rest/workflows",
            "severity": "Critical"
        },
        "Dify": {
            "fingerprints": ["dify", "Dify", "/console/api/", "app-maker"],
            "endpoints": ["/console/api/apps", "/console/api/datasets", "/v1/chat/completions", "/v1/init"],
            "unauthorized_test": "/console/api/apps",
            "severity": "High"
        },
        "Flowise": {
            "fingerprints": ["flowise", "Flowise", "/api/v1/", "chatflow"],
            "endpoints": ["/api/v1/chatflows", "/api/v1/credentials", "/api/v1/assistants"],
            "unauthorized_test": "/api/v1/chatflows",
            "severity": "High"
        },
        "LangChain": {
            "fingerprints": ["langchain", "LangChain", "langchain-api", "/langchain/"],
            "endpoints": ["/langchain/playground", "/langchain/invoke", "/langchain/batch"],
            "unauthorized_test": "/langchain/playground",
            "severity": "Medium"
        },
        "ChatGPT-Next-Web": {
            "fingerprints": ["chatgpt-next-web", "NextChat", "_next/static"],
            "endpoints": ["/api/chat", "/api/config"],
            "unauthorized_test": "/api/config",
            "severity": "Medium"
        },
        "LobeChat": {
            "fingerprints": ["lobe-chat", "LobeChat", "/api/chat", "/api/files"],
            "endpoints": ["/api/chat", "/api/files", "/api/plugin"],
            "unauthorized_test": "/api/chat",
            "severity": "Medium"
        },
        "Gradio": {
            "fingerprints": ["gradio", "Gradio", "/api/predict", "/api/state"],
            "endpoints": ["/api/predict", "/api/state", "/api/flagging"],
            "unauthorized_test": "/api/predict",
            "severity": "High"
        },
        "FastGPT": {
            "fingerprints": ["fastgpt", "FastGPT", "/api/chat", "/api"],
            "endpoints": ["/api/chat", "/api/openapi", "/api/v1"],
            "unauthorized_test": "/api/chat",
            "severity": "High"
        },
        "MaxKB": {
            "fingerprints": ["maxkb", "MaxKB", "/api", "/chat"],
            "endpoints": ["/api/chat", "/api/login", "/api/llm"],
            "unauthorized_test": "/api/llm",
            "severity": "High"
        },
        "RAGFlow": {
            "fingerprints": ["ragflow", "RAGFlow", "/api/v1", "/chat"],
            "endpoints": ["/api/v1/chats", "/api/v1/documents", "/api/v1/retrieve"],
            "unauthorized_test": "/api/v1/documents",
            "severity": "High"
        },
        "QAnything": {
            "fingerprints": ["qanything", "QAnything", "/api/chat", "/api/local_doc_qa"],
            "endpoints": ["/api/chat", "/api/local_doc_qa/knowledge_base"],
            "unauthorized_test": "/api/chat",
            "severity": "High"
        },
        "OneAPI": {
            "fingerprints": ["oneapi", "OneAPI", "/api/", "/api/v1/models"],
            "endpoints": ["/api/v1/models", "/api/v1/keys", "/api/channel"],
            "unauthorized_test": "/api/v1/keys",
            "severity": "High"
        },
        "OpenAI-API-Compatible": {
            "fingerprints": ["/v1/models", "/v1/completions", "/v1/embeddings"],
            "endpoints": ["/v1/models", "/v1/completions", "/v1/chat/completions"],
            "unauthorized_test": "/v1/models",
            "severity": "Medium"
        },
        "Xinference": {
            "fingerprints": ["xinference", "Xinference", "/v1/models", "/chat"],
            "endpoints": ["/v1/models", "/v1/chat/completions", "/v1/embeddings"],
            "unauthorized_test": "/v1/models",
            "severity": "High"
        },
        "Triton Inference Server": {
            "fingerprints": ["triton", "triton-server", "/v2/models", "/metrics"],
            "endpoints": ["/v2/models", "/v2/models/list", "/metrics"],
            "unauthorized_test": "/v2/models",
            "severity": "High"
        },
        "Kubeflow": {
            "fingerprints": ["kubeflow", "Kubeflow", "/pipeline/", "/katib/"],
            "endpoints": ["/pipeline/apis/v1/pipelines", "/katib/api/v1/experiments"],
            "unauthorized_test": "/pipeline/apis/v1/pipelines",
            "severity": "Critical"
        },
        "Ray": {
            "fingerprints": ["ray", "Ray", "/api/", "/dashboard/"],
            "endpoints": ["/api/ray/version", "/dashboard/", "/api/cluster_status"],
            "unauthorized_test": "/api/cluster_status",
            "severity": "High"
        },
    }

    AI_CVE_DATABASE = {
        "CVE-2024-37032": {
            "component": "Ollama",
            "description": "Ollama 未授权访问漏洞",
            "severity": "Critical",
            "check": "访问 /api/tags 是否需要认证"
        },
        "CVE-2024-21514": {
            "component": "ComfyUI",
            "description": "ComfyUI 任意文件读取",
            "severity": "High",
            "check": "通过 /api/detail 读取系统文件"
        },
        "CVE-2024-2219": {
            "component": "Dify",
            "description": "Dify 远程代码执行",
            "severity": "Critical",
            "check": "通过 /api/v1/init 或 /console/api/apps 触发"
        },
        "CVE-2024-2222": {
            "component": "Flowise",
            "description": "Flowise 远程代码执行",
            "severity": "Critical",
            "check": "通过 /api/v1/chatflows 触发"
        },
        "CVE-2023-39968": {
            "component": "Jupyter",
            "description": "Jupyter Notebook 远程代码执行",
            "severity": "Critical",
            "check": "通过 /api/contents 上传恶意notebook"
        },
    }

    def __init__(self, session=None, timeout: int = 15):
        self.session = session
        self.timeout = timeout
        self.findings: List[AIVulnResult] = []

    def scan_ai_components(self, base_url: str) -> List[AIVulnResult]:
        findings = []
        parsed_url = base_url if base_url.startswith('http') else f'http://{base_url}'
        
        logger.info(f"[*] 开始AI基础设施扫描: {parsed_url}")

        for component_name, component_info in self.AI_COMPONENTS.items():
            fingerprints = component_info.get('fingerprints', [])
            endpoints = component_info.get('endpoints', [])

            for endpoint in endpoints[:3]:
                url = f"{parsed_url.rstrip('/')}{endpoint}"
                try:
                    response = self.session.get(url, timeout=self.timeout, verify=False)
                    content = response.text.lower()

                    if response.status_code == 200:
                        for fp in fingerprints:
                            if fp.lower() in content or fp in response.text:
                                logger.info(f"[+] 发现AI组件: {component_name} at {url}")

                        finding = self._test_ai_component(
                            url, component_name, component_info, response
                        )
                        if finding:
                            findings.append(finding)
                        break

                except Exception as e:
                    logger.debug(f"[*] {component_name} 检测失败: {e}")

        return findings

    def _test_ai_component(self, url: str, component: str, info: Dict, response) -> Optional[AIVulnResult]:
        severity = info.get('severity', 'Medium')

        if '/api/tags' in url and 'ollama' in component.lower():
            try:
                data = response.json()
                if 'models' in data or len(data) > 0:
                    return AIVulnResult(
                        vuln_type="未授权访问",
                        severity=severity,
                        url=url,
                        component=component,
                        detail="可列出所有模型，可能泄露模型信息",
                        evidence=f"模型数量: {len(data.get('models', data))}"
                    )
            except:
                pass

        if '/v1/models' in url or '/api/models' in url:
            try:
                data = response.json()
                if 'data' in data or 'models' in data:
                    models = data.get('data', data.get('models', []))
                    if isinstance(models, list) and len(models) > 0:
                        model_names = [m.get('id', m.get('name', str(m))) for m in models[:5]]
                        return AIVulnResult(
                            vuln_type="未授权访问",
                            severity=severity,
                            url=url,
                            component=component,
                            detail="可列出所有模型，可能泄露模型信息",
                            evidence=f"发现模型: {', '.join(model_names)}"
                        )
            except:
                pass

        if '/rest/workflows' in url and 'n8n' in component.lower():
            try:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    workflow_names = [w.get('name', 'unnamed') for w in data[:5]]
                    return AIVulnResult(
                        vuln_type="未授权访问工作流",
                        severity=severity,
                        url=url,
                        component=component,
                        detail="可列出所有工作流，可能包含敏感业务流程",
                        evidence=f"发现工作流: {', '.join(workflow_names)}"
                    )
            except:
                pass

        return None

    def check_ai_cve(self, base_url: str) -> List[AIVulnResult]:
        findings = []
        parsed_url = base_url if base_url.startswith('http') else f'http://{base_url}'

        for cve_id, cve_info in self.AI_CVE_DATABASE.items():
            component = cve_info.get('component', '')
            check_method = cve_info.get('check', '')

            if component in self.AI_COMPONENTS:
                info = self.AI_COMPONENTS[component]
                test_endpoint = info.get('unauthorized_test', '/')

                url = f"{parsed_url.rstrip('/')}{test_endpoint}"
                try:
                    response = self.session.get(url, timeout=self.timeout, verify=False)
                    if response.status_code == 200:
                        findings.append(AIVulnResult(
                            vuln_type="CVE-可能性",
                            severity=cve_info.get('severity', 'High'),
                            url=url,
                            component=component,
                            cve_id=cve_id,
                            detail=cve_info.get('description', ''),
                            remediation=f"建议升级 {component} 到最新版本"
                        ))
                except:
                    pass

        return findings

    def get_findings(self) -> List[AIVulnResult]:
        return self.findings

    def clear_findings(self):
        self.findings.clear()


__all__ = ['AISecurityTester', 'AIVulnResult']
