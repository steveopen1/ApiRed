"""
CI/CD Integration Module
CI/CD 集成模块

支持:
1. GitHub Actions
2. GitLab CI
3. Jenkins
4. Azure DevOps

参考: Akto CI/CD Integration
"""

import os
import json
import logging
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CIPlatform(Enum):
    """CI/CD 平台"""
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    UNKNOWN = "unknown"


@dataclass
class ScanConfig:
    """扫描配置"""
    target: str
    collectors: List[str]
    testers: List[str]
    output_format: str
    fail_on_severity: str


class CICDIntegrator:
    """
    CI/CD 集成器
    
    生成各种 CI/CD 平台的配置文件
    """

    def __init__(self):
        self.platform = self._detect_platform()

    def _detect_platform(self) -> CIPlatform:
        """检测 CI/CD 平台"""
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            return CIPlatform.GITHUB_ACTIONS
        elif os.environ.get('GITLAB_CI') == 'true':
            return CIPlatform.GITLAB_CI
        elif 'JENKINS_HOME' in os.environ:
            return CIPlatform.JENKINS
        elif 'SYSTEM_ACCESSTOKEN' in os.environ:
            return CIPlatform.AZURE_DEVOPS
        return CIPlatform.UNKNOWN

    def generate_github_actions(self, config: ScanConfig) -> str:
        """生成 GitHub Actions workflow"""
        collectors_str = ','.join(config.collectors)
        testers_str = ','.join(config.testers)
        
        workflow = f"""
name: API Security Scan

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master, develop]
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:
    inputs:
      target:
        description: 'Target URL to scan'
        required: true
        type: string

jobs:
  api-security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Run API Security Scan
        env:
          TARGET_URL: ${{ github.event.inputs.target || vars.DEFAULT_SCAN_TARGET || 'https://api.example.com' }}
        run: |
          python -m core.scan \\
            --target $TARGET_URL \\
            --collectors {collectors_str} \\
            --testers {testers_str} \\
            --output-dir ./scan-results \\
            --format json

      - name: Upload scan results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: scan-results
          path: ./scan-results/
          retention-days: 30

      - name: Generate SARIF report
        if: always()
        run: |
          python -m core.export_sarif \\
            --input ./scan-results \\
            --output ./scan-results/results.sarif

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ./scan-results/results.sarif
          category: api-security-scan

      - name: Post scan summary
        if: always()
        run: |
          python -m core.post_results \\
            --results ./scan-results/summary.json \\
            --platform github

      - name: Set commit status
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const summary = JSON.parse(fs.readFileSync('./scan-results/summary.json', 'utf8'));
            const status = summary.critical_count > 0 ? 'failure' : 'success';
            const description = `Found ${{ summary.critical_count }} critical, ${{ summary.high_count }} high issues`;
            
            await github.rest.repos.createCommitStatus({{
              owner: context.repo.owner,
              repo: context.repo.repo,
              sha: context.sha,
              state: status,
              target_url: 'https://github.com/' + context.repo.owner + '/' + context.repo.repo + '/actions/runs/' + github.run_id,
              description: description,
              context: 'API Security Scan'
            }});
"""
        return workflow

    def generate_gitlab_ci(self, config: ScanConfig) -> str:
        """生成 GitLab CI 配置"""
        return f"""
api-security-scan:
  stage: security
  image: python:3.10-slim
  
  variables:
    TARGET_URL: "$CI_DEFAULT_TARGET_URL"
  
  before_script:
    - pip install -r requirements.txt
  
  script:
    - python -m core.scan \\
      --target $TARGET_URL \\
      --collectors {','.join(config.collectors)} \\
      --testers {','.join(config.testers)} \\
      --output-dir ./scan-results \\
      --format json
  
  artifacts:
    when: always
    paths:
      - ./scan-results/
    expire_in: 30 days
    reports:
      sarif: ./scan-results/results.sarif
  
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
    - if: '$CI_COMMIT_BRANCH == "main"'
    - if: '$CI_COMMIT_BRANCH == "master"'
    - if: '$CI_MERGE_REQUEST_ID'
  
  allow_failure: false
"""

    def generate_jenkinsfile(self, config: ScanConfig) -> str:
        """生成 Jenkinsfile"""
        collectors_str = ','.join(config.collectors)
        testers_str = ','.join(config.testers)
        
        jenkinsfile = f"""pipeline {{
    agent {{ label 'docker' }}
    
    environment {{
        TARGET_URL = "${{ params.TARGET_URL ?: 'https://api.example.com' }}"
    }}
    
    stages {{
        stage('API Security Scan') {{
            steps {{
                sh \"\"\"
                    python -m core.scan \\
                        --target $TARGET_URL \\
                        --collectors {collectors_str} \\
                        --testers {testers_str} \\
                        --output-dir ./scan-results \\
                        --format json
                \"\"\"
            }}
        }}
        
        stage('Generate Report') {{
            steps {{
                sh '''
                    python -m core.export_sarif \\
                        --input ./scan-results \\
                        --output ./scan-results/results.sarif
                '''
            }}
        }}
    }}
    
    post {{
        always {{
            archiveArtifacts artifacts: './scan-results/**/*', fingerprint: true
            publishHTML([
                reportDir: './scan-results',
                reportFiles: 'summary.html',
                reportName: 'API Security Report'
            ])
        }}
    }}
}}

parameters {{
    string(name: 'TARGET_URL', defaultValue: 'https://api.example.com', description: 'Target URL to scan')
}}
"""
        return jenkinsfile

    def get_config(self) -> ScanConfig:
        """从环境变量获取扫描配置"""
        target = os.environ.get('API_SCAN_TARGET', 'https://api.example.com')
        collectors = os.environ.get('API_SCAN_COLLECTORS', 'js,api').split(',')
        testers = os.environ.get('API_SCAN_TESTERS', 'fuzz,vuln').split(',')
        output_format = os.environ.get('API_SCAN_FORMAT', 'json')
        fail_on_severity = os.environ.get('API_SCAN_FAIL_ON_SEVERITY', 'critical')
        
        return ScanConfig(
            target=target,
            collectors=collectors,
            testers=testers,
            output_format=output_format,
            fail_on_severity=fail_on_severity
        )

    def run_in_ci(self, config: ScanConfig) -> Dict[str, Any]:
        """
        在 CI/CD 环境中运行扫描
        
        Returns:
            {success: bool, results: {...}}
        """
        if self.platform == CIPlatform.UNKNOWN:
            logger.warning("Not running in a recognized CI/CD environment")
            return {'success': False, 'error': 'Unknown CI/CD platform'}
        
        try:
            from .engine import ScanEngine, EngineConfig
            
            engine_config = EngineConfig(
                target=config.target,
                collectors=config.collectors,
                testers=config.testers,
                output_dir='./scan-results',
            )
            
            engine = ScanEngine(engine_config)
            result = asyncio.run(engine.run())
            
            severity_counts = self._count_by_severity(result.vulnerabilities)
            
            if config.fail_on_severity in ['critical', 'high']:
                if severity_counts.get(config.fail_on_severity, 0) > 0:
                    logger.error(f"Found {severity_counts[config.fail_on_severity]} {config.fail_on_severity} issues")
                    return {
                        'success': False,
                        'severity_counts': severity_counts,
                        'results': result
                    }
            
            return {
                'success': True,
                'severity_counts': severity_counts,
                'results': result
            }
            
        except Exception as e:
            logger.error(f"CI/CD scan failed: {{e}}")
            return {'success': False, 'error': str(e)}

    def _count_by_severity(self, vulnerabilities: List) -> Dict[str, int]:
        """统计漏洞按严重程度"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts


def create_github_actions_file(config: ScanConfig, output_path: str = '.github/workflows/api-security.yml'):
    """创建 GitHub Actions workflow 文件"""
    integrator = CICDIntegrator()
    content = integrator.generate_github_actions(config)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(content)
    
    logger.info(f"Created GitHub Actions workflow: {output_path}")
    return output_path


def create_gitlab_ci_file(config: ScanConfig, output_path: str = '.gitlab-ci.yml'):
    """创建 GitLab CI 配置文件"""
    integrator = CICDIntegrator()
    content = integrator.generate_gitlab_ci(config)
    
    with open(output_path, 'w') as f:
        f.write(content)
    
    logger.info(f"Created GitLab CI config: {output_path}")
    return output_path


if __name__ == "__main__":
    print("CI/CD Integration Module")
    integrator = CICDIntegrator()
    print(f"Detected platform: {integrator.platform.value}")
