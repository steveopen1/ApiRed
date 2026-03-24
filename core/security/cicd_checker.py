"""
CI/CD Security Module
CI/CD 配置安全检测模块
参考 FLUX v4.3 CI/CD 安全检测实现
检测 11 种 CI/CD 配置文件泄露和敏感信息
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CICDFinding:
    """CI/CD 安全发现"""
    config_type: str
    file_path: str
    severity: str
    token_type: str = ""
    token_value: str = ""
    detail: str = ""


class CICDSecurityChecker:
    """
    CI/CD 安全检测器
    
    检测 11 种 CI/CD 配置文件：
    - GitLab CI (.gitlab-ci.yml)
    - Jenkins (Jenkinsfile, credentials.xml)
    - GitHub Actions (.github/workflows/)
    - Travis CI (.travis.yml)
    - CircleCI (.circleci/config.yml)
    - Drone CI (.drone.yml)
    - Azure Pipelines (azure-pipelines.yml)
    - Docker (Dockerfile, docker-compose.yml)
    - Kubernetes (deployment.yaml, secret.yaml)
    - Ansible (ansible.cfg)
    - Terraform (.tf)
    
    检测 17 种敏感 Token：
    - GitLab Token / Runner Token
    - Jenkins API Token
    - Travis CI / CircleCI Token
    - Docker Hub Token / Registry Auth
    - npm / PyPI / RubyGems Token
    - Slack / Discord Webhook
    """
    
    CONFIG_PATTERNS = {
        'gitlab-ci': [
            r'\.gitlab-ci\.yml',
            r'\.gitlab-ci\.yaml',
            r'gitlab-ci',
        ],
        'jenkins': [
            r'Jenkinsfile',
            r'credentials\.xml',
            r'jenkins_credentials',
        ],
        'github-actions': [
            r'\.github/workflows/[^\/]+\.ya?ml',
            r'github-actions',
        ],
        'travis-ci': [
            r'\.travis\.yml',
            r'\.travis\.yaml',
            r'travis-ci',
        ],
        'circleci': [
            r'\.circleci/config\.yml',
            r'circleci',
        ],
        'drone-ci': [
            r'\.drone\.yml',
            r'\.drone\.star',
            r'drone-ci',
        ],
        'azure-pipelines': [
            r'azure-pipelines\.yml',
            r'azure-pipelines\.yaml',
            r'azure-devops',
        ],
        'docker': [
            r'Dockerfile',
            r'docker-compose\.yml',
            r'docker-compose\.yaml',
            r'\.dockerignore',
        ],
        'kubernetes': [
            r'deployment\.yaml',
            r'service\.yaml',
            r'secret\.yaml',
            r'configmap\.yaml',
            r'ingress\.yaml',
            r'\.kubeconfig',
        ],
        'ansible': [
            r'ansible\.cfg',
            r'inventory\.yml',
            r'playbook\.yml',
        ],
        'terraform': [
            r'providers\.tf',
            r'variables\.tf',
            r'main\.tf',
            r'\.tfstate',
        ],
    }
    
    SENSITIVE_TOKEN_PATTERNS = {
        'gitlab-token': [
            r'GLecret',
            r'gitlab_token',
            r'GITLAB_TOKEN',
            r'gitlab-ci-token',
            r'CI_JOB_TOKEN',
        ],
        'gitlab-runner-token': [
            r'RUNNER_TOKEN',
            r'RUNNER_REGISTRATION_TOKEN',
            r'CI_REGISTRATION_TOKEN',
        ],
        'jenkins-token': [
            r'jenkins_api_token',
            r'JENKINS_API_TOKEN',
            r'apitoken',
            r'password=[^&\s]+',
        ],
        'travis-ci-token': [
            r'TRAVIS_TOKEN',
            r'TRAVIS_API_TOKEN',
            r'\.travis\.yml.*token',
        ],
        'circleci-token': [
            r'CIRCLECI_TOKEN',
            r'circleci_api_token',
            r'PERSONAL_API_TOKEN',
        ],
        'dockerhub-token': [
            r'DOCKERHUB_TOKEN',
            r'DOCKER_PASSWORD',
            r'docker_pass',
            r'DOCKER_AUTH_CONFIG',
        ],
        'npm-token': [
            r'npm_[a-zA-Z0-9]{36}',
            r'//registry\.npmjs\.org/:_authToken=',
        ],
        'pypi-token': [
            r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}',
            r'pip install.*--index-url.*:[a-zA-Z0-9\-_]+@',
        ],
        'rubygems-token': [
            r'rubygems_[a-zA-Z0-9]{48}',
        ],
        'slack-webhook': [
            r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+',
            r'https://[a-zA-Z0-9-]+\.slack\.com/api/chat\.postMessage',
        ],
        'discord-webhook': [
            r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+',
        ],
        'aws-access-key': [
            r'AKIA[0-9A-Z]{16}',
            r'ASIA[0-9A-Z]{16}',
        ],
        'aws-secret-key': [
            r'[A-Za-z0-9/+=]{40}',
        ],
        'github-token': [
            r'ghp_[a-zA-Z0-9]{36}',
            r'gho_[a-zA-Z0-9]{36}',
            r'ghu_[a-zA-Z0-9]{36}',
            r'ghs_[a-zA-Z0-9]{36}',
            r'ghcr_[a-zA-Z0-9]{36}',
        ],
        'private-key': [
            r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
            r'-----BEGIN CERTIFICATE-----',
        ],
        'database-url': [
            r'mysql://[^@]+@[^:]+:[^\s]+',
            r'postgres://[^@]+@[^:]+:[^\s]+',
            r'mongodb://[^@]+@[^:]+:[^\s]+',
            r'redis://[^@]+@[^:]+:[^\s]+',
        ],
    }
    
    ENV_VAR_PATTERNS = {
        'aws_key': [
            r'AWS_ACCESS_KEY_ID',
            r'AWS_SECRET_ACCESS_KEY',
            r'AWS_SESSION_TOKEN',
        ],
        'azure_key': [
            r'AZURE_STORAGE_ACCOUNT',
            r'AZURE_STORAGE_KEY',
            r'AZURE_CLIENT_SECRET',
        ],
        'database_password': [
            r'DATABASE_URL',
            r'DB_PASSWORD',
            r'MYSQL_PASSWORD',
            r'POSTGRES_PASSWORD',
            r'MONGO_PASSWORD',
        ],
        'api_keys': [
            r'API_KEY',
            r'API_SECRET',
            r'REACT_APP_.*=',
        ],
        'private_key': [
            r'PRIVATE_KEY',
            r'SSH_PRIVATE_KEY',
        ],
    }
    
    def __init__(self):
        self.findings: List[CICDFinding] = []
    
    def check_config_exposure(self, content: str, config_type: str) -> bool:
        """
        检测配置文件是否泄露敏感信息
        
        Args:
            content: 文件内容
            config_type: 配置文件类型
            
        Returns:
            bool: 是否存在问题
        """
        is_exposed = False
        
        for token_type, patterns in self.SENSITIVE_TOKEN_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches:
                        finding = CICDFinding(
                            config_type=config_type,
                            file_path=f'**/{config_type}',
                            severity='critical',
                            token_type=token_type,
                            token_value=match[:20] + '***' if len(match) > 20 else match + '***',
                            detail=f'发现敏感 {token_type}'
                        )
                        self.findings.append(finding)
                        is_exposed = True
                        logger.warning(f"CI/CD config exposure: {config_type} - {token_type}")
        
        return is_exposed
    
    def check_env_leakage(self, content: str) -> List[CICDFinding]:
        """
        检测环境变量泄露
        
        Args:
            content: 环境变量文件内容
            
        Returns:
            List[CICDFinding]: 发现的问题
        """
        findings = []
        
        for env_type, patterns in self.ENV_VAR_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(f'{pattern}=([^\s&\'"]+)', content)
                for match in matches:
                    if match and len(match) > 3:
                        finding = CICDFinding(
                            config_type='environment',
                            file_path='.env 或配置文件',
                            severity='high',
                            token_type=env_type,
                            token_value=match[:20] + '***' if len(match) > 20 else match + '***',
                            detail=f'环境变量 {pattern} 疑似泄露'
                        )
                        findings.append(finding)
        
        self.findings.extend(findings)
        return findings
    
    def check_docker_config(self, content: str) -> List[CICDFinding]:
        """
        检测 Docker 配置问题
        
        Args:
            content: Dockerfile 或 docker-compose.yml 内容
            
        Returns:
            List[CICDFinding]: 发现的问题
        """
        findings = []
        
        docker_issues = [
            (r'FROM\s+[a-z0-9/_:]+as\s+[a-z]+', '多阶段构建 - 确认基础镜像安全性'),
            (r'USER\s+root', '以 root 用户运行 - 安全风险'),
            (r'COPY\s+\.+/\s+', '复制整个目录 - 可能包含敏感文件'),
            (r'ENV\s+PASSWORD[^\s]+', '明文密码环境变量'),
            (r'--privileged', '特权容器 - 安全风险'),
            (r'--net=host', '主机网络模式 - 安全风险'),
            (r'volumes?:\s*.*:/', '敏感路径挂载'),
        ]
        
        for pattern, issue in docker_issues:
            if re.search(pattern, content, re.IGNORECASE):
                finding = CICDFinding(
                    config_type='docker',
                    file_path='Dockerfile 或 docker-compose.yml',
                    severity='medium',
                    detail=issue
                )
                findings.append(finding)
        
        self.findings.extend(findings)
        return findings
    
    def check_k8s_config(self, content: str) -> List[CICDFinding]:
        """
        检测 Kubernetes 配置问题
        
        Args:
            content: K8s YAML 配置内容
            
        Returns:
            List[CICDFinding]: 发现的问题
        """
        findings = []
        
        k8s_issues = [
            (r'kubernetes.io/dockerconfigjson', 'Docker 镜像仓库配置'),
            (r'kind:\s*Secret', 'Secret 资源 - 检查是否包含敏感数据'),
            (r'privileged:\s*true', '特权容器 - 安全风险'),
            (r'hostNetwork:\s*true', '主机网络模式'),
            (r'hostPID:\s*true', '共享宿主机 PID'),
            (r'hostIPC:\s*true', '共享宿主机 IPC'),
            (r'replicas:\s*[3-9]|\d{2,}', '高可用副本数'),
        ]
        
        secrets = re.findall(r'name:\s*(\S+secret\S+)', content)
        if secrets:
            finding = CICDFinding(
                config_type='kubernetes',
                file_path='**/*.yaml',
                severity='high',
                token_type='secret',
                detail=f'发现 {len(secrets)} 个 Secret 资源'
            )
            findings.append(finding)
        
        for pattern, issue in k8s_issues:
            if re.search(pattern, content, re.IGNORECASE):
                finding = CICDFinding(
                    config_type='kubernetes',
                    file_path='**/*.yaml',
                    severity='medium',
                    detail=issue
                )
                findings.append(finding)
        
        self.findings.extend(findings)
        return findings
    
    def get_all_findings(self) -> List[CICDFinding]:
        """获取所有发现"""
        return self.findings
    
    def clear_findings(self):
        """清空发现列表"""
        self.findings.clear()


def check_cicd_security(content: str, config_type: str = 'auto') -> List[CICDFinding]:
    """
    便捷函数：检测 CI/CD 安全问题
    """
    checker = CICDSecurityChecker()
    
    if config_type == 'auto':
        for ct, patterns in CICDSecurityChecker.CONFIG_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    config_type = ct
                    break
    
    if config_type == 'docker':
        return checker.check_docker_config(content)
    elif config_type == 'kubernetes':
        return checker.check_k8s_config(content)
    elif config_type != 'auto':
        checker.check_config_exposure(content, config_type)
        return checker.get_all_findings()
    
    return checker.get_all_findings()
