"""
Test Case Library Loader
从 YAML 文件加载测试用例
"""

import os
import yaml
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TestCase:
    """测试用例"""
    id: str
    name: str
    severity: str
    description: str
    vuln_type: str
    method: str
    path: str
    parameters: List[Dict] = field(default_factory=list)
    payloads: List[Any] = field(default_factory=list)
    attack_vectors: List[Dict] = field(default_factory=list)
    bypass_techniques: Dict[str, str] = field(default_factory=dict)
    checks: List[Dict] = field(default_factory=list)
    expected_response: Dict = field(default_factory=dict)
    validation: Dict = field(default_factory=dict)
    remediation: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'severity': self.severity,
            'vuln_type': self.vuln_type,
            'method': self.method,
            'path': self.path,
            'parameters': self.parameters,
            'payloads': self.payloads,
            'attack_vectors': self.attack_vectors,
            'bypass_techniques': self.bypass_techniques,
            'checks': self.checks,
            'expected_response': self.expected_response,
            'validation': self.validation,
            'remediation': self.remediation
        }


@dataclass
class TestCaseLibrary:
    """测试用例库"""
    api_version: str
    category: str
    test_cases: List[TestCase] = field(default_factory=list)
    
    def get_by_vuln_type(self, vuln_type: str) -> List[TestCase]:
        """按漏洞类型获取测试用例"""
        return [tc for tc in self.test_cases if tc.vuln_type == vuln_type]
    
    def get_by_severity(self, severity: str) -> List[TestCase]:
        """按严重程度获取测试用例"""
        return [tc for tc in self.test_cases if tc.severity == severity]
    
    def get_by_id(self, test_id: str) -> Optional[TestCase]:
        """按 ID 获取测试用例"""
        for tc in self.test_cases:
            if tc.id == test_id:
                return tc
        return None
    
    def get_all_vuln_types(self) -> List[str]:
        """获取所有漏洞类型"""
        return list(set(tc.vuln_type for tc in self.test_cases))
    
    def count(self) -> int:
        """获取测试用例总数"""
        return len(self.test_cases)


class TestCaseLoader:
    """测试用例加载器"""
    
    def __init__(self, base_path: Optional[str] = None):
        if base_path is None:
            base_path = Path(__file__).parent
        self.base_path = Path(base_path)
        self._libraries: Dict[str, TestCaseLibrary] = {}
    
    def load(self, category: str = "owasp_api_security") -> TestCaseLibrary:
        """加载测试用例库"""
        if category in self._libraries:
            return self._libraries[category]
        
        yaml_path = self.base_path / f"{category}.yaml"
        
        if not yaml_path.exists():
            raise FileNotFoundError(f"Test case library not found: {yaml_path}")
        
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        test_cases = []
        for tc_data in data.get('test_cases', []):
            test_case = TestCase(
                id=tc_data.get('id', ''),
                name=tc_data.get('name', ''),
                severity=tc_data.get('severity', 'MEDIUM'),
                description=tc_data.get('description', ''),
                vuln_type=tc_data.get('vuln_type', ''),
                method=tc_data.get('method', 'GET'),
                path=tc_data.get('path', ''),
                parameters=tc_data.get('parameters', []),
                payloads=tc_data.get('payloads', []),
                attack_vectors=tc_data.get('attack_vectors', []),
                bypass_techniques=tc_data.get('bypass_techniques', {}),
                checks=tc_data.get('checks', []),
                expected_response=tc_data.get('expected_response', {}),
                validation=tc_data.get('validation', {}),
                remediation=tc_data.get('remediation', '')
            )
            test_cases.append(test_case)
        
        library = TestCaseLibrary(
            api_version=data.get('api_version', '1.0'),
            category=data.get('category', category),
            test_cases=test_cases
        )
        
        self._libraries[category] = library
        return library
    
    def load_all(self) -> Dict[str, TestCaseLibrary]:
        """加载所有测试用例库"""
        libraries = {}
        
        for yaml_file in self.base_path.glob("*.yaml"):
            category = yaml_file.stem
            try:
                libraries[category] = self.load(category)
            except Exception as e:
                print(f"Failed to load {category}: {e}")
        
        return libraries
    
    def get_combined_library(self) -> TestCaseLibrary:
        """获取所有测试用例库的组合"""
        all_libraries = self.load_all()
        
        all_cases = []
        for library in all_libraries.values():
            all_cases.extend(library.test_cases)
        
        return TestCaseLibrary(
            api_version="1.0",
            category="all",
            test_cases=all_cases
        )


def load_default_library() -> TestCaseLibrary:
    """加载默认测试用例库"""
    loader = TestCaseLoader()
    return loader.load("owasp_api_security")


def load_all_libraries() -> Dict[str, TestCaseLibrary]:
    """加载所有测试用例库"""
    loader = TestCaseLoader()
    return loader.load_all()
