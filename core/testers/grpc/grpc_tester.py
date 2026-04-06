"""
gRPC Security Tester
gRPC协议安全测试模块

测试能力：
1. gRPC服务发现
2. gRPC反射API探测
3. Protocol Buffer消息构造
4. gRPC身份验证测试
5. 服务间通信漏洞检测
"""

import asyncio
import base64
import json
import logging
import re
import struct
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ProtobufEncoder:
    """
    Protocol Buffer消息编码器
    
    支持：
    1. 基础类型编码(int32/int64/string/bool)
    2. 常用wire_type编码
    3. 嵌套消息构造
    """
    
    WIRE_TYPES = {
        0: 'varint',
        1: 'fixed64',
        2: 'length_delimited',
        5: 'fixed32',
    }

    @staticmethod
    def encode_varint(value: int) -> bytes:
        """编码Varint类型"""
        if value < 0:
            value = (1 << 64) + value
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    @staticmethod
    def encode_fixed64(value: float) -> bytes:
        """编码fixed64类型"""
        return struct.pack('<d', value)

    @staticmethod
    def encode_fixed32(value: int) -> bytes:
        """编码fixed32类型"""
        return struct.pack('<I', value)

    @staticmethod
    def encode_string_field(field_number: int, value: str) -> bytes:
        """编码字符串字段 (field_number << 3 | wire_type = field_number << 3 | 2)"""
        encoded_value = value.encode('utf-8')
        result = bytearray()
        result.extend(ProtobufEncoder.encode_varint((field_number << 3) | 2))
        result.extend(ProtobufEncoder.encode_varint(len(encoded_value)))
        result.extend(encoded_value)
        return bytes(result)

    @staticmethod
    def encode_int32_field(field_number: int, value: int) -> bytes:
        """编码int32字段"""
        result = bytearray()
        result.extend(ProtobufEncoder.encode_varint((field_number << 3) | 0))
        result.extend(ProtobufEncoder.encode_varint(value))
        return bytes(result)

    @staticmethod
    def encode_int64_field(field_number: int, value: int) -> bytes:
        """编码int64字段"""
        return ProtobufEncoder.encode_int32_field(field_number, value)

    @staticmethod
    def encode_bool_field(field_number: int, value: bool) -> bytes:
        """编码bool字段"""
        return bytes([(field_number << 3) | 0, 1 if value else 0])

    @staticmethod
    def encode_message(field_number: int, message: 'bytes') -> bytes:
        """编码嵌套消息"""
        result = bytearray()
        result.extend(ProtobufEncoder.encode_varint((field_number << 3) | 2))
        result.extend(ProtobufEncoder.encode_varint(len(message)))
        result.extend(message)
        return bytes(result)

    @classmethod
    def build_message(cls, fields: Dict[int, Any]) -> bytes:
        """
        构建完整ProtoBuf消息
        
        Args:
            fields: {field_number: value} 字典
            value可以是: int, str, bool, bytes
        """
        result = bytearray()
        for field_number, value in fields.items():
            if isinstance(value, int):
                if field_number < 16:
                    result.extend(cls.encode_int32_field(field_number, value))
                else:
                    result.extend(cls.encode_int64_field(field_number, value))
            elif isinstance(value, str):
                result.extend(cls.encode_string_field(field_number, value))
            elif isinstance(value, bool):
                result.extend(cls.encode_bool_field(field_number, value))
            elif isinstance(value, bytes):
                result.extend(cls.encode_message(field_number, value))
        return bytes(result)


@dataclass
class GRPCService:
    """gRPC服务信息"""
    name: str
    host: str
    port: int
    methods: List[str]
    proto_package: str
    reflection_enabled: bool


@dataclass
class GRPCTestResult:
    """gRPC测试结果"""
    service: str
    method: str
    vulnerable: bool
    vulnerability_type: str
    evidence: str
    severity: str


class GRPCTester:
    """
    gRPC安全测试器
    
    支持：
    1. gRPC反射API探测服务和方法
    2. 构造Protocol Buffer请求
    3. 未授权访问测试
    4. 服务间通信漏洞
    """

    GRPC_COMMON_PATHS = [
        '/grpc.reflection.v1alpha.ServerReflection',
        '/grpc.reflection.v1.ServerReflection',
        '/grpc.testing.Test',
        '/api.v1alpha.ApiService',
        '/api.v1.ApiService',
        '/api.v2.ApiService',
    ]

    GRPC_HEADERS = [
        ('Content-Type', 'application/grpc'),
        ('TE', 'trailers'),
        ('grpc-accept-encoding', 'gzip'),
        ('user-agent', 'grpc-go/1.0'),
    ]

    def __init__(self, http_client=None):
        self.http_client = http_client
        self.services: List[GRPCService] = []

    async def discover_services(
        self,
        host: str,
        port: int,
        use_reflection: bool = True
    ) -> List[GRPCService]:
        """
        发现gRPC服务
        
        Args:
            host: 目标主机
            port: 端口
            use_reflection: 是否使用反射API
            
        Returns:
            发现的服务列表
        """
        services = []

        if use_reflection:
            reflection_result = await self._try_reflection_api(host, port)
            if reflection_result:
                services.extend(reflection_result)

        if not services:
            services.extend(await self._probe_common_services(host, port))

        self.services = services
        return services

    async def _try_reflection_api(
        self,
        host: str,
        port: int
    ) -> Optional[List[GRPCService]]:
        """使用gRPC反射API探测"""
        try:
            reflection_services = [
                '/grpc.reflection.v1alpha.ServerReflection',
                '/grpc.reflection.v1.ServerReflection',
            ]

            for service_path in reflection_services:
                url = f'{host}:{port}{service_path}'

                reflection_request = self._build_reflection_request('list_services')
                headers = self._build_grpc_headers()

                try:
                    response = await self.http_client.request(
                        url,
                        'POST',
                        data=reflection_request,
                        headers=headers
                    )

                    if response.status_code == 200:
                        services = self._parse_reflection_response(response.content)
                        if services:
                            return services

                except Exception as e:
                    logger.debug(f"Reflection API failed for {service_path}: {e}")

        except Exception as e:
            logger.debug(f"Reflection discovery failed: {e}")

        return None

    async def _probe_common_services(
        self,
        host: str,
        port: int
    ) -> List[GRPCService]:
        """探测常见gRPC服务"""
        services = []

        for service_path in self.GRPC_COMMON_PATHS:
            url = f'{host}:{port}{service_path}'

            try:
                request = self._build_grpc_request(
                    service_path,
                    'MethodDescriptorProto',
                    b''
                )

                headers = self._build_grpc_headers()

                response = await self.http_client.request(
                    url,
                    'POST',
                    data=request,
                    headers=headers
                )

                if response.status_code != 404:
                    services.append(GRPCService(
                        name=service_path,
                        host=host,
                        port=port,
                        methods=[],
                        proto_package='',
                        reflection_enabled=False
                    ))

            except Exception as e:
                logger.debug(f"Service probe failed for {service_path}: {e}")

        return services

    def _build_grpc_headers(self) -> Dict[str, str]:
        """构建gRPC请求头"""
        headers = dict(self.GRPC_HEADERS)
        headers['grpc-accept-encoding'] = 'identity,gzip'
        return headers

    def _build_grpc_request(
        self,
        service: str,
        method: str,
        message: bytes
    ) -> bytes:
        """构造gRPC请求"""
        grpc_request = bytearray()

        message_size = len(message)
        header = bytearray(5)
        header[0] = 0
        header[1] = (message_size >> 24) & 0xFF
        header[2] = (message_size >> 16) & 0xFF
        header[3] = (message_size >> 8) & 0xFF
        header[4] = message_size & 0xFF

        grpc_request.extend(header)
        grpc_request.extend(message)

        return bytes(grpc_request)

    def build_protobuf_request(
        self,
        service_path: str,
        method_name: str,
        fields: Dict[int, Any]
    ) -> bytes:
        """
        构建ProtoBuf格式的gRPC请求
        
        Args:
            service_path: 服务路径
            method_name: 方法名
            fields: ProtoBuf字段字典 {field_number: value}
            
        Returns:
            完整的gRPC请求字节
        """
        message = ProtobufEncoder.build_message(fields)
        return self._build_grpc_request(service_path, method_name, message)

    def build_grpc_request_with_protobuf(
        self,
        package: str,
        service: str,
        method: str,
        protobuf_message: bytes
    ) -> bytes:
        """
        使用ProtoBuf消息构建gRPC请求
        
        Args:
            package: Proto包名
            service: 服务名
            method: 方法名
            protobuf_message: ProtoBuf编码的消息体
            
        Returns:
            完整的gRPC HTTP/2请求
        """
        full_method = f"/{package}.{service}/{method}"
        
        grpc_request = bytearray()
        grpc_request.extend(self._build_grpc_request('', '', protobuf_message))
        
        return bytes(grpc_request)

    def _build_reflection_request(self, command: str) -> bytes:
        """构造反射API请求"""
        request_data = {
            'listServices': ''
        }

        if command == 'list_services':
            request_data = {
                'host': '',
                'listServices': ''
            }

        message = json.dumps(request_data).encode('utf-8')
        return self._build_grpc_request('', '', message)

    def _parse_reflection_response(self, content: bytes) -> Optional[List[GRPCService]]:
        """解析反射API响应"""
        try:
            if len(content) < 5:
                return None

            message = content[5:]
            decoded = message.decode('utf-8', errors='ignore')

            services = []
            service_names = re.findall(r'"name":\s*"([^"]+)"', decoded)

            for name in service_names:
                if name and not name.startswith('grpc.'):
                    services.append(GRPCService(
                        name=name,
                        host='',
                        port=0,
                        methods=[],
                        proto_package=name.split('.')[-1] if '.' in name else name,
                        reflection_enabled=True
                    ))

            return services if services else None

        except Exception as e:
            logger.debug(f"Reflection response parse failed: {e}")
            return None

    async def test_unauthorized_access(
        self,
        service: GRPCService
    ) -> List[GRPCTestResult]:
        """测试未授权访问"""
        results = []

        if not service.host or not service.port:
            return results

        try:
            empty_request = self._build_grpc_request(
                service.name,
                '',
                b'\x00'
            )

            headers = self._build_grpc_headers()

            response = await self.http_client.request(
                f'{service.host}:{service.port}{service.name}',
                'POST',
                data=empty_request,
                headers=headers
            )

            if response.status_code == 200:
                results.append(GRPCTestResult(
                    service=service.name,
                    method='*',
                    vulnerable=True,
                    vulnerability_type='unauthorized_access',
                    evidence='Empty request processed without authentication',
                    severity='high'
                ))

        except Exception as e:
            logger.debug(f"Unauthorized access test failed: {e}")

        return results

    async def test_method_discovery(
        self,
        service: GRPCService
    ) -> List[str]:
        """发现服务方法"""
        methods = []

        if not service.reflection_enabled:
            common_methods = [
                'Get', 'List', 'Create', 'Update', 'Delete',
                'Describe', 'Inspect', 'Query', 'Fetch', 'Search'
            ]
            methods.extend(common_methods)
            return methods

        try:
            list_request = self._build_reflection_request('list_services')
            headers = self._build_grpc_headers()

            response = await self.http_client.request(
                f'{service.host}:{service.port}/grpc.reflection.v1alpha.ServerReflection',
                'POST',
                data=list_request,
                headers=headers
            )

            if response.status_code == 200:
                method_pattern = r'"name":\s*"([^"]+)\.([^"]+)"'
                matches = re.findall(method_pattern, response.content.decode('utf-8', errors='ignore'))

                for _, method in matches:
                    if method not in methods:
                        methods.append(method)

        except Exception as e:
            logger.debug(f"Method discovery failed: {e}")

        return methods

    async def test_grpc_injection(
        self,
        service: GRPCService,
        method: str
    ) -> List[GRPCTestResult]:
        """测试gRPC注入"""
        results = []

        if not service.host or not service.port:
            return results

        payloads = [
            b'\x00\x00\x00\x00\x00',
            b'{"*": "test"}',
            b'<script>alert(1)</script>',
        ]

        for payload in payloads:
            try:
                request = self._build_grpc_request(
                    service.name,
                    method,
                    payload
                )

                headers = self._build_grpc_headers()

                response = await self.http_client.request(
                    f'{service.host}:{service.port}{service.name}/{method}',
                    'POST',
                    data=request,
                    headers=headers
                )

                if response.status_code == 200:
                    content = response.content.decode('utf-8', errors='ignore')

                    if '<script>' in content or 'error' not in content.lower():
                        results.append(GRPCTestResult(
                            service=service.name,
                            method=method,
                            vulnerable=True,
                            vulnerability_type='grpc_injection',
                            evidence=f'Payload processed: {payload[:20]}',
                            severity='high'
                        ))

            except Exception as e:
                logger.debug(f"gRPC injection test failed: {e}")

        return results


async def test_grpc_services(host: str, port: int, http_client) -> List[GRPCService]:
    """便捷函数：发现gRPC服务"""
    tester = GRPCTester(http_client)
    return await tester.discover_services(host, port)
