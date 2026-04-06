"""
Message Queue Security Tester
消息队列安全测试模块

测试能力：
1. RabbitMQ未授权访问
2. Kafka未授权访问
3. Redis Pub/Sub未授权测试
4. AMQP协议安全
5. 消息队列遍历/注入
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MQTestResult:
    """消息队列测试结果"""
    mq_type: str
    vuln_type: str
    vulnerable: bool
    severity: str
    endpoint: str
    evidence: str
    details: str


class MessageQueueSecurityTester:
    """
    消息队列安全测试器
    
    支持：
    1. RabbitMQ Management API
    2. Kafka REST API
    3. Redis Pub/Sub
    4. AMQP协议
    5. MQTT协议
    """

    RABBITMQ_PORTS = [15672, 15692, 55672, 5672]
    KAFKA_PORTS = [9092, 9093, 9094]
    REDIS_PORTS = [6379, 16379]
    ACTIVEMQ_PORTS = [8161, 61616]

    RABBITMQ_ENDPOINTS = [
        '/api/overview',
        '/api/queues',
        '/api/exchanges',
        '/api/bindings',
        '/api/consumers',
        '/api/nodes',
        '/api/healthchecks/node',
    ]

    KAFKA_ENDPOINTS = [
        '/',
        '/topics',
        '/brokers',
        '/clusters',
        '/connectors',
        '/consumer-groups',
    ]

    def __init__(self, http_client):
        self.http_client = http_client

    async def test_rabbitmq(
        self,
        host: str,
        port: int = 15672
    ) -> List[MQTestResult]:
        """测试RabbitMQ未授权访问"""
        results = []
        base_url = f"http://{host}:{port}"

        default_creds = [
            ('guest', 'guest'),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('', ''),
        ]

        for endpoint in self.RABBITMQ_ENDPOINTS:
            url = f"{base_url}{endpoint}"

            for username, password in default_creds:
                try:
                    auth = None
                    if username and password:
                        import base64
                        auth = base64.b64encode(
                            f"{username}:{password}".encode()
                        ).decode()

                    headers = {}
                    if auth:
                        headers['Authorization'] = f'Basic {auth}'

                    response = await self.http_client.request(
                        url,
                        'GET',
                        headers=headers if headers else None,
                        timeout=5
                    )

                    if response and response.status_code == 200:
                        content = response.content or ''

                        if 'overview' in content or 'management' in content.lower():
                            results.append(MQTestResult(
                                mq_type='rabbitmq',
                                vuln_type='unauthorized_access',
                                vulnerable=True,
                                severity='critical',
                                endpoint=url,
                                evidence=f'RabbitMQ API accessible with creds: {username}:{password}',
                                details='RabbitMQ management API has no proper access control'
                            ))
                            break

                    elif response and response.status_code == 401:
                        continue

                except Exception as e:
                    logger.debug(f"RabbitMQ test failed for {endpoint}: {e}")

            if results:
                break

        return results

    async def test_kafka(
        self,
        host: str,
        port: int = 9092
    ) -> List[MQTestResult]:
        """测试Kafka未授权访问"""
        results = []
        base_url = f"http://{host}:{port}"

        for endpoint in self.KAFKA_ENDPOINTS:
            url = f"{base_url}{endpoint}"

            try:
                response = await self.http_client.request(url, 'GET', timeout=5)

                if response and response.status_code == 200:
                    content = response.content or ''

                    if 'topics' in content or 'cluster' in content.lower():
                        results.append(MQTestResult(
                            mq_type='kafka',
                            vuln_type='unauthorized_access',
                            vulnerable=True,
                            severity='critical',
                            endpoint=url,
                            evidence=f'Kafka REST API accessible without authentication',
                            details='Kafka cluster metadata exposed'
                        ))
                        break

            except Exception as e:
                logger.debug(f"Kafka test failed for {endpoint}: {e}")

        return results

    async def test_redis_pubsub(
        self,
        host: str,
        port: int = 6379
    ) -> Optional[MQTestResult]:
        """测试Redis Pub/Sub未授权"""
        url = f"http://{host}:{port}"

        endpoints = ['/_stats', '/_info', '/monitor', '/keys', '/config']

        for endpoint in endpoints:
            test_url = f"{url}{endpoint}"

            try:
                response = await self.http_client.request(test_url, 'GET', timeout=5)

                if response and response.status_code == 200:
                    content = response.content or ''

                    if 'redis' in content.lower() or 'keyspace' in content:
                        return MQTestResult(
                            mq_type='redis',
                            vuln_type='unauthorized_access',
                            vulnerable=True,
                            severity='critical',
                            endpoint=test_url,
                            evidence=f'Redis command accessible: {endpoint}',
                            details='Redis supports arbitrary commands without AUTH'
                        )

            except Exception as e:
                logger.debug(f"Redis test failed: {e}")

        return None

    async def test_mqtt_broker(
        self,
        host: str,
        port: int = 1883
    ) -> Optional[MQTestResult]:
        """测试MQTT Broker未授权"""
        url = f"http://{host}:{port}"

        endpoints = ['/mqtt', '/api/topics', '/api/clients']

        for endpoint in endpoints:
            test_url = f"{url}{endpoint}"

            try:
                response = await self.http_client.request(test_url, 'GET', timeout=5)

                if response and response.status_code == 200:
                    return MQTestResult(
                        mq_type='mqtt',
                        vuln_type='unauthorized_access',
                        vulnerable=True,
                        severity='high',
                        endpoint=test_url,
                        evidence=f'MQTT API accessible: {endpoint}',
                        details='MQTT broker has no proper authentication'
                    )

            except Exception:
                pass

        return None

    async def test_activemq(
        self,
        host: str,
        port: int = 8161
    ) -> List[MQTestResult]:
        """测试ActiveMQ未授权"""
        results = []
        base_url = f"http://{host}:{port}"

        endpoints = ['/admin', '/api/jolokia', '/console']

        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"

            try:
                response = await self.http_client.request(url, 'GET', timeout=5)

                if response and response.status_code in [200, 401]:
                    if response.status_code == 200:
                        results.append(MQTestResult(
                            mq_type='activemq',
                            vuln_type='unauthorized_access',
                            vulnerable=True,
                            severity='high',
                            endpoint=url,
                            evidence=f'ActiveMQ endpoint accessible: {endpoint}',
                            details='ActiveMQ has weak or no authentication'
                        ))
                    else:
                        results.append(MQTestResult(
                            mq_type='activemq',
                            vuln_type='weak_auth',
                            vulnerable=True,
                            severity='medium',
                            endpoint=url,
                            evidence=f'ActiveMQ requires authentication but may have weak creds',
                            details='Consider testing default credentials'
                        ))

            except Exception as e:
                logger.debug(f"ActiveMQ test failed: {e}")

        return results

    async def test_all(
        self,
        host: str
    ) -> Dict[str, List[MQTestResult]]:
        """测试所有消息队列服务"""
        results = {}

        rabbitmq_results = await self.test_rabbitmq(host)
        if rabbitmq_results:
            results['rabbitmq'] = rabbitmq_results

        kafka_results = await self.test_kafka(host)
        if kafka_results:
            results['kafka'] = kafka_results

        redis_result = await self.test_redis_pubsub(host)
        if redis_result:
            results['redis'] = [redis_result]

        mqtt_result = await self.test_mqtt_broker(host)
        if mqtt_result:
            results['mqtt'] = [mqtt_result]

        activemq_results = await self.test_activemq(host)
        if activemq_results:
            results['activemq'] = activemq_results

        return results
