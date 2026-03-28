"""
ScanEngine 向后兼容层
提供 ScanEngineCore 到原始 ScanEngine 的适配
"""

from .core import ScanEngineCore


class ScanEngineAdapter(ScanEngineCore):
    """
    ScanEngine 适配器
    
    继承自 ScanEngineCore，同时保持与原始 ScanEngine 的接口兼容。
    允许渐进式迁移：现有代码可以继续使用原始接口，
    新代码可以直接使用模块化的组件。
    
    使用方式：
    ```python
    # 原有方式（继续工作）
    engine = ScanEngine(config)
    await engine.run()
    
    # 新方式（直接使用模块）
    collector = ScanCollector(http_client, config)
    results = await collector.run_collectors()
    ```
    """
    
    def __init__(self, config):
        super().__init__(config)
        self._legacy_mode = True
    
    async def _run_collectors(self):
        """运行采集阶段 - 优先使用新模块，fallback 到原有逻辑"""
        try:
            from .collector import ScanCollector
            
            collector = ScanCollector(self._http_client, self.config)
            self._collector_results = await collector.run_collectors()
        except Exception as e:
            logger.debug(f"Module collector failed, using legacy: {e}")
            await self._run_collectors_legacy()
    
    async def _run_collectors_legacy(self):
        """原有采集逻辑（保留作为 fallback）"""
        self._current_stage = 0
        
        active_collectors = self.config.collectors or ['js', 'api']
        collector_results = {}
        
        if 'js' in active_collectors:
            collector_results['js'] = await self._collect_js()
        
        self._collector_results = collector_results
        
        if 'api' in active_collectors:
            collector_results['api'] = await self._extract_apis()
        
        self._collector_results = collector_results
    
    async def _run_analyzers(self):
        """运行分析阶段"""
        await self._score_apis()
        await self._detect_sensitive()
    
    async def _run_testers(self):
        """运行测试阶段"""
        await self._run_fuzz_test()
        await self._run_vuln_test()
    
    async def _stage_reporting(self):
        """报告生成"""
        pass
