"""
Large Scale Fingerprint Generator
大规模指纹生成器
"""

import yaml
from pathlib import Path


def generate_large_scale_fingerprints():
    """生成大规模指纹库"""
    fingerprints = {}
    
    # AI 组件指纹 - 扩展到 46+
    ai_components = [
        # 推理服务
        {'name': 'Ollama', 'patterns': ['ollama', '/api/tags'], 'headers': ['X-Ollama']},
        {'name': 'vLLM', 'patterns': ['vllm', '/v1/models']},
        {'name': 'TGI (Triton Inference Server)', 'patterns': ['tgi', 'tritonserver']},
        {'name': 'Xinference', 'patterns': ['xinference', '/v1/models']},
        {'name': 'Ray Serve', 'patterns': ['rayserve', '/api/serve']},
        {'name': 'SGLang', 'patterns': ['sglang', '/v1/chat']},
        {'name': 'TensorRT-LLM', 'patterns': ['tensorrt_llm', '/trtllm']},
        {'name': 'DeepSpeed', 'patterns': ['deepspeed', '/v1/chat']},
        {'name': 'Accelerate', 'patterns': ['accelerate', '/api']},
        {'name': 'llama.cpp', 'patterns': ['llama.cpp', '/completion']},
        {'name': 'ggml', 'patterns': ['ggml', '/predict']},
        {'name': 'GPT4All', 'patterns': ['gpt4all', '/v1/chat']},
        {'name': 'LocalAI', 'patterns': ['localai', '/v1/chat']},
        {'name': 'Janus', 'patterns': ['janus', '/api/chat']},
        {'name': 'Mistral.rs', 'patterns': ['mistralrs', '/v1/chat']},
        
        # AI 工作流平台
        {'name': 'n8n', 'patterns': ['n8n', '/webhook', '/rest/node']},
        {'name': 'Dify', 'patterns': ['dify', '/api/providers', '/v1/workflows']},
        {'name': 'Flowise', 'patterns': ['flowise', '/api/v1/prediction']},
        {'name': 'LangFlow', 'patterns': ['langflow', '/api/v1/run']},
        {'name': 'ComfyUI', 'patterns': ['comfyui', '/api/workflow']},
        {'name': 'FastGPT', 'patterns': ['fastgpt', '/api/chat']},
        {'name': 'MaxKB', 'patterns': ['maxkb', '/api/chat']},
        {'name': 'RAGFlow', 'patterns': ['ragflow', '/api/v1/retrieval']},
        {'name': 'ChatQA', 'patterns': ['chatqa', '/api/chat']},
        {'name': 'Strolid', 'patterns': ['strolid', '/api/v1/chat']},
        {'name': 'LibreChat', 'patterns': ['librechat', '/api/chat']},
        {'name': 'NextChat', 'patterns': ['nextchat', '/api/chat']},
        {'name': 'OpenChat', 'patterns': ['openchat', '/api/chat']},
        {'name': 'AIKit', 'patterns': ['aikit', '/api/chat']},
        {'name': 'AutoGPT', 'patterns': ['autogpt', '/api/tasks']},
        {'name': 'AgentGPT', 'patterns': ['agentgpt', '/api/agent']},
        {'name': 'Open Interpreter', 'patterns': ['open-interpreter', '/api/interpreter']},
        {'name': 'Local AI Gateway', 'patterns': ['localai-gateway', '/api/v1/chat']},
        {'name': 'Portkey', 'patterns': ['portkey', '/v1/chat']},
        {'name': 'Weights & Biases W&B', 'patterns': ['wandb', '/wandb/']},
        {'name': 'MLflow', 'patterns': ['mlflow', '/ajax-api']},
        {'name': 'Arize Phoenix', 'patterns': ['arize-phoenix', '/api/v1/traces']},
        {'name': 'Helicone', 'patterns': ['helicone', '/v1/chat']},
        {'name': 'Braintrust', 'patterns': ['braintrust', '/v1/chat']},
        {'name': 'LangSmith', 'patterns': ['langsmith', '/api/v1/chat']},
        {'name': 'PromptLayer', 'patterns': ['promptlayer', '/api/v1/chat']},
        {'name': 'Semantic Cache', 'patterns': ['semantic-cache', '/api/cache']},
        
        # Embedding 服务
        {'name': 'Embedding Service', 'patterns': ['embedding', '/v1/embeddings']},
        {'name': 'Sentence Transformers', 'patterns': ['sentence-transformers', '/encode']},
        {'name': 'Cohere', 'patterns': ['cohere', '/v1/embed']},
        {'name': 'Instructor Embedding', 'patterns': ['instructor', '/v1/embeddings']},
        
        # Vector 数据库
        {'name': 'Pinecone', 'patterns': ['pinecone', '/vectors/upsert']},
        {'name': 'Weaviate', 'patterns': ['weaviate', '/v1/objects']},
        {'name': 'Qdrant', 'patterns': ['qdrant', '/collections']},
        {'name': 'Milvus', 'patterns': ['milvus', '/api/v1/entities']},
        {'name': 'Chroma', 'patterns': ['chromadb', '/api/v1/collections']},
        {'name': 'pgvector', 'patterns': ['pgvector', '/api/v1/embeddings']},
        
        # LLM API 代理
        {'name': 'OneAPI', 'patterns': ['oneapi', '/api/user']},
        {'name': 'NewAPI', 'patterns': ['newapi', '/api/chat']},
        {'name': 'Allor', 'patterns': ['allor', '/v1/chat']},
        {'name': 'Venus', 'patterns': ['venus', '/api/chat']},
        {'name': 'AutoAI Proxy', 'patterns': ['autoai-proxy', '/v1/chat']},
    ]
    fingerprints['ai'] = ai_components
    
    # 扩展 CMS 指纹
    cms_list = []
    cms_names = ['WordPress', 'Drupal', 'Joomla', 'Magento', 'ShopNC', 'ECShop', 'Dedecms', 'PhpCMS', '帝国CMS', 'Discuz', 'PhpOa', 'SiteServer', 'Z-Blog', 'Typecho', 'Emlog', 'PbootCMS', 'DcatAdmin', 'Laravel', 'ThinkPHP', 'Yii2', 'CodeIgniter', 'Symfony', 'CakePHP', 'FuelPHP', 'Phalcon', 'Slim', 'Swoole']
    cms_plugins = {
        'WordPress': ['yoast', 'woocommerce', 'akismet', 'contact-form-7', 'jetpack', 'elementor', 'wpbakery', 'slider-revolution', 'all-in-one-seo', 'wordfence', 'updraftplus', 'wp-super-cache', 'w3-total-cache', 'redis-cache'],
        'Joomla': ['k2', 'virtuemart', 'joomshopping', 'hikashop', 'akeeba', 'aicontacts', 'phocamaps'],
        'Drupal': ['views', 'panels', 'ctools', 'token', 'pathauto', 'xmlsitemap', 'rules'],
    }
    for cms in cms_names:
        patterns = [cms.lower().replace(' ', '-').replace('_', '-'), f'/{cms.lower().replace(" ", "-")}']
        cms_list.append({'name': cms, 'patterns': patterns})
        if cms in cms_plugins:
            for plugin in cms_plugins[cms]:
                cms_list.append({'name': f'{cms} Plugin - {plugin}', 'patterns': [f'/{plugin}']})
    fingerprints['cms'] = cms_list
    
    # 扩展 OA 指纹
    oa_list = []
    oa_names = ['泛微E-cology', '泛微E-mobile', '泛微E-office', '致远OA', '蓝凌OA', '通达OA', '飞致OA', '华天动力OA', '久久OA', '用友NC', '用友U8', '金蝶EAS', '金蝶K3', '钉钉', '企业微信', '飞书', 'Worktile', 'Teambition', 'TAPD', '禅道', 'Redmine', 'Jira', 'Confluence']
    for oa in oa_names:
        oa_list.append({'name': oa, 'patterns': [oa.lower().replace(' ', '-').replace('_', '-')]})
    fingerprints['oa'] = oa_list
    
    # 扩展框架指纹
    framework_list = []
    framework_names = [
        'Spring Boot', 'Spring MVC', 'Spring Security', 'Struts2', 'Hibernate', 'MyBatis', 'JFinal', 'Blade', 'Solon', 'Jboot',
        'Django', 'Flask', 'FastAPI', 'Tornado', 'Pyramid', 'Bottle', 'Web2py', 'Sanic',
        'Express', 'Koa', 'NestJS', 'Egg', 'Next.js', 'Nuxt.js', 'SvelteKit',
        'Laravel', 'ThinkPHP', 'Yii2', 'CodeIgniter', 'Symfony', 'Zend', 'Phalcon', 'Slim',
        'Rails', 'Sinatra', 'Hanami',
        'Gin', 'Echo', 'Fiber', 'Beego', 'Iris', 'Martini',
        'ASP.NET', 'ASP.NET Core', 'NancyFX',
        'React', 'Vue', 'Angular', 'Svelte', 'jQuery', 'Bootstrap', 'TailwindCSS'
    ]
    for fw in framework_names:
        framework_list.append({'name': fw, 'patterns': [fw.lower().replace(' ', '-').replace('.', '')]})
    fingerprints['framework'] = framework_list
    
    # WAF 指纹
    waf_list = []
    intl_wafs = ['Cloudflare', 'AWS WAF', 'Akamai', 'Sucuri', 'Incapsula', 'ModSecurity', 'F5 ASM', 'Imperva', 'Barracuda', 'Citrix NetScaler', 'FortiWeb', 'Palo Alto WAF', 'Radware', 'Sophos', 'Wordfence', 'SiteGround', 'StackPath', 'CloudFront', 'Fastly', 'KeyCDN']
    cn_wafs = ['阿里云盾', '腾讯云WAF', '华为云WAF', '安全狗', '360网站卫士', '知道创宇', '安恒WAF', '长亭雷池', '云锁', 'WebRAY', 'OneWAF', '360云防护', '玄武盾', '创宇盾', 'T级防御']
    for waf in intl_wafs + cn_wafs:
        waf_list.append({'name': waf, 'patterns': [waf.lower().replace(' ', '-').replace('\'', '').replace(' ', '-')]})
    fingerprints['waf'] = waf_list
    
    # 扩展数据库指纹
    db_list = []
    databases = ['MySQL', 'PostgreSQL', 'Oracle', 'MongoDB', 'Redis', 'Memcached', 'Elasticsearch', 'SQL Server', 'SQLite', 'Cassandra', 'CouchDB', 'DynamoDB', 'Neo4j', 'InfluxDB', 'TimescaleDB', 'CockroachDB', 'SingleStore', 'Vertica', 'Sybase', 'Informix', 'Interbase', 'Firebird']
    for db in databases:
        db_list.append({'name': db, 'patterns': [db.lower().replace(' ', '')]})
    fingerprints['database'] = db_list
    
    # 容器指纹
    container_list = [
        {'name': 'Docker', 'patterns': ['docker', '/containers/json']},
        {'name': 'Kubernetes', 'patterns': ['kubernetes', '/api/v1']},
        {'name': 'Harbor', 'patterns': ['harbor', '/c/']},
        {'name': ' Quay', 'patterns': ['quay', '/v1/repositories']},
        {'name': 'Nexus Repository', 'patterns': ['nexus', '/repository']},
        {'name': 'JFrog Artifactory', 'patterns': ['jfrog', '/artifactory']},
        {'name': 'Podman', 'patterns': ['podman', '/containers']},
        {'name': 'Containerd', 'patterns': ['containerd', '/containers']},
        {'name': 'CRI-O', 'patterns': ['cri-o', '/info']},
        {'name': 'Portainer', 'patterns': ['portainer', '/api']},
        {'name': 'Rancher', 'patterns': ['rancher', '/v3']},
        {'name': 'K3s', 'patterns': ['k3s', '/api/k8s']},
        {'name': 'Minikube', 'patterns': ['minikube', '/api']},
        {'name': 'Docker Swarm', 'patterns': ['swarm', '/services']},
    ]
    fingerprints['container'] = container_list
    
    # DevOps 指纹
    devops_list = [
        {'name': 'Jenkins', 'patterns': ['jenkins', '/job/']},
        {'name': 'GitLab', 'patterns': ['gitlab', '/users/sign_in']},
        {'name': 'GitHub Actions', 'patterns': ['github-actions', '/workflows']},
        {'name': 'Travis CI', 'patterns': ['travis-ci', '/api/3/repos']},
        {'name': 'CircleCI', 'patterns': ['circleci', '/api/v1.1/insights']},
        {'name': 'Drone CI', 'patterns': ['drone-ci', '/api/repos']},
        {'name': 'Azure Pipelines', 'patterns': ['azure-devops', '/_apis']},
        {'name': 'TeamCity', 'patterns': ['teamcity', '/httpStat']},
        {'name': 'Bamboo', 'patterns': ['bamboo', '/rest/api']},
        {'name': 'GoCD', 'patterns': ['gocd', '/go/api']},
        {'name': 'Spinnaker', 'patterns': ['spinnaker', '/api/v1']},
        {'name': 'ArgoCD', 'patterns': ['argocd', '/api/v1/argocd']},
        {'name': 'Tekton', 'patterns': ['tekton', '/v1/pipelineruns']},
        {'name': 'Jenkins X', 'patterns': ['jenkins-x', '/jx']},
        {'name': 'GitLab CI', 'patterns': ['gitlab-ci', '/api/4/projects']},
    ]
    fingerprints['cicd'] = devops_list
    
    # K8s 组件指纹
    k8s_list = [
        {'name': 'Kubernetes API Server', 'patterns': ['kubernetes', '/api/v1']},
        {'name': 'etcd', 'patterns': ['etcd', '/v2/keys']},
        {'name': 'kubelet', 'patterns': ['kubelet', '/stats/summary']},
        {'name': 'kube-proxy', 'patterns': ['kube-proxy', '/api/v1/namespaces/kube-proxy']},
        {'name': 'kube-scheduler', 'patterns': ['kube-scheduler', '/metrics']},
        {'name': 'kube-controller-manager', 'patterns': ['kube-controller', '/metrics']},
        {'name': 'coredns', 'patterns': ['coredns', '/api/v1/namespaces/kube-system/services/kube-dns']},
        {'name': 'Prometheus', 'patterns': ['prometheus', '/api/v1/query']},
        {'name': 'Grafana', 'patterns': ['grafana', '/api/ds/query']},
        {'name': 'Alertmanager', 'patterns': ['alertmanager', '/api/v1/alerts']},
        {'name': 'Thanos', 'patterns': ['thanos', '/api/v1/query']},
        {'name': 'Kube-state-metrics', 'patterns': ['kube-state-metrics', '/metrics']},
        {'name': 'Node-Exporter', 'patterns': ['node-exporter', '/metrics']},
        {'name': 'Kube-Prometheus', 'patterns': ['k8s-prometheus', '/api/v1']},
        {'name': 'Weave Scope', 'patterns': ['weave-scope', '/api/topology']},
    ]
    fingerprints['kubernetes'] = k8s_list
    
    return fingerprints


def generate_all():
    """生成完整指纹库"""
    data = generate_large_scale_fingerprints()
    
    output_path = Path(__file__).parent / 'large_scale_fingerprints.yaml'
    
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False)
    
    total = sum(len(v) for v in data.values())
    print(f"Generated {total} fingerprints:")
    for cat, items in data.items():
        print(f"  {cat}: {len(items)}")
    
    return data


if __name__ == '__main__':
    generate_all()
