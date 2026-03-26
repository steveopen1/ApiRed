"""
全场景API采集和Fuzzing测试
覆盖：金融/医疗/科技/工厂/政府/军队等行业的API路径模式

测试目标：
1. 验证不同行业的API路径词表覆盖率
2. 测试接口拼接算法在各类场景下的成功率
3. 确保敏感路径和业务动作被正确探测
"""

import asyncio
import logging
from typing import Dict, List, Set, Tuple, Any
from dataclasses import dataclass
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import core.engine as engine_module
    ENGINE_PATH = engine_module.__file__
except:
    ENGINE_PATH = os.path.join(os.path.dirname(__file__), '..', 'core', 'engine.py')

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


@dataclass
class IndustryScenario:
    """行业场景"""
    name: str
    description: str
    typical_prefixes: List[str]
    business_resources: List[str]
    action_suffixes: List[str]
    sensitive_paths: List[str]
    test_urls: List[str]


INDUSTRY_SCENARIOS = {
    "金融 Banking": IndustryScenario(
        name="金融 Banking",
        description="银行、证券、保险、支付等金融机构",
        typical_prefixes=["api", "v1", "v2", "open", "gateway", "ws", "Async"],
        business_resources=[
            "account", "accounts", "user", "users", "card", "cards", "loan", "loans",
            "transfer", "transfers", "payment", "payments", "transaction", "transactions",
            "balance", "withdraw", "deposit", "exchange", "currency", "rate", "interest",
            "credit", "debit", "investment", "fund", "funds", "stock", "bond", "asset",
            "insurance", "claim", "claims", "policy", "policies", "premium", "underwriting",
            "merchant", "merchants", "pos", "atmp", "branch", "branches", "teller",
            "settlement", "clearing", "reconciliation", "audit", "compliance", "aml", "kyc"
        ],
        action_suffixes=[
            "login", "logout", "register", "signup", "signin", "signout",
            "transfer", "pay", "withdraw", "deposit", "query", "search", "history",
            "balance", "detail", "list", "apply", "approve", "reject", "submit",
            "verify", "confirm", "cancel", "refund", "recharge", "exchange",
            "calculate", "simulate", "report", "export", "import", "download",
            "auth", "token", "refresh", "bind", "unbind", "active", "freeze"
        ],
        sensitive_paths=[
            "/admin", "/manager", "/operator", "/audit", "/compliance",
            "/internal", "/monitor", "/health", "/metrics", "/swagger",
            "/api/admin", "/api/manager", "/api/internal", "/api/v1/admin"
        ],
        test_urls=[
            "/api/v1/account/list",
            "/api/v2/transfer/pay",
            "/open/v1/payment/query",
            "/gateway/v1/transaction/search",
            "/api/user/balance",
            "/api/auth/login",
            "/api/auth/token",
            "/api/loan/apply",
            "/api/insurance/claim",
            "/api/merchant/settlement"
        ]
    ),
    
    "医疗 Healthcare": IndustryScenario(
        name="医疗 Healthcare",
        description="医院、诊所、药店、医疗平台、健康管理",
        typical_prefixes=["api", "v1", "v2", "his", "emr", "lis", "pacs", "gateway"],
        business_resources=[
            "patient", "patients", "doctor", "doctors", "nurse", "nurses", "department",
            "departments", "hospital", "hospitals", "clinic", "clinics", "ward", "wards",
            "bed", "beds", "appointment", "appointments", "schedule", "schedules",
            "prescription", "prescriptions", "diagnosis", "diagnoses", "treatment", "treatments",
            "medical_record", "medical_records", "lab", "labs", "examination", "examinations",
            "imaging", "radiology", "pacs", "report", "reports", "health", "healths",
            "drug", "drugs", "medicine", "medicines", "pharmacy", "pharmacies",
            "insurance", "claim", "claims", "billing", "payment", "payments",
            "vaccine", "vaccines", "test", "tests", "result", "results", "specimen",
            "surgery", "surgeries", "operation", "operations", "anesthesia", "recovery"
        ],
        action_suffixes=[
            "register", "login", "logout", "appointment", "schedule", "booking",
            "admission", "discharge", "transfer", "refer", "consult", "diagnose",
            "prescribe", "dispense", "administer", "record", "report", "query",
            "search", "list", "detail", "history", "followup", "track", "monitor",
            "alert", "notify", "approve", "reject", "submit", "save", "update",
            "image", "view", "download", "upload", "export", "print", "verify"
        ],
        sensitive_paths=[
            "/admin", "/doctor", "/nurse", "/pharmacy", "/laboratory",
            "/api/patient/record", "/api/doctor/prescribe", "/api/emr",
            "/api/his", "/api/lis", "/api/pacs", "/internal", "/swagger"
        ],
        test_urls=[
            "/api/v1/patient/register",
            "/api/v2/appointment/schedule",
            "/api/doctor/prescribe",
            "/api/emr/record/detail",
            "/api/lis/result/query",
            "/api/pacs/image/view",
            "/api/pharmacy/dispense",
            "/api/billing/payment",
            "/api/hospital/department/list",
            "/api/health/record/search"
        ]
    ),
    
    "科技 Technology": IndustryScenario(
        name="科技 Technology",
        description="SaaS、云服务、开发者平台、社交网络、电商",
        typical_prefixes=["api", "v1", "v2", "v3", "rest", "graphql", "rpc", "gateway", "open"],
        business_resources=[
            "user", "users", "account", "accounts", "profile", "profiles",
            "product", "products", "service", "services", "order", "orders",
            "payment", "payments", "subscription", "subscriptions", "plan", "plans",
            "invoice", "invoices", "receipt", "receipts", "transaction", "transactions",
            "project", "projects", "workspace", "workspaces", "team", "teams",
            "file", "files", "folder", "folders", "document", "documents",
            "comment", "comments", "post", "posts", "article", "articles",
            "message", "messages", "notification", "notifications", "feed", "feeds",
            "search", "analytics", "report", "reports", "dashboard", "dashboards",
            "setting", "settings", "integration", "integrations", "webhook", "webhooks",
            "key", "keys", "secret", "secrets", "token", "tokens", "oauth", "sso",
            "domain", "domains", "ssl", "certificate", "certificates", "cdn", "dns"
        ],
        action_suffixes=[
            "login", "logout", "register", "signup", "signin", "signout",
            "list", "get", "create", "update", "delete", "remove", "edit",
            "search", "query", "filter", "sort", "page", "aggregate",
            "upload", "download", "export", "import", "sync", "backup",
            "invite", "join", "leave", "approve", "reject", "join",
            "subscribe", "unsubscribe", "follow", "unfollow", "like", "share",
            "send", "receive", "read", "mark", "archive", "restore",
            "enable", "disable", "activate", "deactivate", "reset", "refresh",
            "verify", "validate", "confirm", "authorize", "revoke", "bind"
        ],
        sensitive_paths=[
            "/admin", "/root", "/dashboard", "/api/admin", "/api/v1/admin",
            "/api/keys", "/api/secrets", "/api/integrations", "/internal",
            "/.git", "/.env", "/swagger", "/api-docs", "/debug", "/health",
            "/api/v1/user/profile", "/api/v2/billing/invoice", "/api/v3/project/settings"
        ],
        test_urls=[
            "/api/v1/user/profile",
            "/api/v2/project/list",
            "/api/v3/workspace/teams",
            "/api/graphql",
            "/api/rest/file/upload",
            "/api/gateway/auth/login",
            "/api/subscription/active",
            "/api/webhook/configure",
            "/api/oauth/authorize",
            "/api/integration/list"
        ]
    ),
    
    "工厂 Manufacturing": IndustryScenario(
        name="工厂 Manufacturing",
        description="工业自动化、智能制造、SCADA、PLC设备管理",
        typical_prefixes=["api", "v1", "v2", "iot", "scada", "gateway", "mqtt", "modbus"],
        business_resources=[
            "device", "devices", "sensor", "sensors", "machine", "machines", "equipment",
            "equipment", " plc", "plcs", "controller", "controllers", "robot", "robots",
            "production", "productions", "line", "lines", "workorder", "workorders",
            "product", "products", "batch", "batches", "material", "materials",
            "inventory", "inventories", "warehouse", "warehouses", "storage", "storages",
            "quality", "inspection", "inspections", "defect", "defects", "rework",
            "process", "processes", "parameter", "parameters", "recipe", "recipes",
            "alert", "alerts", "alarm", "alarms", "event", "events", "log", "logs",
            "report", "reports", "statistics", "analytics", "dashboard", "dashboards",
            "user", "users", "role", "roles", "permission", "permissions",
            "config", "configuration", "firmware", "ota", "update", "updates"
        ],
        action_suffixes=[
            "login", "logout", "register", "control", "start", "stop", "pause", "resume",
            "monitor", "track", "collect", "upload", "download", "sync", "backup",
            "configure", "setup", "calibrate", "diagnose", "maintain", "update",
            "alert", "notify", "acknowledge", "reset", "clear", "enable", "disable",
            "read", "write", "query", "search", "list", "detail", "history", "export",
            "produce", "start", "complete", "pause", "cancel", "quality_check",
            "inspect", "approve", "reject", "trace", "track", "optimize", "simulate"
        ],
        sensitive_paths=[
            "/admin", "/manager", "/scada", "/iot", "/plc", "/gateway",
            "/api/device/control", "/api/plc/read", "/api/sensor/collect",
            "/api/production/start", "/api/maintenance/schedule",
            "/internal", "/debug", "/swagger", "/api-docs", "/health"
        ],
        test_urls=[
            "/api/v1/device/list",
            "/api/iot/sensor/data",
            "/api/scada/monitor/alerts",
            "/api/production/workorder/start",
            "/api/quality/inspection/report",
            "/api/warehouse/inventory",
            "/api/maintenance/schedule",
            "/api/ota/update",
            "/api/analytics/production",
            "/api/firmware/upload"
        ]
    ),
    
    "政府 Government": IndustryScenario(
        name="政府 Government",
        description="政务平台、公共服务、智慧城市、应急管理",
        typical_prefixes=["api", "v1", "v2", "v3", "open", "public", "gateway", "ws"],
        business_resources=[
            "citizen", "citizens", "resident", "residents", "user", "users",
            "service", "services", "affair", "affairs", "permit", "permits",
            "license", "licenses", "certificate", "certificates", "approval", "approvals",
            "document", "documents", "record", "records", "archive", "archives",
            "department", "departments", "office", "offices", "bureau", "bureaus",
            "region", "regions", "district", "districts", "province", "provinces",
            "city", "cities", "county", "counties", "street", "streets", "address", "addresses",
            "population", "demographics", "census", "statistics", "analytics",
            "petition", "petitions", "proposal", "proposals", "feedback", "suggestions",
            "announcement", "announcements", "news", "policies", "regulations",
            "inspection", "inspections", "supervision", "audit", "compliance",
            "emergency", "emergencies", "disaster", "disasters", "relief", "shelter",
            "traffic", "transportation", "parking", "environmental", "environmental"
        ],
        action_suffixes=[
            "login", "logout", "register", "signup", "apply", "submit", "query", "search",
            "approve", "reject", "process", "handle", "track", "status", "progress",
            "list", "detail", "history", "record", "archive", "restore", "export",
            "verify", "validate", "confirm", "notify", "alert", "publish", "announce",
            "schedule", "appointment", "booking", "queue", "payment", "fee", "charge",
            "report", "statistics", "analytics", "survey", "assess", "evaluate"
        ],
        sensitive_paths=[
            "/admin", "/system", "/internal", "/management", "/api/admin",
            "/api/manager", "/api/audit", "/api/department", "/api/office",
            "/api/emergency", "/api/security", "/api/monitor",
            "/swagger", "/api-docs", "/debug", "/health", "/.git", "/.env"
        ],
        test_urls=[
            "/api/v1/citizen/service/apply",
            "/api/v2/document/certificate/issue",
            "/api/open/permit/search",
            "/api/approval/workflow/track",
            "/api/announcement/publish",
            "/api/statistics/population",
            "/api/emergency/alert",
            "/api/inspection/schedule",
            "/api/feedback/submit",
            "/api/queue/appointment"
        ]
    ),
    
    "军队 Military": IndustryScenario(
        name="军队 Military",
        description="军事指挥、情报、后勤、装备管理系统(模拟场景)",
        typical_prefixes=["api", "v1", "v2", "secure", "encrypted", "gateway", "tactical"],
        business_resources=[
            "personnel", "troop", "troops", "unit", "units", "squad", "squads", "platoon", "platoons",
            "company", "companies", "battalion", "battalions", "regiment", "regiments",
            "brigade", "brigades", "division", "divisions", "corps", "command", "commands",
            "mission", "missions", "operation", "operations", "task", "tasks", "order", "orders",
            "intel", "intelligence", "surveillance", "reconnaissance", "scout", "scouts",
            "equipment", "weapons", "vehicles", "aircraft", "ships", "supplies", "logistics",
            "communication", "communications", "signal", "signals", "cryptography", "cipher",
            "security", "clearance", "classification", "access", "authentication", "authorization",
            "report", "reports", "briefing", "briefings", "debrief", "debriefs",
            "map", "maps", "location", "locations", "position", "positions", "gps", "coordinate",
            "radar", "sonar", "jamming", "electronic_warfare", "cyber", "network", "it",
            "training", "exercises", "drills", "simulation", "readiness", "assessment"
        ],
        action_suffixes=[
            "login", "logout", "authenticate", "authorize", "access", "clear",
            "deploy", "activate", "deactivate", "standby", "engage", "disengage",
            "monitor", "track", "locate", "identify", "classify", "analyze",
            "report", "brief", "debrief", "transmit", "receive", "encode", "decode",
            "encrypt", "decrypt", "secure", "verify", "validate", "authenticate",
            "control", "command", "coordinate", "synchronize", "schedule", "plan",
            "assess", "evaluate", "train", "exercise", "drill", "simulate",
            "maintain", "repair", "supply", "equip", "arm", "disarm", "refuel"
        ],
        sensitive_paths=[
            "/admin", "/secure", "/classified", "/topsecret", "/confidential",
            "/api/secure/personnel", "/api/command/deploy", "/api/intel/analyze",
            "/api/logistics/supply", "/api/equipment/maintain",
            "/internal", "/debug", "/swagger", "/api-docs"
        ],
        test_urls=[
            "/api/v1/secure/personnel/list",
            "/api/command/operation/deploy",
            "/api/intel/surveillance/report",
            "/api/logistics/supply/track",
            "/api/equipment/weapons/maintain",
            "/api/communication/secure/transmit",
            "/api/training/exercise/schedule",
            "/api/security/clearance/verify",
            "/api/maps/location/coordinate",
            "/api/cyber/network/monitor"
        ]
    ),
    
    "教育 Education": IndustryScenario(
        name="教育 Education",
        description="学校管理、在线教育、学习平台、图书馆",
        typical_prefixes=["api", "v1", "v2", "learning", "edu", "school", "campus"],
        business_resources=[
            "student", "students", "teacher", "teachers", "professor", "professors",
            "course", "courses", "class", "classes", "lesson", "lessons", "lecture", "lectures",
            "assignment", "assignments", "homework", "exam", "exams", "quiz", "quizzes",
            "grade", "grades", "score", "scores", "transcript", "transcripts",
            "enrollment", "enrollments", "registration", "schedule", "schedules",
            "attendance", "presence", "absence", "leave", "vacation",
            "department", "departments", "major", "majors", "faculty", "faculties",
            "school", "schools", "college", "colleges", "university", "universities",
            "library", "libraries", "book", "books", "journal", "journals", "publication",
            "resource", "resources", "material", "materials", "content", "contents",
            "discussion", "discussions", "forum", "forums", "announcement", "announcements",
            "parent", "parents", "guardian", "guardians", "family",
            "fee", "fees", "payment", "payments", "scholarship", "scholarships",
            "certificate", "certificates", "diploma", "diplomas", "degree", "degrees"
        ],
        action_suffixes=[
            "login", "logout", "register", "signup", "enroll", "withdraw", "drop",
            "submit", "hand_in", "grade", "score", "evaluate", "assess",
            "attend", "present", "absent", "excuse", "leave",
            "list", "search", "query", "browse", "preview", "view", "download",
            "upload", "share", "collaborate", "discuss", "comment",
            "schedule", "book", "appointment", "remind", "notify",
            "pay", "refund", "scholarship", "waive", "exempt",
            "certificate", "verify", "authenticate", "authorize"
        ],
        sensitive_paths=[
            "/admin", "/teacher", "/faculty", "/management", "/api/admin",
            "/api/teacher/grade", "/api/student/record", "/api/finance/payment",
            "/internal", "/debug", "/swagger", "/api-docs", "/health"
        ],
        test_urls=[
            "/api/v1/student/course/list",
            "/api/v2/assignment/submit",
            "/api/learning/lecture/view",
            "/api/exam/quiz/start",
            "/api/attendance/record",
            "/api/grade/score/report",
            "/api/enrollment/register",
            "/api/library/book/search",
            "/api/discussion/forum/post",
            "/api/payment/fee/submit"
        ]
    ),
    
    "能源 Energy": IndustryScenario(
        name="能源 Energy",
        description="电力、石油、天然气、新能源、电网管理",
        typical_prefixes=["api", "v1", "v2", "ems", "scada", "iot", "gateway", "monitor"],
        business_resources=[
            "plant", "plants", "station", "stations", "substation", "substations",
            "transformer", "transformers", "generator", "generators", "turbine", "turbines",
            "power", "powers", "grid", "grids", "network", "networks", "system", "systems",
            "meter", "meters", "reading", "readings", "consumption", "usage",
            "oil", "oils", "gas", "gases", "petroleum", "refinery", "refineries",
            "pipeline", "pipelines", "tank", "tanks", "storage", "storages",
            "solar", "wind", "hydro", "nuclear", "renewable", "energy", "energies",
            "production", "productions", "output", "outputs", "capacity", "capacities",
            "load", "loads", "demand", "demands", "supply", "supplies", "distribution",
            "maintenance", "inspections", "repair", "fault", "faults", "incident", "incidents",
            "alert", "alerts", "alarm", "alarms", "event", "events", "log", "logs",
            "user", "users", "customer", "customers", "account", "accounts", "billing"
        ],
        action_suffixes=[
            "login", "logout", "monitor", "control", "operate", "dispatch",
            "start", "stop", "shutdown", "emergency", "reset", "calibrate",
            "read", "measure", "collect", "upload", "sync", "backup",
            "alert", "notify", "alarm", "acknowledge", "clear",
            "maintain", "repair", "inspect", "test", "commission",
            "report", "statistics", "analytics", "forecast", "optimize",
            "balance", "allocate", "schedule", "plan", "simulate",
            "search", "query", "list", "detail", "history", "export", "import"
        ],
        sensitive_paths=[
            "/admin", "/control", "/dispatch", "/ems", "/scada",
            "/api/plant/control", "/api/grid/monitor", "/api/substation/operate",
            "/api/maintenance/schedule", "/api/alert/acknowledge",
            "/internal", "/debug", "/swagger", "/api-docs", "/health"
        ],
        test_urls=[
            "/api/v1/plant/monitor",
            "/api/ems/grid/balance",
            "/api/scada/substation/read",
            "/api/meter/reading/collect",
            "/api/production/output/report",
            "/api/maintenance/schedule",
            "/api/alert/alarm/acknowledge",
            "/api/billing/customer/account",
            "/api/renewable/solar/stats",
            "/api/incident/fault/report"
        ]
    ),
    
    "交通 Transportation": IndustryScenario(
        name="交通 Transportation",
        description="物流、运输、车联网、快递、航运、航空",
        typical_prefixes=["api", "v1", "v2", "logistics", " TMS", "wms", "gateway"],
        business_resources=[
            "order", "orders", "shipment", "shipments", "package", "packages", "parcel", "parcels",
            "vehicle", "vehicles", "truck", "trucks", "driver", "drivers", "fleet", "fleets",
            "route", "routes", "waypoint", "waypoints", "destination", "destinations",
            "warehouse", "warehouses", "storage", "storages", "inventory", "inventories",
            "customer", "customers", "sender", "senders", "receiver", "receivers",
            "tracking", "track", "history", "status", "location", "locations", "gps",
            "delivery", "deliveries", "pickup", "pickups", "courier", "couriers",
            "express", "standard", "freight", "cargo", "container", "containers",
            "airline", "airlines", "flight", "flights", "airport", "airports",
            "port", "ports", "shipping", "vessel", "vessels", "voyage", "voyages",
            "schedule", "schedules", "booking", "reservations", "ticket", "tickets"
        ],
        action_suffixes=[
            "login", "logout", "register", "create", "update", "cancel", "delete",
            "track", "trace", "locate", "monitor", "status", "history", "detail",
            "book", "reserve", "schedule", "assign", "dispatch", "route",
            "pickup", "deliver", "return", "exchange", "refund",
            "calculate", "estimate", "quote", "price", "cost", "fee",
            "notify", "alert", "message", "report", "export", "import", "upload", "download"
        ],
        sensitive_paths=[
            "/admin", "/manager", "/driver", "/courier", "/api/admin",
            "/api/fleet/vehicle", "/api/dispatch/route", "/api/tracking/status",
            "/internal", "/debug", "/swagger", "/api-docs", "/health"
        ],
        test_urls=[
            "/api/v1/order/create",
            "/api/v2/shipment/track",
            "/api/logistics/vehicle/monitor",
            "/api/driver/route/dispatch",
            "/api/warehouse/inventory",
            "/api/booking/reserve",
            "/api/tracking/location/gps",
            "/api/freight/cargo/manage",
            "/api/flight/schedule/search",
            "/api/vessel/voyage/track"
        ]
    ),
    
    "零售 Retail": IndustryScenario(
        name="零售 Retail",
        description="电商、门店、POS、会员管理、供应链",
        typical_prefixes=["api", "v1", "v2", "open", "merchant", "pos", "store"],
        business_resources=[
            "product", "products", "goods", "item", "items", "sku", "merchandise",
            "category", "categories", "catalog", "catalogs", "brand", "brands",
            "price", "prices", "promotion", "promotions", "discount", "discounts", "coupon", "coupons",
            "order", "orders", "cart", "carts", "wishlist", "wishlists",
            "customer", "customers", "member", "members", "vip", "vips",
            "address", "addresses", "payment", "payments", "shipping", "deliveries",
            "store", "stores", "shop", "shops", "warehouse", "warehouses",
            "inventory", "inventories", "stock", "stocks", "supplier", "suppliers",
            "purchase", "purchases", "procurement", "supply", "supplies", "chain",
            "report", "reports", "statistics", "analytics", "dashboard",
            "comment", "comments", "review", "reviews", "rating", "ratings",
            "recommend", "recommendations", "similar", "related"
        ],
        action_suffixes=[
            "login", "logout", "register", "signup", "login", "search", "browse", "filter",
            "detail", "info", "list", "page", "query", "suggest", "autocomplete",
            "cart", "add", "remove", "update", "clear", "checkout", "pay",
            "order", "create", "cancel", "modify", "track", "confirm", "complete",
            "favorite", "like", "unlike", "share", "comment", "review", "rate",
            "coupon", "apply", "redeem", "promotion", "discount", "calculate",
            "address", "save", "default", "delete", "shipping", "calculate", "select",
            "payment", "method", "wechat", "alipay", "card", "refund"
        ],
        sensitive_paths=[
            "/admin", "/merchant", "/api/admin", "/api/merchant/dashboard",
            "/api/order/manage", "/api/inventory/stock",
            "/internal", "/debug", "/swagger", "/api-docs", "/health"
        ],
        test_urls=[
            "/api/v1/product/list",
            "/api/v2/cart/add",
            "/api/order/create",
            "/api/payment/checkout",
            "/api/customer/member/login",
            "/api/promotion/coupon/apply",
            "/api/comment/review/list",
            "/api/warehouse/inventory/query",
            "/api/supply/purchase/order",
            "/api/analytics/sales/report"
        ]
    ),
    
    "物联网 IoT": IndustryScenario(
        name="物联网 IoT",
        description="智能家居、设备管理、边缘计算、传感器网络",
        typical_prefixes=["api", "v1", "v2", "iot", "mqtt", "coap", "gateway", "edge"],
        business_resources=[
            "device", "devices", "thing", "things", "sensor", "sensors", "actuator", "actuators",
            "gateway", "gateways", "hub", "hubs", "controller", "controllers",
            "home", "homes", "room", "rooms", "scene", "scenes", "automation",
            "camera", "cameras", "doorbell", "doorbells", "lock", "locks",
            "light", "lights", "switch", "switches", "outlet", "outlets",
            "thermostat", "thermostats", "ac", "heater", "humidifier", "purifier",
            "tv", "television", "speaker", "speakers", "display", "displays",
            "user", "users", "family", "families", "member", "members",
            "firmware", "ota", "update", "updates", "config", "configuration",
            "data", "datas", "telemetry", "metrics", "statistics", "analytics",
            "alert", "alerts", "alarm", "alarms", "notification", "notifications",
            "rule", "rules", "trigger", "triggers", "schedule", "schedules"
        ],
        action_suffixes=[
            "login", "logout", "register", "bind", "unbind", "share", "authorize",
            "status", "control", "turn_on", "turn_off", "toggle", "dim", "brighten",
            "monitor", "track", "collect", "upload", "sync", "history", "query",
            "alert", "notify", "alarm", "trigger", "action", "execute", "run",
            "configure", "setup", "calibrate", "pair", "discover", "add", "remove",
            "schedule", "timer", "scene", "automate", "report", "statistics", "analytics",
            "firmware", "ota", "update", "download", "upgrade", "reboot"
        ],
        sensitive_paths=[
            "/admin", "/manager", "/api/admin", "/api/device/control",
            "/api/gateway/configure", "/api/home/scene/execute",
            "/internal", "/debug", "/swagger", "/api-docs", "/health"
        ],
        test_urls=[
            "/api/v1/device/list",
            "/api/iot/gateway/status",
            "/api/home/scene/execute",
            "/api/camera/live/stream",
            "/api/sensor/data/collect",
            "/api/alert/alarm/notify",
            "/api/firmware/ota/update",
            "/api/rule/trigger/action",
            "/api/analytics/usage/report",
            "/api/user/family/member"
        ]
    ),
    
    "游戏 Gaming": IndustryScenario(
        name="游戏 Gaming",
        description="游戏后端、匹配系统、排行榜、虚拟经济、广告变现",
        typical_prefixes=["api", "v1", "v2", "game", "sdk", "gateway", "cdn"],
        business_resources=[
            "player", "players", "user", "users", "account", "accounts", "profile", "profiles",
            "character", "characters", "avatar", "avatars", "inventory", "inventories",
            "item", "items", "equipment", "skills", "skill", "level", "levels", "exp", "experience",
            "mission", "missions", "quest", "quests", "dungeon", "dungeons", "boss", "bosses",
            "guild", "guilds", "clan", "clans", "team", "teams", "friend", "friends",
            "match", "matches", "matchmaking", "leaderboard", "rank", "ranks", "rating",
            "currency", "currencies", "coin", "coins", "gem", "gems", "cash", "purchase", "purchases",
            "shop", "shops", "store", "stores", "deal", "deals", "offer", "offers",
            "mail", "mails", "message", "messages", "announcement", "announcements",
            "server", "servers", "channel", "channels", "cluster", "clusters",
            "log", "logs", "report", "reports", "anti_cheat", "security",
            "ad", "ads", "advertising", "impression", "click", "conversion"
        ],
        action_suffixes=[
            "login", "logout", "register", "signup", "auth", "token", "refresh", "bind",
            "play", "start", "end", "quit", "surrender", "pause", "resume",
            "create", "delete", "update", "upgrade", "evolve", "transform",
            "trade", "exchange", "gift", "reward", "claim", "receive",
            "match", "queue", "ready", "cancel", "status",
            "rank", "rating", "score", "leaderboard", "stat",
            "purchase", "pay", "refund", "restore", "subscribe",
            "send", "receive", "read", "delete", "mark",
            "join", "leave", "invite", "kick", "ban", "mute", "admin"
        ],
        sensitive_paths=[
            "/admin", "/gm", "/api/admin", "/api/gm", "/api/player/manage",
            "/api/server/monitor", "/api/security/anti_cheat",
            "/internal", "/debug", "/swagger", "/api-docs", "/health"
        ],
        test_urls=[
            "/api/v1/player/profile",
            "/api/v2/inventory/items",
            "/api/game/match/queue",
            "/api/guild/create",
            "/api/leaderboard/rank",
            "/api/shop/purchase",
            "/api/currency/buy",
            "/api/mail/send",
            "/api/ad/impression",
            "/api/server/status"
        ]
    )
}


class IndustryAPICoverageTester:
    """测试各行业API路径覆盖率"""
    
    def __init__(self):
        self.engine_ACTION_SUFFIXES = set()
        self.engine_RESOURCES = set()
        self.engine_RESTFUL_SUFFIXES = set()
        self.engine_PATH_FRAGMENTS = set()
        
    def load_engine_vocabulary(self):
        """从engine.py加载词表"""
        import re
        
        try:
            with open(ENGINE_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
            
            action_match = re.search(r'ACTION_SUFFIXES\s*=\s*\{([^}]+)\}', content, re.DOTALL)
            if action_match:
                actions = re.findall(r"'([^']+)'", action_match.group(1))
                self.engine_ACTION_SUFFIXES = set(actions)
            
            resource_match = re.search(r'RESOURCE_WORDS\s*=\s*\{([^}]+)\}', content, re.DOTALL)
            if resource_match:
                resources = re.findall(r"'([^']+)'", resource_match.group(1))
                self.engine_RESOURCES = set(resources)
            
            restful_match = re.search(r'RESTFUL_SUFFIXES\s*=\s*\[([^\]]+)\]', content, re.DOTALL)
            if restful_match:
                restfuls = re.findall(r"'([^']+)'", restful_match.group(1))
                self.engine_RESTFUL_SUFFIXES = set(restfuls)
            
            fragment_match = re.search(r'PATH_FRAGMENTS\s*=\s*\[([^\]]+)\]', content, re.DOTALL)
            if fragment_match:
                fragments = re.findall(r"'([^']+)'", fragment_match.group(1))
                self.engine_PATH_FRAGMENTS = set(fragments)
                
        except Exception as e:
            logger.error(f"加载词表失败: {e}")
    
    def calculate_coverage(self, scenario: IndustryScenario) -> Dict[str, Any]:
        """计算词表覆盖率"""
        scenario_actions = set(s.lower() for s in scenario.action_suffixes)
        scenario_resources = set(s.lower() for s in scenario.business_resources)
        scenario_sensitive = set(s.lower() for s in scenario.sensitive_paths)
        
        matched_actions = scenario_actions & self.engine_ACTION_SUFFIXES
        matched_resources = scenario_resources & self.engine_RESOURCES
        
        action_coverage = len(matched_actions) / len(scenario_actions) * 100 if scenario_actions else 0
        resource_coverage = len(matched_resources) / len(scenario_resources) * 100 if scenario_resources else 0
        
        missing_actions = scenario_actions - self.engine_ACTION_SUFFIXES
        missing_resources = scenario_resources - self.engine_RESOURCES
        
        return {
            'action_coverage': action_coverage,
            'resource_coverage': resource_coverage,
            'matched_actions': matched_actions,
            'matched_resources': matched_resources,
            'missing_actions': missing_actions,
            'missing_resources': missing_resources,
            'total_sensitive_paths': len(scenario_sensitive)
        }
    
    def test_path_generation(self, scenario: IndustryScenario) -> Dict[str, Any]:
        """测试路径生成"""
        generated_paths = set()
        
        prefixes = scenario.typical_prefixes
        resources = scenario.business_resources
        actions = scenario.action_suffixes
        
        for prefix in prefixes[:3]:
            for resource in resources[:10]:
                for action in actions[:10]:
                    path1 = f"/{prefix}/{resource}/{action}"
                    path2 = f"/api/{resource}/{action}"
                    path3 = f"/{prefix}/{resource}/{action}/{action}"
                    generated_paths.add(path1)
                    generated_paths.add(path2)
                    generated_paths.add(path3)
        
        testable_paths = set(scenario.test_urls)
        coverage = len(generated_paths & testable_paths) / len(testable_paths) * 100 if testable_paths else 0
        
        return {
            'generated_count': len(generated_paths),
            'testable_paths': testable_paths,
            'coverage': coverage
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """运行全场景测试"""
        self.load_engine_vocabulary()
        
        results = {}
        
        for name, scenario in INDUSTRY_SCENARIOS.items():
            coverage = self.calculate_coverage(scenario)
            path_test = self.test_path_generation(scenario)
            
            results[name] = {
                'scenario': scenario,
                'coverage': coverage,
                'path_test': path_test
            }
        
        return results


def print_test_report(results: Dict[str, Any]):
    """打印测试报告"""
    print("\n" + "="*80)
    print("全场景API采集和Fuzzing测试报告")
    print("="*80)
    
    total_coverage = 0
    total_path_coverage = 0
    industries_with_gaps = []
    
    for name, data in results.items():
        scenario = data['scenario']
        coverage = data['coverage']
        path_test = data['path_test']
        
        avg_coverage = (coverage['action_coverage'] + coverage['resource_coverage']) / 2
        total_coverage += avg_coverage
        total_path_coverage += path_test['coverage']
        
        if coverage['action_coverage'] < 80 or coverage['resource_coverage'] < 80:
            industries_with_gaps.append(name)
        
        print(f"\n【{name}】{scenario.description}")
        print("-" * 60)
        print(f"  词表覆盖率:")
        print(f"    - 动作词(Action): {coverage['action_coverage']:.1f}% ({len(coverage['matched_actions'])}/{len(scenario.action_suffixes)})")
        print(f"    - 资源词(Resource): {coverage['resource_coverage']:.1f}% ({len(coverage['matched_resources'])}/{len(scenario.business_resources)})")
        print(f"  路径生成测试:")
        print(f"    - 生成路径数: {path_test['generated_count']}")
        print(f"    - 测试覆盖率: {path_test['coverage']:.1f}%")
        
        if coverage['missing_actions']:
            print(f"  缺失动作词 (Top 10): {', '.join(list(coverage['missing_actions'])[:10])}")
        if coverage['missing_resources']:
            print(f"  缺失资源词 (Top 10): {', '.join(list(coverage['missing_resources'])[:10])}")
    
    avg_total = total_coverage / len(results)
    path_avg = total_path_coverage / len(results)
    
    print("\n" + "="*80)
    print("总体统计")
    print("="*80)
    print(f"  平均词表覆盖率: {avg_total:.1f}%")
    print(f"  平均路径覆盖率: {path_avg:.1f}%")
    print(f"  需要优化的行业: {len(industries_with_gaps)}")
    if industries_with_gaps:
        print(f"  - {', '.join(industries_with_gaps)}")
    
    print("\n" + "="*80)
    print("优化建议")
    print("="*80)
    
    all_missing_actions = set()
    all_missing_resources = set()
    
    for name, data in results.items():
        all_missing_actions.update(data['coverage']['missing_actions'])
        all_missing_resources.update(data['coverage']['missing_resources'])
    
    print(f"\n建议添加的动作词 ({len(all_missing_actions)} 个):")
    sorted_actions = sorted(all_missing_actions, key=len, reverse=True)
    for i in range(0, min(len(sorted_actions), 50), 5):
        print(f"    {', '.join(sorted_actions[i:i+5])}")
    
    print(f"\n建议添加的资源词 ({len(all_missing_resources)} 个):")
    sorted_resources = sorted(all_missing_resources, key=len, reverse=True)
    for i in range(0, min(len(sorted_resources), 50), 5):
        print(f"    {', '.join(sorted_resources[i:i+5])}")


async def test_unified_fuzzer():
    """测试统一Fuzzer"""
    print("\n" + "="*80)
    print("测试 UnifiedFuzzer 集成")
    print("="*80)
    
    try:
        from core.unified_fuzzer import UnifiedFuzzer, UnifiedFuzzResult
        
        print("\n[✓] UnifiedFuzzer 导入成功")
        
        fuzzer = UnifiedFuzzer()
        print(f"[✓] UnifiedFuzzer 实例化成功")
        print(f"    - Payload管理器: {fuzzer._payload_manager is not None}")
        print(f"    - 路径Fuzzer: {fuzzer._path_fuzzer is not None}")
        print(f"    - Fuzz测试器: {fuzzer._fuzz_tester is not None}")
        
        stats = fuzzer.stats
        print(f"\n[✓] 统计信息: {stats}")
        
        return True
    except Exception as e:
        print(f"\n[✗] UnifiedFuzzer 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_scanner_module():
    """测试扫描器模块"""
    print("\n" + "="*80)
    print("测试 Scanner 模块")
    print("="*80)
    
    try:
        from core.scanner import ScannerConfig, ChkApiScanner
        
        print("\n[✓] Scanner 模块导入成功")
        
        config = ScannerConfig(
            target="http://localhost:8888",
            attack_mode="collect",
            no_api_scan=True
        )
        
        print(f"[✓] ScannerConfig 创建成功")
        print(f"    - 攻击模式: {config.attack_mode}")
        print(f"    - 无API扫描: {config.no_api_scan}")
        
        return True
    except Exception as e:
        print(f"\n[✗] Scanner 模块测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_api_combiner():
    """测试API拼接器"""
    print("\n" + "="*80)
    print("测试 API 拼接算法")
    print("="*80)
    
    try:
        from core.collectors.api_collector import APIPathCombiner
        
        print("\n[✓] APIPathCombiner 导入成功")
        
        combiner = APIPathCombiner()
        print(f"[✓] APIPathCombiner 实例化成功")
        
        test_cases = [
            ("finance", "banking", ["/api/user/list", "/api/account/detail"]),
            ("healthcare", "hospital", ["/api/patient/register", "/api/doctor/schedule"]),
            ("iot", "smart_home", ["/api/device/control", "/api/sensor/data"]),
        ]
        
        for industry, desc, paths in test_cases:
            print(f"\n  [{industry}] {desc}:")
            for path in paths:
                print(f"    - {path}")
        
        return True
    except Exception as e:
        print(f"\n[✗] APIPathCombiner 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """主测试流程"""
    print("\n" + "="*80)
    print("ApiRed 全场景API采集和Fuzzing测试")
    print("金融/医疗/科技/工厂/政府/军队/教育/能源/交通/零售/物联网/游戏")
    print("="*80)
    
    tester = IndustryAPICoverageTester()
    
    print("\n[1/5] 加载引擎词表...")
    tester.load_engine_vocabulary()
    print(f"    - 动作词(ACTION_SUFFIXES): {len(tester.engine_ACTION_SUFFIXES)} 个")
    print(f"    - 资源词(RESOURCE_WORDS): {len(tester.engine_RESOURCES)} 个")
    print(f"    - RESTful后缀: {len(tester.engine_RESTFUL_SUFFIXES)} 个")
    print(f"    - 路径片段: {len(tester.engine_PATH_FRAGMENTS)} 个")
    
    print("\n[2/5] 运行行业覆盖率测试...")
    results = tester.run_all_tests()
    
    print("\n[3/5] 生成测试报告...")
    print_test_report(results)
    
    print("\n[4/5] 测试核心模块...")
    await test_unified_fuzzer()
    await test_scanner_module()
    await test_api_combiner()
    
    print("\n[5/5] 验证词表优化...")
    avg_action = 0
    avg_resource = 0
    for name, data in results.items():
        avg_action += data['coverage']['action_coverage']
        avg_resource += data['coverage']['resource_coverage']
    
    avg_action /= len(results)
    avg_resource /= len(results)
    
    print(f"\n  当前覆盖率:")
    print(f"    - 平均动作词覆盖率: {avg_action:.1f}%")
    print(f"    - 平均资源词覆盖率: {avg_resource:.1f}%")
    
    if avg_action < 80 or avg_resource < 80:
        print(f"\n  [建议] 词表覆盖率偏低，建议扩展 ACTION_SUFFIXES 和 RESOURCE_WORDS")
    
    print("\n" + "="*80)
    print("测试完成")
    print("="*80 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
