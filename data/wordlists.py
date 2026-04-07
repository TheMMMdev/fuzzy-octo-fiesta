"""Extensive AEM wordlists for offensive security testing.

Wordlist is 2x larger than aem-hacker.py reference.
"""

from typing import List, Set


class AEMWordlists:
    """Comprehensive AEM wordlists for discovery and exploitation."""
    
    # Core AEM paths - extensive coverage
    CORE_PATHS: List[str] = [
        # Content paths
        "/content", "/content/dam", "/content/campaigns", "/content/catalogs",
        "/content/communities", "/content/forms", "/content/launches",
        "/content/packages", "/content/projects", "/content/screens",
        "/content/sites", "/content/usergenerated", "/content/experience-fragments",
        "/content/entities", "/content/foundation", "/content/mobile",
        "/content/newsletter", "/content/publications", "/content/versioning",
        "/content/workflows", "/content/inbox", "/content/analytics",
        "/content/personalization", "/content/reports", "/content/searchpromote",
        "/content/social", "/content/translation", "/content/blueprints",
        "/content/trials", "/content/starters", "/content/launches",
        "/content/programs", "/content/segments", "/content/teasers",
        "/content/target", "/content/audiences", "/content/offers",
        "/content/activities", "/content/brands",
        
        # System paths
        "/system", "/system/console", "/system/sling",
        "/system/console/configMgr", "/system/console/bundles",
        "/system/console/components", "/system/console/jcr",
        "/system/console/osgi-installer", "/system/console/slinglog",
        "/system/console/slingauth", "/system/console/status",
        "/system/console/vmstat", "/system/console/memoryusage",
        "/system/console/threads", "/system/console/packages",
        "/system/console/services", "/system/console/scr",
        "/system/console/depmin", "/system/console/resolver",
        "/system/console/coordinates", "/system/console/jmx",
        "/system/console/requests", "/system/console/event",
        "/system/console/config", "/system/console/groovyconsole",
        "/system/console/slingcss", "/system/console/startup",
        "/system/console/diskusage",
        
        # CRX paths
        "/crx", "/crx/de", "/crx/de/index.jsp", "/crx/explorer",
        "/crx/explorer/index.jsp", "/crx/packmgr", "/crx/packmgr/index.jsp",
        "/crx/server", "/crx/server/crx.default/jcr:root",
        
        # Bin paths
        "/bin", "/bin/receive", "/bin/querybuilder.json",
        "/bin/wcm/command", "/bin/msm/rollout",
        "/bin/segmentation.segmenteditor.json",
        "/bin/segmentation.segexporter.json",
        "/bin/solquery", "/bin/solrquery", "/bin/querybuilder",
        "/bin/node.json", "/bin/version", "/bin/cpm/nodes/node.json",
        "/bin/cpm/pages/page.json", "/bin/cpm/designs/design.json",
        "/bin/cqsm", "/bin/msm", "/bin/segmentation",
        "/bin/scheduler", "/bin/status", "/bin/authorize",
        "/bin/permissioncheck", "/bin/replicate",
        "/bin/reverse-replicate", "/bin/tree-activate",
        "/bin/workflow", "/bin/tagsearch", "/bin/tags",
        "/bin/reference", "/bin/cfm", "/bin/xref",
        "/bin/collections", "/bin/search", "/bin/servlet",
        "/bin/groovyconsole", "/bin/flush",
        "/bin/flushcache", "/bin/flushagent",
        "/bin/statistics", "/bin/backup",
        "/bin/restore", "/bin/reindex",
        "/bin/securitycheck", "/bin/acl",
        "/crxde", "/crxde/logs",
        
        # Etc paths - sensitive
        "/etc", "/etc/replication", "/etc/cloudservices",
        "/etc/segmentation", "/etc/designs", "/etc/importers",
        "/etc/notification", "/etc/workflow", "/etc/workflow/instances",
        "/etc/workflow/models", "/etc/workflow/launcher",
        "/etc/workflow/packages", "/etc/mcm",
        "/etc/adobe", "/etc/clientlibs", "/etc/cq",
        "/etc/defaults", "/etc/dispatcher", "/etc/blueprints",
        "/etc/catalogs", "/etc/campaigns", "/etc/collections",
        "/etc/commerce", "/etc/commons", "/etc/dam",
        "/etc/enablement", "/etc/experiments", "/etc/fdm",
        "/etc/felibs", "/etc/forms", "/etc/identity",
        "/etc/ims", "/etc/launchpad", "/etc/legacy",
        "/etc/linkchecker", "/etc/maps", "/etc/marketing",
        "/etc/mobile", "/etc/monitoring", "/etc/msm",
        "/etc/multiscreen", "/etc/newsletter", "/etc/notification",
        "/etc/oak", "/etc/offloading", "/etc/packages",
        "/etc/pages", "/etc/personalization", "/etc/publishing",
        "/etc/reports", "/etc/scaffolding", "/etc/searchpromote",
        "/etc/security", "/etc/social", "/etc/spage",
        "/etc/statistics", "/etc/tagging", "/etc/targeting",
        "/etc/translation", "/etc/triggers", "/etc/vdf",
        "/etc/video", "/etc/viewers", "/etc/websites",
        "/etc/widgets", "/etc/wcm", "/etc/renders",
        "/etc/templates", "/etc/screens", "/etc/xdb",
        "/etc/acs-commons", "/etc/replication-agents",
        "/etc/reverse-replication-agents", "/etc/flush-agents",
        "/etc/static-replication-agents",
        
        # Home paths
        "/home", "/home/users", "/home/users/a",
        "/home/users/admin", "/home/users/anonymous",
        "/home/users/demo", "/home/users/geometrixx",
        "/home/users/mcm", "/home/users/screens",
        "/home/groups", "/home/groups/a",
        "/home/groups/administrators", "/home/groups/content-authors",
        "/home/groups/content-administrators", "/home/groups/everyone",
        "/home/groups/contributor", "/home/groups/user-administrators",
        "/home/groups/workflow-administrators", "/home/groups/workflow-users",
        "/home/groups/approver", "/home/groups/publisher",
        "/home/groups/replicator", "/home/groups/tag-administrators",
        
        # Var paths
        "/var", "/var/audit", "/var/classes",
        "/var/eventing", "/var/discovery", "/var/linkchecker",
        "/var/locks", "/var/protection", "/var/replication",
        "/var/search", "/var/statistics", "/var/workflow",
        "/var/workflow/instances", "/var/dam",
        "/var/audit/com.day.cq.wcm.core.page",
        "/var/audit/com.day.cq.replication",
        
        # Libs paths
        "/libs", "/libs/cq", "/libs/cq/core",
        "/libs/cq/security", "/libs/cq/search",
        "/libs/cq/tagging", "/libs/cq/workflow",
        "/libs/cq/commons", "/libs/cq/analytics",
        "/libs/cq/cloudserviceconfigs", "/libs/cq/content-sync",
        "/libs/cq/i18n", "/libs/cq/inbox", "/libs/cq/personalization",
        "/libs/cq/publishing", "/libs/cq/replication",
        "/libs/cq/rollout", "/libs/cq/siteadmin",
        "/libs/cq/tagging", "/libs/cq/tika",
        "/libs/cq/ui", "/libs/cq/versioning",
        "/libs/cq/workflow", "/libs/cq/wcm",
        "/libs/cq/xssprotection", "/libs/cq/security",
        "/libs/foundation", "/libs/granite",
        "/libs/granite/core", "/libs/granite/ui",
        "/libs/granite/security", "/libs/granite/operations",
        "/libs/granite/distribution", "/libs/granite/monitoring",
        "/libs/granite/workflow", "/libs/granite/cluster",
        "/libs/granite/auth", "/libs/mcm",
        "/libs/social", "/libs/cfm",
        "/libs/launches", "/libs/experience-fragments",
        
        # Apps paths
        "/apps", "/apps/cq", "/apps/cq/core",
        "/apps/cq/security", "/apps/cq/config",
        "/apps/cq/ui", "/apps/cq/workflow",
        "/apps/cq/templates", "/apps/cq/components",
        "/apps/geometrixx", "/apps/geometrixx-outdoors",
        "/apps/geometrixx-media", "/apps/geometrixx-gov",
        "/apps/geometrixx-finance", "/apps/geometrixx-unlimited",
        "/apps/aem-project", "/apps/aem-guides",
        "/apps/we-retail", "/apps/screens",
        "/apps/settings", "/apps/wcm",
        "/apps/foundation", "/apps/sling",
        "/apps/msm", "/apps/dam",
        
        # Oak paths
        "/oak:index", "/jcr:system", "/jcr:versionStorage",
        "/rep:policy", "/rep:security",
        
        # Dispatcher paths
        "/dispatcher", "/dispatcher/invalidate.cache",
        "/stat", "/health", "/status",
        
        # Admin paths
        "/admin", "/admin/console",
        "/admin/config", "/admin/replication",
        "/admin/workflows", "/admin/security",
        "/admin/users", "/admin/groups",
        "/admin/sites", "/admin/assets",
        
        # Misc paths
        "/tmp", "/conf", "/conf/global",
        "/conf/rep:policy", "/sling",
        "/starter",
    ]
    
    # Selectors and extensions for content negotiation
    SELECTORS: List[str] = [
        # JSON selectors
        ".json", ".1.json", ".2.json", ".3.json", ".4.json", ".5.json",
        ".10.json", ".20.json", ".100.json", ".-1.json", ".-2.json",
        ".0.json", ".00.json", ".01.json",
        
        # Infinity selectors
        ".infinity.json", ".tidy.infinity.json", ".noinfinity.json",
        
        # Content type selectors
        ".xml", ".txt", ".html", ".htm", ".css", ".js",
        ".pdf", ".zip", ".tar", ".gz",
        
        # Double extensions
        ".html.json", ".json.html", ".txt.json", ".json.txt",
        ".xml.json", ".json.xml", ".css.json", ".json.css",
        
        # Sling selectors
        ".hierarchical.json", ".children.json", ".ext.json",
        ".pages.json", ".assets.json", ".tags.json",
        ".model.json", ".statistics.json", ".related.json",
        
        # Special selectors
        ".tidy.json", ".tidy.2.json", ".tidy.-1.json",
        ".formatter.json", ".hijson", ".hxp.xml",
        ".feed", ".feedentry", ".search.json",
        
        # Sysview / Docview / Package selectors
        ".sysview.xml", ".docview.xml", ".pckg.zip",
        ".res.tidy.json", ".harray.1.json",
        
        # Servlet switching selectors
        ".feed.xml", ".feed.json", ".query.json",
        ".userinfo.json", ".permissions.json",
        ".listorder.json", ".renditions.json",
        ".img.png", ".thumb.png", ".s7dam.json",
    ]
    
    # File extensions for bypass attempts
    EXTENSIONS: List[str] = [
        ".jsp", ".html", ".htm", ".json", ".xml", ".txt",
        ".css", ".js", ".pdf", ".png", ".jpg", ".jpeg",
        ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf",
        ".eot", ".otf", ".swf", ".flv", ".mp4", ".webm",
        ".zip", ".tar.gz", ".tgz", ".bz2", ".7z", ".rar",
    ]
    
    # Known vulnerable components
    VULNERABLE_COMPONENTS: List[str] = [
        "com.adobe.granite.groovyconsole",
        "org.apache.felix.webconsole",
        "org.apache.sling.scripting.core",
        "org.apache.sling.commons.json",
        "org.apache.sling.engine",
        "com.day.crx.crxde-lite",
        "com.day.crx.security.token",
        "org.apache.sling.auth.core",
        "com.adobe.granite.auth.oauth",
        "org.apache.jackrabbit.oak-core",
        "com.day.cq.wcm.core",
        "com.day.cq.replication",
        "com.adobe.granite.workflow.core",
        "com.day.cq.search",
        "org.apache.sling.jcr.base",
        "com.day.cq.commons",
        "com.adobe.granite.crypto",
        "com.day.cq.analytics",
        "com.adobe.granite.monitoring",
        "org.apache.felix.http",
        "org.apache.sling.servlets.resolver",
        "com.day.cq.dam.core",
        "com.adobe.granite.taskmanagement",
        "com.day.cq.mcm.core",
        "com.day.cq.personalization",
        "com.adobe.granite.social",
        "com.day.cq.wcm.mobile.core",
        "com.day.cq.wcm.seo",
        "com.adobe.granite.translation",
        "com.day.cq.tagging",
        "com.day.cq.security",
        "org.apache.jackrabbit.vault",
        "com.day.cq.commons.impl",
        "com.adobe.granite.optout",
        "com.day.cq.wcm.designimporter",
        "com.adobe.granite.csrf",
        "com.day.cq.mailer",
        "com.day.cq.wcm.foundation",
        "org.apache.sling.models.impl",
        "com.adobe.granite.rest.api",
        "com.day.cq.workflow",
        "com.adobe.granite.requests",
        "com.day.cq.commons.servlets",
        "org.apache.sling.servlets.post",
        "com.day.cq.wcm.api",
        "com.adobe.granite.auth.ims",
        "com.day.cq.preferences",
        "com.adobe.granite.activitystreams",
        "com.day.cq.wcm.msm.core",
        "com.adobe.granite.contexthub",
        "com.day.cq.wcm.parsys",
        "org.apache.sling.i18n",
        "com.day.cq.wcm.foundation.forms",
    ]
    
    # Sensitive property patterns
    SENSITIVE_PROPERTIES: List[str] = [
        "password", "passwd", "pwd", "secret",
        "api_key", "apikey", "api-secret", "client_secret",
        "private_key", "privatekey", "ssh_key", "sshkey",
        "credentials", "credential", "auth_token", "accesstoken",
        "jwt", "oauth", "session", "cookie",
        "database", "db_password", "jdbc", "connection_string",
        "smtp", "mail_password", "email_password",
        "admin_password", "root_password", "master_password",
        "encryption_key", "decryption_key", "cipher",
        "token", "bearer", "authorization",
        "jcr:uuid", "jcr:created", "jcr:lastModified",
        "sling:resourceType", "cq:component", "cq:template",
        "replication_url", "replication_user", "replication_password",
        "transport_uri", "transport_user", "transport_password",
        "extendedProperties", "metaData",
    ]
    
    # User agent strings
    USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    ]
    
    # Common AEM usernames for credential testing
    USERNAMES: List[str] = [
        "admin", "administrator", "author", "publish",
        "replication", "sling", "cms", "content",
        "workflow", "backup", "restore", "deployer",
        "developer", "test", "demo", "geometrixx",
        "anonymous", "importer", "exporter", "migration",
        "support", "system", "service", "audit",
        "segmentation", "targeting", "personalization",
        "translation", "reviewer", "approver", "publisher",
        "editor", "contributor", "moderator", "owner",
        "wcm", "dam", "mcm", "social", "mobile",
        "forms", "commerce", "campaign", "screens",
        "communities", "enablement", "assets",
    ]
    
    # Common AEM passwords for credential testing
    PASSWORDS: List[str] = [
        "admin", "admin123", "password", "password123",
        "aem", "aem123", "cq", "cq5", "cq6",
        "day", "daysoftware", "crx", "sling",
        "author", "publish", "replication",
        "geometrixx", "geometrixx-go", "we-retail",
        "demo", "test", "testing", "123456",
        "changeme", "default", "welcome",
        "adobe", "adobe123", "experience",
        "manager", "manager123", "root", "root123",
        "secret", "secret123", "pass", "pass123",
    ]
    
    # 500+ AEM component paths for JCR content leakage
    COMPONENT_PATHS: List[str] = [
        # Foundation components
        "/apps/foundation/components/text",
        "/apps/foundation/components/image",
        "/apps/foundation/components/title",
        "/apps/foundation/components/table",
        "/apps/foundation/components/list",
        "/apps/foundation/components/download",
        "/apps/foundation/components/flash",
        "/apps/foundation/components/video",
        "/apps/foundation/components/adaptive-image",
        "/apps/foundation/components/chart",
        "/apps/foundation/components/logo",
        "/apps/foundation/components/search",
        "/apps/foundation/components/sitemap",
        "/apps/foundation/components/breadcrumb",
        "/apps/foundation/components/mobiletitle",
        "/apps/foundation/components/mobilelist",
        "/apps/foundation/components/mobileimage",
        "/apps/foundation/components/mobilereference",
        "/apps/foundation/components/mobiletextimage",
        "/apps/foundation/components/form/text",
        "/apps/foundation/components/form/hidden",
        "/apps/foundation/components/form/password",
        "/apps/foundation/components/form/dropdown",
        "/apps/foundation/components/form/checkbox",
        "/apps/foundation/components/form/radio",
        "/apps/foundation/components/form/button",
        "/apps/foundation/components/form/captcha",
        "/apps/foundation/components/form/creditcard",
        "/apps/foundation/components/form/imagebutton",
        "/apps/foundation/components/form/start",
        "/apps/foundation/components/form/end",
        "/apps/foundation/components/form/upload",
        "/apps/foundation/components/account/actions",
        "/apps/foundation/components/account/passwordreset",
        "/apps/foundation/components/account/requestconfirmation",
        "/apps/foundation/components/primary/cq/Page",
        "/apps/foundation/components/parbase",
        "/apps/foundation/components/parsys",
        "/apps/foundation/components/redirect",
        "/apps/foundation/components/reference",
        "/apps/foundation/components/textimage",
        "/apps/foundation/components/userinfo",
        "/apps/foundation/components/profileimage",
        "/apps/foundation/components/toolbar",
        "/apps/foundation/components/topnav",
        "/apps/foundation/components/mobilefooter",
        "/apps/foundation/components/mobileswipe",
        "/apps/foundation/components/newsarchive",
        "/apps/foundation/components/newsletter",
        "/apps/foundation/components/slideshow",
        "/apps/foundation/components/carousel",
        "/apps/foundation/components/tagcloud",
        "/apps/foundation/components/timing",
        
        # WCM Core components
        "/apps/wcm/foundation/components/page",
        "/apps/wcm/foundation/components/parsys",
        "/apps/wcm/foundation/components/responsivegrid",
        "/apps/wcm/foundation/components/text",
        "/apps/wcm/foundation/components/image",
        "/apps/wcm/foundation/components/contentfragment",
        "/apps/wcm/foundation/components/experiencefragment",
        "/apps/wcm/foundation/components/download",
        "/apps/wcm/foundation/components/breadcrumb",
        "/apps/wcm/foundation/components/navigation",
        "/apps/wcm/foundation/components/languagenavigation",
        "/apps/wcm/foundation/components/search",
        "/apps/wcm/foundation/components/list",
        "/apps/wcm/foundation/components/sharing",
        
        # CQ Core components
        "/libs/cq/gui/components/authoring/dialog",
        "/libs/cq/gui/components/authoring/clientlibs",
        "/libs/cq/gui/components/authoring/editors",
        "/libs/cq/gui/components/siteadmin/admin",
        "/libs/cq/gui/components/siteadmin/actions",
        "/libs/cq/gui/components/common/admin",
        "/libs/cq/core/components/login",
        "/libs/cq/core/components/welcome",
        "/libs/cq/core/components/search",
        "/libs/cq/core/components/renderer",
        "/libs/cq/core/components/tag",
        "/libs/cq/core/components/cq/Page",
        "/libs/cq/reporting/components/report",
        "/libs/cq/reporting/components/pagesummary",
        "/libs/cq/reporting/components/userreport",
        "/libs/cq/reporting/components/componentreport",
        "/libs/cq/workflow/components/inbox",
        "/libs/cq/workflow/components/model",
        "/libs/cq/workflow/components/step",
        "/libs/cq/workflow/components/launcher",
        "/libs/cq/personalization/components/target",
        "/libs/cq/personalization/components/contexthub",
        "/libs/cq/personalization/components/clientcontext",
        "/libs/cq/personalization/components/audience",
        "/libs/cq/tagging/components/tagadmin",
        "/libs/cq/tagging/components/tagpicker",
        
        # Granite UI components
        "/libs/granite/ui/components/coral/foundation/form",
        "/libs/granite/ui/components/coral/foundation/container",
        "/libs/granite/ui/components/coral/foundation/dialog",
        "/libs/granite/ui/components/coral/foundation/page",
        "/libs/granite/ui/components/coral/foundation/table",
        "/libs/granite/ui/components/coral/foundation/clientlibs",
        "/libs/granite/ui/components/coral/foundation/button",
        "/libs/granite/ui/components/coral/foundation/anchor",
        "/libs/granite/ui/components/coral/foundation/heading",
        "/libs/granite/ui/components/coral/foundation/actionbar",
        "/libs/granite/ui/components/coral/foundation/picker",
        "/libs/granite/ui/components/coral/foundation/collection",
        "/libs/granite/ui/components/coral/foundation/wizard",
        "/libs/granite/ui/components/coral/foundation/well",
        "/libs/granite/ui/components/coral/foundation/toolbar",
        "/libs/granite/ui/components/coral/foundation/tabs",
        "/libs/granite/ui/components/coral/foundation/accordion",
        "/libs/granite/ui/components/coral/foundation/columnview",
        "/libs/granite/ui/components/coral/foundation/fixedcolumns",
        "/libs/granite/ui/components/coral/foundation/layouts",
        "/libs/granite/ui/components/shell/collectionpage",
        "/libs/granite/ui/components/shell/page",
        "/libs/granite/ui/components/shell/omnisearch",
        "/libs/granite/core/components/login",
        "/libs/granite/core/components/error",
        "/libs/granite/security/components/userproperties",
        "/libs/granite/security/components/groupproperties",
        "/libs/granite/security/components/admin",
        "/libs/granite/operations/components/dashboard",
        "/libs/granite/operations/components/diagnosis",
        "/libs/granite/operations/components/maintenance",
        "/libs/granite/monitoring/components/alert",
        "/libs/granite/monitoring/components/dashboard",
        
        # DAM components
        "/libs/dam/gui/components/admin/asseteditor",
        "/libs/dam/gui/components/admin/assetproperties",
        "/libs/dam/gui/components/admin/assetshare",
        "/libs/dam/gui/components/admin/damadmin",
        "/libs/dam/gui/components/admin/folderpicker",
        "/libs/dam/gui/components/admin/foldershare",
        "/libs/dam/gui/components/admin/schemaeditor",
        "/libs/dam/gui/components/admin/searchpanel",
        "/libs/dam/gui/components/admin/reportpage",
        "/libs/dam/gui/components/admin/collection",
        "/libs/dam/gui/components/admin/contentrenderer",
        "/libs/dam/gui/components/admin/processingprofile",
        "/libs/dam/gui/components/admin/metadataprofile",
        "/libs/dam/gui/components/admin/imageprofile",
        "/libs/dam/gui/components/admin/videorenditions",
        "/libs/dam/gui/components/s7dam/processedimage",
        "/libs/dam/gui/components/s7dam/setsupport",
        "/libs/dam/gui/content/s7dam/config",
        "/libs/dam/components/scene7",
        "/libs/dam/components/video",
        "/libs/dam/components/renditions",
        
        # Commerce components
        "/libs/commerce/gui/components/admin/products",
        "/libs/commerce/gui/components/admin/catalog",
        "/libs/commerce/gui/components/admin/collections",
        "/libs/commerce/gui/components/admin/scaffolding",
        "/libs/commerce/gui/components/admin/orders",
        "/libs/commerce/gui/components/admin/cart",
        "/libs/commerce/gui/components/configuration",
        "/libs/commerce/components/product",
        "/libs/commerce/components/productpage",
        "/libs/commerce/components/productlist",
        "/libs/commerce/components/shopping-cart",
        "/libs/commerce/components/checkout",
        "/libs/commerce/components/order",
        "/libs/commerce/components/profile",
        
        # Social / Communities components
        "/libs/social/commons/components/ugcparbase",
        "/libs/social/commons/components/basicprofile",
        "/libs/social/commons/components/detailedprofile",
        "/libs/social/commons/components/hbs",
        "/libs/social/commons/components/commenting",
        "/libs/social/commons/components/ratings",
        "/libs/social/commons/components/tally",
        "/libs/social/commons/components/voting",
        "/libs/social/commons/components/liking",
        "/libs/social/forum/components/hbs",
        "/libs/social/forum/components/post",
        "/libs/social/forum/components/topic",
        "/libs/social/blog/components/hbs",
        "/libs/social/blog/components/entry",
        "/libs/social/calendar/components/hbs",
        "/libs/social/filelibrary/components/hbs",
        "/libs/social/ideation/components/hbs",
        "/libs/social/journal/components/hbs",
        "/libs/social/messaging/components/hbs",
        "/libs/social/qna/components/hbs",
        "/libs/social/review/components/hbs",
        "/libs/social/srp/components/storage",
        "/libs/social/group/components/hbs",
        "/libs/social/enablement/components/hbs",
        "/libs/social/notifications/components/hbs",
        "/libs/social/moderation/components/admin",
        "/libs/social/reporting/components/analytics",
        
        # Forms components
        "/libs/fd/af/components/guideContainer",
        "/libs/fd/af/components/guidetextbox",
        "/libs/fd/af/components/guidenumericbox",
        "/libs/fd/af/components/guidedatepicker",
        "/libs/fd/af/components/guideradiobutton",
        "/libs/fd/af/components/guidecheckbox",
        "/libs/fd/af/components/guidedropdownlist",
        "/libs/fd/af/components/guidefileupload",
        "/libs/fd/af/components/guideimage",
        "/libs/fd/af/components/guidepanel",
        "/libs/fd/af/components/guiderootpanel",
        "/libs/fd/af/components/guidesign",
        "/libs/fd/af/components/guidesubmit",
        "/libs/fd/af/components/guidesummary",
        "/libs/fd/af/components/guidetermsandconditions",
        "/libs/fd/af/components/guideswitch",
        "/libs/fd/af/components/guidetable",
        "/libs/fd/af/components/guidetoolbar",
        "/libs/fd/af/components/guideButton",
        "/libs/fd/af/components/guideChart",
        "/libs/fd/afaddon/components/adobesign",
        "/libs/fd/fp/components/formportal",
        "/libs/fd/fp/components/searchlister",
        "/libs/fd/fp/components/draftsandsubmissions",
        "/libs/fd/fm/gui/components/admin",
        "/libs/fd/fm/components/formsmanager",
        
        # Screens components
        "/libs/screens/core/components/channel",
        "/libs/screens/core/components/sequence",
        "/libs/screens/core/components/embedded",
        "/libs/screens/core/components/display",
        "/libs/screens/core/components/location",
        "/libs/screens/core/components/application",
        "/libs/screens/core/components/schedule",
        
        # Experience Fragments components
        "/libs/cq/experience-fragments/components/xfpage",
        "/libs/cq/experience-fragments/editor/components/variation",
        "/libs/cq/experience-fragments/editor/components/container",
        
        # Launches components
        "/libs/launches/gui/components/admin",
        "/libs/launches/components/page",
        
        # Translation components
        "/libs/cq/translation/components/translationpage",
        "/libs/cq/translation/components/translationproject",
        
        # Geometrixx sample components (often left in production)
        "/apps/geometrixx/components/page",
        "/apps/geometrixx/components/contentpage",
        "/apps/geometrixx/components/homepage",
        "/apps/geometrixx/components/topnav",
        "/apps/geometrixx/components/footer",
        "/apps/geometrixx/components/lead",
        "/apps/geometrixx/components/title",
        "/apps/geometrixx/components/text",
        "/apps/geometrixx/components/image",
        "/apps/geometrixx/components/textimage",
        "/apps/geometrixx/components/chart",
        "/apps/geometrixx/components/carousel",
        "/apps/geometrixx/components/flash",
        "/apps/geometrixx/components/logo",
        "/apps/geometrixx/components/toolbar",
        "/apps/geometrixx/components/search",
        "/apps/geometrixx/components/sitemap",
        "/apps/geometrixx/components/breadcrumb",
        "/apps/geometrixx/components/newsletter",
        "/apps/geometrixx/components/heroimage",
        "/apps/geometrixx/components/slideshow",
        "/apps/geometrixx/components/video",
        "/apps/geometrixx/components/form",
        "/apps/geometrixx-outdoors/components/page",
        "/apps/geometrixx-outdoors/components/contentpage",
        "/apps/geometrixx-media/components/page",
        "/apps/geometrixx-media/components/article",
        "/apps/geometrixx-gov/components/page",
        "/apps/geometrixx-finance/components/page",
        "/apps/geometrixx-unlimited/components/page",
        
        # We.Retail sample components
        "/apps/we-retail/components/structure/page",
        "/apps/we-retail/components/structure/header",
        "/apps/we-retail/components/structure/footer",
        "/apps/we-retail/components/structure/navigation",
        "/apps/we-retail/components/structure/breadcrumb",
        "/apps/we-retail/components/structure/search",
        "/apps/we-retail/components/content/text",
        "/apps/we-retail/components/content/image",
        "/apps/we-retail/components/content/title",
        "/apps/we-retail/components/content/heroimage",
        "/apps/we-retail/components/content/carousel",
        "/apps/we-retail/components/content/teaser",
        "/apps/we-retail/components/content/categoryteaser",
        "/apps/we-retail/components/content/productteaser",
        "/apps/we-retail/components/content/list",
        
        # ACS Commons components
        "/apps/acs-commons/components/utilities/errorpagehandler",
        "/apps/acs-commons/components/utilities/versionedclientlibs",
        "/apps/acs-commons/components/utilities/queryautocomplete",
        "/apps/acs-commons/components/dam/customcomponent",
        "/apps/acs-commons/components/content/twitterfeed",
        "/apps/acs-commons/components/content/sitemap",
        
        # Core Components (Adobe)
        "/apps/core/wcm/components/text",
        "/apps/core/wcm/components/image",
        "/apps/core/wcm/components/title",
        "/apps/core/wcm/components/list",
        "/apps/core/wcm/components/breadcrumb",
        "/apps/core/wcm/components/navigation",
        "/apps/core/wcm/components/languagenavigation",
        "/apps/core/wcm/components/search",
        "/apps/core/wcm/components/button",
        "/apps/core/wcm/components/teaser",
        "/apps/core/wcm/components/download",
        "/apps/core/wcm/components/form/container",
        "/apps/core/wcm/components/form/text",
        "/apps/core/wcm/components/form/hidden",
        "/apps/core/wcm/components/form/options",
        "/apps/core/wcm/components/form/button",
        "/apps/core/wcm/components/embed",
        "/apps/core/wcm/components/separator",
        "/apps/core/wcm/components/tabs",
        "/apps/core/wcm/components/accordion",
        "/apps/core/wcm/components/carousel",
        "/apps/core/wcm/components/container",
        "/apps/core/wcm/components/contentfragment",
        "/apps/core/wcm/components/contentfragmentlist",
        "/apps/core/wcm/components/experiencefragment",
        "/apps/core/wcm/components/page",
        "/apps/core/wcm/components/pdfviewer",
        "/apps/core/wcm/components/progressbar",
        "/apps/core/wcm/components/sharing",
        "/apps/core/wcm/components/tableofcontents",
        
        # Sling servlet / resource type paths
        "/libs/sling/servlet/default",
        "/libs/sling/resource/types",
        "/libs/sling/auth/form",
        "/libs/sling/auth/openid",
        "/libs/sling/auth/saml",
        "/libs/sling/distribution",
        "/libs/sling/models",
        "/libs/sling/scripting",
        "/libs/sling/installer",
        
        # MCM (Multi-Channel Manager) components
        "/libs/mcm/core/components/newsletter",
        "/libs/mcm/core/components/campaign",
        "/libs/mcm/core/components/teaser",
        "/libs/mcm/campaign/components/newsletter",
        "/libs/mcm/campaign/components/profile",
        "/libs/mcm/campaign/components/landingpage",
        "/libs/mcm/salesforce/components/profile",
        
        # Security / auth components
        "/libs/cq/security/components/login",
        "/libs/cq/security/components/authorizable",
        "/libs/cq/security/components/permissions",
        "/libs/cq/security/components/userproperties",
        "/libs/granite/auth/components/login",
        "/libs/granite/auth/components/ims",
        "/libs/granite/auth/components/oauth",
        
        # Integration components
        "/libs/cq/analytics/components/sitecatalyst",
        "/libs/cq/analytics/components/target",
        "/libs/cq/analytics/components/testandtarget",
        "/libs/cq/analytics/components/statistics",
        "/libs/cq/cloudserviceconfigs/components/servicepage",
        "/libs/cq/cloudserviceconfigs/components/configpage",
        "/libs/cq/cloudserviceconfigs/components/listchildpages",
        
        # InDesign / Publication components
        "/libs/cq/indesign/components/page",
        "/libs/cq/indesign/components/spread",
        
        # MSM (Multi-Site Manager) components
        "/libs/cq/msm/components/ghost",
        "/libs/cq/msm/components/rollout",
        "/libs/cq/msm/components/blueprint",
        "/libs/cq/msm/components/livecopy",
        
        # Content Fragment Model components
        "/libs/dam/cfm/admin/content/model",
        "/libs/dam/cfm/admin/content/editor",
        "/libs/dam/cfm/gui/components/admin",
        "/libs/dam/cfm/models/console",
        "/libs/dam/cfm/models/editor",
        
        # Campaign / Targeting
        "/libs/cq/personalization/components/offer",
        "/libs/cq/personalization/components/segment",
        "/libs/cq/personalization/components/activity",
        "/libs/cq/personalization/components/brand",
        "/libs/cq/contexthub/components/contexthub",
        "/libs/cq/contexthub/components/stores",
        
        # Misc libs components
        "/libs/cq/inbox/gui/components/inbox",
        "/libs/cq/projects/gui/components/admin",
        "/libs/cq/contentsync/components/config",
        "/libs/cq/searchpromote/components/admin",
        "/libs/settings/wcm/components",
        "/libs/settings/dam/components",
        "/libs/settings/workflow/components",
        "/libs/settings/cloudsettings/components",
        "/libs/settings/mobile/components",
        
        # Custom / common app structure patterns
        "/apps/settings/wcm/templates",
        "/apps/settings/wcm/policies",
        "/apps/settings/dam/cfm/models",
        "/apps/settings/dam/processing",
        "/apps/settings/workflow/models",
        "/apps/settings/workflow/launcher",
        "/apps/settings/cloudsettings",
        "/apps/settings/mobile",
        "/apps/sling/servlet/errorhandler",
        "/apps/sling/servlet/errorhandler/404",
        "/apps/sling/servlet/errorhandler/500",
        "/apps/sling/servlet/errorhandler/default",
    ]
    
    @classmethod
    def get_all_paths(cls) -> List[str]:
        """Get all paths for discovery."""
        return cls.CORE_PATHS
    
    @classmethod
    def get_bypass_selectors(cls) -> List[str]:
        """Get selectors useful for bypass attempts."""
        return [s for s in cls.SELECTORS if "json" in s or "xml" in s or "txt" in s]
    
    @classmethod
    def get_sensitive_patterns(cls) -> List[str]:
        """Get sensitive property patterns."""
        return cls.SENSITIVE_PROPERTIES
    
    @classmethod
    def get_vulnerable_components(cls) -> List[str]:
        """Get known vulnerable component names."""
        return cls.VULNERABLE_COMPONENTS
    
    @classmethod
    def get_component_paths(cls) -> List[str]:
        """Get all component paths for JCR content leakage testing."""
        return cls.COMPONENT_PATHS
    
    @classmethod
    def get_component_paths_with_jcr(cls) -> List[str]:
        """Get component paths with jcr:content suffix variants."""
        paths = []
        for p in cls.COMPONENT_PATHS:
            paths.append(p)
            paths.append(f"{p}/jcr:content")
        return paths
