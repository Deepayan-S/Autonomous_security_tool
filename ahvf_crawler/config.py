import yaml
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path

@dataclass
class RateLimitConfig:
    floor: float = 1.0
    backoff_multiplier: float = 2.0
    max_retries: int = 5

@dataclass
class CaptchaConfig:
    enabled: bool = True
    model: str = "llava"
    max_retries: int = 3
    api_url: str = "http://localhost:11434/api/generate"

@dataclass
class LlmConfig:
    enabled: bool = False
    model: str = "llama3"
    api_url: str = "http://localhost:11434/api/generate"

@dataclass
class RoleConfig:
    username: str = ""
    password: str = ""

@dataclass
class CrawlConfig:
    roe_acknowledged: bool = False
    target_base_url: str = ""
    login_url: str = ""
    scope_hosts: List[str] = field(default_factory=list)
    scope_ips: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    max_pages_per_role: int = 500
    crawl_depth: int = 10
    
    # Form detection defaults
    username_selector: str = "input[name='username']"
    password_selector: str = "input[name='password']"
    submit_selector: str = "button[type='submit']"
    
    # Config blocks
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    captcha: CaptchaConfig = field(default_factory=CaptchaConfig)
    llm: LlmConfig = field(default_factory=LlmConfig)
    roles: Dict[str, RoleConfig] = field(default_factory=dict)
    
    # Storage
    output_dir: str = "results"
    db_path: str = "results/ahvf_crawler.db"

def load_config(config_path: str | Path) -> CrawlConfig:
    path = Path(config_path)
    if not path.exists():
        print(f"[-] Config file not found: {path}")
        sys.exit(1)
        
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"[-] Failed to load YAML config: {e}")
        sys.exit(1)
        
    if not data:
        data = {}

    # RoE Acknowledgment
    if not data.get("roe_acknowledged"):
        print("[-] FATAL: Execution blocked. Rules of Engagement (roe_acknowledged) must be explicitly true in config.")
        sys.exit(1)

    # Parse nested
    rl_data = data.get("rate_limit", {})
    rate_limit = RateLimitConfig(
        floor=rl_data.get("floor", 1.0),
        backoff_multiplier=rl_data.get("backoff_multiplier", 2.0),
        max_retries=rl_data.get("max_retries", 5)
    )

    cap_data = data.get("captcha", {})
    captcha = CaptchaConfig(
        enabled=cap_data.get("enabled", True),
        model=cap_data.get("model", "llava"),
        max_retries=cap_data.get("max_retries", 3),
        api_url=cap_data.get("api_url", "http://localhost:11434/api/generate")
    )
    
    llm_data = data.get("llm", {})
    llm = LlmConfig(
        enabled=llm_data.get("enabled", False),
        model=llm_data.get("model", "llama3"),
        api_url=llm_data.get("api_url", "http://localhost:11434/api/generate")
    )
    
    roles_data = data.get("roles", {})
    roles = {
        r_name: RoleConfig(username=r.get("username", ""), password=r.get("password", ""))
        for r_name, r in roles_data.items()
    }
    
    # Fallback to guest if no roles
    if not roles:
        roles["Guest"] = RoleConfig()

    config = CrawlConfig(
        roe_acknowledged=True,
        target_base_url=data.get("target_base_url", ""),
        login_url=data.get("login_url", ""),
        scope_hosts=data.get("scope_hosts", []),
        scope_ips=data.get("scope_ips", []),
        excluded_paths=data.get("excluded_paths", []),
        max_pages_per_role=data.get("max_pages_per_role", 500),
        crawl_depth=data.get("crawl_depth", 10),
        username_selector=data.get("username_selector", "input[name='username']"),
        password_selector=data.get("password_selector", "input[name='password']"),
        submit_selector=data.get("submit_selector", "button[type='submit']"),
        rate_limit=rate_limit,
        captcha=captcha,
        llm=llm,
        roles=roles,
        output_dir=data.get("output_dir", "results"),
        db_path=data.get("db_path", "results/ahvf_crawler.db")
    )
    
    if not config.target_base_url:
        print("[-] FATAL: target_base_url is required in config.")
        sys.exit(1)
        
    if not config.login_url:
        config.login_url = config.target_base_url
        
    _validate_reachability(config.target_base_url)
    
    return config

def _validate_reachability(url: str):
    print(f"[*] Validating reachability of {url}...")
    req = urllib.request.Request(url, headers={'User-Agent': 'AHVF-SecurityScanner/1.0'})
    try:
        urllib.request.urlopen(req, timeout=10)
        print("[+] Target is reachable.")
    except Exception as e:
        print(f"[-] FATAL: Target URL is unreachable: {e}")
        sys.exit(1)
