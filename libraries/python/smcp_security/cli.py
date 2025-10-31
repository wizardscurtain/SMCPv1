#!/usr/bin/env python3
"""Command Line Interface for SMCP Security Framework"""

import argparse
import asyncio
import json
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional

from .core import SMCPSecurityFramework, SecurityConfig
from .exceptions import SecurityError


def create_default_config() -> Dict[str, Any]:
    """Create default configuration file"""
    return {
        "security": {
            "validation_strictness": "standard",
            "enable_mfa": False,  # Disabled by default for ease of use
            "enable_rbac": True,
            "enable_rate_limiting": True,
            "default_rate_limit": 100,
            "enable_encryption": True,
            "enable_ai_immune": True,
            "anomaly_threshold": 0.7,
            "enable_audit_logging": True,
            "log_level": "INFO"
        },
        "server": {
            "host": "0.0.0.0",
            "port": 8080,
            "workers": 1
        },
        "api": {
            "enable_cors": True,
            "cors_origins": ["*"],
            "enable_docs": True
        }
    }


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from file or environment"""
    config = create_default_config()
    
    # Load from file if provided
    if config_path and Path(config_path).exists():
        with open(config_path, 'r') as f:
            file_config = json.load(f)
            config.update(file_config)
    
    # Override with environment variables
    env_mappings = {
        'SMCP_VALIDATION_STRICTNESS': ('security', 'validation_strictness'),
        'SMCP_ENABLE_MFA': ('security', 'enable_mfa'),
        'SMCP_RATE_LIMIT': ('security', 'default_rate_limit'),
        'SMCP_LOG_LEVEL': ('security', 'log_level'),
        'SMCP_HOST': ('server', 'host'),
        'SMCP_PORT': ('server', 'port'),
    }
    
    for env_var, (section, key) in env_mappings.items():
        if env_var in os.environ:
            value = os.environ[env_var]
            # Convert types
            if key in ['enable_mfa', 'enable_rbac', 'enable_rate_limiting', 'enable_encryption', 'enable_ai_immune', 'enable_audit_logging']:
                value = value.lower() in ('true', '1', 'yes', 'on')
            elif key in ['default_rate_limit', 'port', 'workers']:
                value = int(value)
            elif key == 'anomaly_threshold':
                value = float(value)
            
            config[section][key] = value
    
    return config


def check_system() -> bool:
    """Check if system meets requirements"""
    print("🔍 Checking system requirements...")
    
    # Check Python version
    if sys.version_info < (3, 11):
        print("❌ Python 3.11+ required")
        return False
    print("✅ Python version OK")
    
    # Check dependencies
    try:
        import fastapi
        import uvicorn
        import cryptography
        import sklearn
        print("✅ Dependencies OK")
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        return False
    
    # Check permissions
    try:
        test_file = Path("/tmp/smcp_test")
        test_file.write_text("test")
        test_file.unlink()
        print("✅ File permissions OK")
    except Exception:
        print("⚠️  Limited file permissions")
    
    print("✅ System check passed")
    return True


async def run_self_test(config: Dict[str, Any]) -> bool:
    """Run comprehensive self-test"""
    print("🧪 Running security self-test...")
    
    try:
        # Initialize security framework
        security_config = SecurityConfig(**config['security'])
        security = SMCPSecurityFramework(security_config)
        
        # Test basic functionality
        test_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        test_context = {
            "user_id": "test_user",
            "ip_address": "127.0.0.1",
            "user_agent": "SMCP-CLI/1.0"
        }
        
        # Process test request
        result = await security.process_request(test_request, test_context)
        
        if result and 'security_metadata' in result:
            print("✅ Basic security processing OK")
        else:
            print("❌ Security processing failed")
            return False
        
        # Test security components
        if security.input_validator:
            print("✅ Input validation enabled")
        
        if security.jwt_auth:
            print("✅ Authentication system enabled")
        
        if security.rbac_manager:
            print("✅ Authorization system enabled")
        
        if security.rate_limiter:
            print("✅ Rate limiting enabled")
        
        if security.crypto:
            print("✅ Cryptographic system enabled")
        
        if security.ai_immune:
            print("✅ AI immune system enabled")
        
        if security.audit_logger:
            print("✅ Audit logging enabled")
        
        print("✅ Self-test passed")
        return True
        
    except Exception as e:
        print(f"❌ Self-test failed: {e}")
        return False


def scan_vulnerabilities() -> Dict[str, Any]:
    """Scan for common vulnerabilities"""
    print("🔍 Scanning for vulnerabilities...")
    
    vulnerabilities = []
    warnings = []
    
    # Check for insecure configurations
    if os.environ.get('SMCP_ENABLE_MFA', '').lower() in ('false', '0', 'no', 'off'):
        warnings.append("MFA is disabled - consider enabling for production")
    
    if os.environ.get('SMCP_VALIDATION_STRICTNESS', '') == 'minimal':
        warnings.append("Validation strictness is minimal - consider 'standard' or 'maximum'")
    
    # Check file permissions
    config_files = ['smcp-config.json', 'security.json', '.env']
    for config_file in config_files:
        if Path(config_file).exists():
            stat = Path(config_file).stat()
            if stat.st_mode & 0o077:  # Check if readable by others
                vulnerabilities.append(f"Config file {config_file} has insecure permissions")
    
    # Check for default secrets
    if os.environ.get('JWT_SECRET_KEY') in ['secret', 'default', 'changeme']:
        vulnerabilities.append("Using default JWT secret key")
    
    result = {
        "vulnerabilities": vulnerabilities,
        "warnings": warnings,
        "status": "secure" if not vulnerabilities else "vulnerable"
    }
    
    if vulnerabilities:
        print(f"❌ Found {len(vulnerabilities)} vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"  - {vuln}")
    else:
        print("✅ No vulnerabilities found")
    
    if warnings:
        print(f"⚠️  {len(warnings)} warnings:")
        for warning in warnings:
            print(f"  - {warning}")
    
    return result


def generate_report(config: Dict[str, Any]) -> Dict[str, Any]:
    """Generate security configuration report"""
    print("📊 Generating security report...")
    
    security_config = config['security']
    
    report = {
        "timestamp": "2025-01-27T12:00:00Z",
        "version": "1.0.0",
        "configuration": {
            "validation_strictness": security_config['validation_strictness'],
            "mfa_enabled": security_config['enable_mfa'],
            "rbac_enabled": security_config['enable_rbac'],
            "rate_limiting_enabled": security_config['enable_rate_limiting'],
            "encryption_enabled": security_config['enable_encryption'],
            "ai_immune_enabled": security_config['enable_ai_immune'],
            "audit_logging_enabled": security_config['enable_audit_logging']
        },
        "security_score": 0
    }
    
    # Calculate security score
    score = 0
    if security_config['validation_strictness'] == 'maximum':
        score += 20
    elif security_config['validation_strictness'] == 'standard':
        score += 15
    else:
        score += 10
    
    if security_config['enable_mfa']:
        score += 20
    if security_config['enable_rbac']:
        score += 15
    if security_config['enable_rate_limiting']:
        score += 10
    if security_config['enable_encryption']:
        score += 15
    if security_config['enable_ai_immune']:
        score += 10
    if security_config['enable_audit_logging']:
        score += 10
    
    report['security_score'] = score
    
    # Security level
    if score >= 90:
        level = "Excellent"
    elif score >= 75:
        level = "Good"
    elif score >= 60:
        level = "Fair"
    else:
        level = "Poor"
    
    report['security_level'] = level
    
    print(f"Security Score: {score}/100 ({level})")
    
    return report


async def start_server(config: Dict[str, Any]):
    """Start SMCP security server"""
    try:
        import uvicorn
        from fastapi import FastAPI, HTTPException
        from fastapi.middleware.cors import CORSMiddleware
        
        # Initialize security framework
        security_config = SecurityConfig(**config['security'])
        security = SMCPSecurityFramework(security_config)
        
        # Create FastAPI app
        app = FastAPI(
            title="SMCP Security API",
            description="Secure Model Context Protocol Security Framework",
            version="1.0.0",
            docs_url="/docs" if config['api']['enable_docs'] else None
        )
        
        # Add CORS middleware
        if config['api']['enable_cors']:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=config['api']['cors_origins'],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        
        @app.get("/")
        async def root():
            return {"message": "SMCP Security Framework API", "version": "1.0.0"}
        
        @app.get("/health")
        async def health():
            return {"status": "healthy", "timestamp": "2025-01-27T12:00:00Z"}
        
        @app.post("/validate")
        async def validate_request(data: dict):
            try:
                request_data = data.get('request')
                context = data.get('context')
                
                if not request_data or not context:
                    raise HTTPException(status_code=400, detail="Missing request or context")
                
                result = await security.process_request(request_data, context)
                return result
                
            except SecurityError as e:
                raise HTTPException(status_code=403, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/metrics")
        async def get_metrics():
            return security.get_security_metrics()
        
        # Start server
        server_config = config['server']
        print(f"🚀 Starting SMCP Security API server on {server_config['host']}:{server_config['port']}")
        
        uvicorn.run(
            app,
            host=server_config['host'],
            port=server_config['port'],
            workers=server_config['workers']
        )
        
    except ImportError:
        print("❌ FastAPI/Uvicorn not installed. Install with: pip install smcp-security[all]")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Server startup failed: {e}")
        sys.exit(1)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="SMCP Security Framework CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  smcp-security --check-system
  smcp-security --server --config security.json
  smcp-security --scan
  smcp-security --report
  smcp-security --init
        """
    )
    
    parser.add_argument('--version', action='version', version='SMCP Security Framework 1.0.0')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--check-system', action='store_true', help='Check system requirements')
    parser.add_argument('--self-test', action='store_true', help='Run security self-test')
    parser.add_argument('--scan', action='store_true', help='Scan for vulnerabilities')
    parser.add_argument('--report', action='store_true', help='Generate security report')
    parser.add_argument('--server', action='store_true', help='Start security API server')
    parser.add_argument('--init', action='store_true', help='Initialize configuration file')
    parser.add_argument('--show-config', action='store_true', help='Show current configuration')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Handle commands
    if args.init:
        config_file = args.config or 'smcp-config.json'
        with open(config_file, 'w') as f:
            json.dump(create_default_config(), f, indent=2)
        print(f"✅ Configuration file created: {config_file}")
        return
    
    if args.show_config:
        print(json.dumps(config, indent=2))
        return
    
    if args.check_system:
        success = check_system()
        sys.exit(0 if success else 1)
    
    if args.self_test:
        success = asyncio.run(run_self_test(config))
        sys.exit(0 if success else 1)
    
    if args.scan:
        result = scan_vulnerabilities()
        sys.exit(0 if result['status'] == 'secure' else 1)
    
    if args.report:
        report = generate_report(config)
        print(json.dumps(report, indent=2))
        return
    
    if args.server:
        asyncio.run(start_server(config))
        return
    
    # Default: show help
    parser.print_help()


if __name__ == '__main__':
    main()
