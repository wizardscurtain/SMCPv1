#!/usr/bin/env node
/**
 * Node.js Client Example for SMCP Security Framework
 * 
 * This example shows how to integrate with SMCP security from a Node.js MCP client.
 */

const axios = require('axios');
const crypto = require('crypto');

class SMCPSecurityClient {
    constructor(options = {}) {
        this.apiUrl = options.apiUrl || 'https://smcp-security-api.onrender.com';
        this.apiKey = options.apiKey || 'demo_key_123';
        this.timeout = options.timeout || 30000;
        
        // Create axios instance with default config
        this.client = axios.create({
            baseURL: this.apiUrl,
            timeout: this.timeout,
            headers: {
                'Authorization': `Bearer ${this.apiKey}`,
                'Content-Type': 'application/json',
                'User-Agent': 'SMCP-NodeJS-Client/1.0.0'
            }
        });
    }

    /**
     * Validate an MCP request through SMCP security
     */
    async validateRequest(mcpRequest, context = {}) {
        try {
            const response = await this.client.post('/validate', {
                request: mcpRequest,
                context: {
                    user_id: context.userId || 'anonymous',
                    ip_address: context.ipAddress || '127.0.0.1',
                    user_agent: context.userAgent || 'NodeJS-Client',
                    session_id: context.sessionId || crypto.randomUUID(),
                    ...context
                }
            });

            return response.data;
        } catch (error) {
            if (error.response) {
                // Security validation failed
                throw new Error(`Security validation failed: ${error.response.data.error}`);
            } else {
                // Network or other error
                throw new Error(`Request failed: ${error.message}`);
            }
        }
    }

    /**
     * Validate multiple requests in batch
     */
    async validateBatch(requests, context = {}) {
        try {
            const requestsWithContext = requests.map(req => ({
                request: req,
                context: {
                    user_id: context.userId || 'anonymous',
                    ip_address: context.ipAddress || '127.0.0.1',
                    user_agent: context.userAgent || 'NodeJS-Client',
                    session_id: context.sessionId || crypto.randomUUID(),
                    ...context
                }
            }));

            const response = await this.client.post('/batch-validate', requestsWithContext);
            return response.data.results;
        } catch (error) {
            throw new Error(`Batch validation failed: ${error.message}`);
        }
    }

    /**
     * Get service health status
     */
    async getHealth() {
        try {
            const response = await this.client.get('/health');
            return response.data;
        } catch (error) {
            throw new Error(`Health check failed: ${error.message}`);
        }
    }

    /**
     * Get security metrics
     */
    async getMetrics() {
        try {
            const response = await this.client.get('/metrics');
            return response.data;
        } catch (error) {
            throw new Error(`Metrics request failed: ${error.message}`);
        }
    }

    /**
     * Get current security configuration
     */
    async getConfig() {
        try {
            const response = await this.client.get('/config');
            return response.data;
        } catch (error) {
            throw new Error(`Config request failed: ${error.message}`);
        }
    }
}

/**
 * MCP Client with SMCP Security Integration
 */
class SecureMCPClient {
    constructor(mcpServerUrl, smcpOptions = {}) {
        this.mcpServerUrl = mcpServerUrl;
        this.security = new SMCPSecurityClient(smcpOptions);
        this.requestId = 1;
    }

    /**
     * Send a secure MCP request
     */
    async sendRequest(method, params = {}, context = {}) {
        // Create MCP request
        const mcpRequest = {
            jsonrpc: '2.0',
            id: this.requestId++,
            method: method,
            params: params
        };

        try {
            // Validate through SMCP security first
            console.log('🛡️ Validating request through SMCP security...');
            const securityResult = await this.security.validateRequest(mcpRequest, context);

            if (!securityResult.success) {
                throw new Error(`Security validation failed: ${securityResult.error}`);
            }

            console.log('✅ Security validation passed');
            
            // Use the validated request
            const validatedRequest = securityResult.request || mcpRequest;

            // Send to actual MCP server
            console.log('📡 Sending request to MCP server...');
            const response = await axios.post(this.mcpServerUrl, validatedRequest, {
                headers: {
                    'Content-Type': 'application/json'
                },
                timeout: 30000
            });

            // Add security metadata to response
            if (response.data && securityResult.security_metadata) {
                response.data.security_metadata = securityResult.security_metadata;
            }

            return response.data;

        } catch (error) {
            console.error('❌ Request failed:', error.message);
            throw error;
        }
    }

    /**
     * List available tools
     */
    async listTools(context = {}) {
        return this.sendRequest('tools/list', {}, context);
    }

    /**
     * Call a tool
     */
    async callTool(toolName, arguments = {}, context = {}) {
        return this.sendRequest('tools/call', {
            name: toolName,
            arguments: arguments
        }, context);
    }
}

/**
 * Demo function
 */
async function runDemo() {
    console.log('🚀 SMCP Security - Node.js Client Demo\n');

    // Initialize secure MCP client
    const client = new SecureMCPClient(
        'http://localhost:8000/mcp',  // Your MCP server URL
        {
            apiUrl: 'https://smcp-security-api.onrender.com',
            apiKey: 'demo_key_123'
        }
    );

    const context = {
        userId: 'demo_user',
        ipAddress: '192.168.1.100',
        userAgent: 'Demo-Client/1.0'
    };

    try {
        // Check SMCP security service health
        console.log('🏥 Checking SMCP security service health...');
        const health = await client.security.getHealth();
        console.log('Health status:', health.status);
        console.log('Uptime:', Math.round(health.uptime_seconds), 'seconds\n');

        // Get security configuration
        console.log('⚙️ Getting security configuration...');
        const config = await client.security.getConfig();
        console.log('Validation strictness:', config.validation_strictness);
        console.log('Rate limit:', config.default_rate_limit, 'requests/minute\n');

        // Test 1: List tools
        console.log('📋 Test 1: Listing available tools...');
        const toolsResponse = await client.listTools(context);
        console.log('Available tools:', toolsResponse.result?.tools?.length || 0);
        if (toolsResponse.security_metadata) {
            console.log('Security level:', toolsResponse.security_metadata.security_level);
            console.log('Processing time:', toolsResponse.security_metadata.processing_time_ms, 'ms');
        }
        console.log();

        // Test 2: Call echo tool
        console.log('🔊 Test 2: Calling echo tool...');
        const echoResponse = await client.callTool('echo', {
            message: 'Hello from Node.js client!'
        }, context);
        console.log('Echo result:', echoResponse.result?.content?.[0]?.text);
        console.log();

        // Test 3: Call calculate tool
        console.log('🧮 Test 3: Calling calculate tool...');
        const calcResponse = await client.callTool('calculate', {
            expression: '2 + 3 * 4'
        }, context);
        console.log('Calculation result:', calcResponse.result?.content?.[0]?.text);
        console.log();

        // Test 4: Test security validation with malicious input
        console.log('🚨 Test 4: Testing security with malicious input...');
        try {
            await client.callTool('echo', {
                message: 'Hello; rm -rf /'
            }, context);
        } catch (error) {
            console.log('✅ Malicious input blocked:', error.message);
        }
        console.log();

        // Get final metrics
        console.log('📊 Getting security metrics...');
        const metrics = await client.security.getMetrics();
        console.log('Requests processed:', metrics.requests_processed);
        console.log('Requests blocked:', metrics.requests_blocked);
        console.log('Security score:', metrics.security_score);
        console.log('Average processing time:', Math.round(metrics.average_processing_time_ms), 'ms');

    } catch (error) {
        console.error('❌ Demo failed:', error.message);
        process.exit(1);
    }

    console.log('\n✅ Demo completed successfully!');
}

// Export classes for use as library
module.exports = {
    SMCPSecurityClient,
    SecureMCPClient
};

// Run demo if called directly
if (require.main === module) {
    runDemo().catch(console.error);
}
