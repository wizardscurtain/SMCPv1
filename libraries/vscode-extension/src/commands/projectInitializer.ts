import * as vscode from 'vscode';
import * as path from 'path';
import { LanguageDetector } from '../utils/languageDetector';
import { TemplateGenerator } from '../utils/templateGenerator';
import { PackageManager } from '../utils/packageManager';

export class ProjectInitializer {
    constructor(private context: vscode.ExtensionContext) {}

    async initializeProject() {
        try {
            // Get workspace folder
            const workspaceFolder = await this.getWorkspaceFolder();
            if (!workspaceFolder) {
                return;
            }

            // Detect project language
            const language = await LanguageDetector.detectLanguage(workspaceFolder.uri);
            
            // Show language selection if detection failed
            const selectedLanguage = language || await this.selectLanguage();
            if (!selectedLanguage) {
                return;
            }

            // Show framework selection
            const framework = await this.selectFramework(selectedLanguage);
            if (!framework) {
                return;
            }

            // Show configuration options
            const config = await this.getSecurityConfiguration();
            if (!config) {
                return;
            }

            // Show progress
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Initializing SMCP Security',
                cancellable: false
            }, async (progress) => {
                // Create .smcp directory
                progress.report({ increment: 10, message: 'Creating configuration directory...' });
                await this.createSMCPDirectory(workspaceFolder.uri);

                // Install dependencies
                progress.report({ increment: 20, message: 'Installing dependencies...' });
                await PackageManager.installDependencies(workspaceFolder.uri, selectedLanguage);

                // Generate configuration files
                progress.report({ increment: 40, message: 'Generating configuration files...' });
                await this.generateConfigurationFiles(workspaceFolder.uri, config);

                // Generate example code
                progress.report({ increment: 60, message: 'Generating example code...' });
                await TemplateGenerator.generateExampleCode(
                    workspaceFolder.uri,
                    selectedLanguage,
                    framework,
                    config
                );

                // Generate documentation
                progress.report({ increment: 80, message: 'Generating documentation...' });
                await this.generateDocumentation(workspaceFolder.uri, selectedLanguage, framework);

                progress.report({ increment: 100, message: 'Initialization complete!' });
            });

            // Set context for UI updates
            vscode.commands.executeCommand('setContext', 'smcp.projectInitialized', true);

            // Show success message
            const openConfig = 'Open Configuration';
            const viewDocs = 'View Documentation';
            const result = await vscode.window.showInformationMessage(
                'SMCP Security has been successfully initialized!',
                openConfig,
                viewDocs
            );

            if (result === openConfig) {
                const configUri = vscode.Uri.joinPath(workspaceFolder.uri, '.smcp', 'config.json');
                await vscode.window.showTextDocument(configUri);
            } else if (result === viewDocs) {
                const docsUri = vscode.Uri.joinPath(workspaceFolder.uri, 'SMCP_SECURITY.md');
                await vscode.window.showTextDocument(docsUri);
            }

        } catch (error) {
            vscode.window.showErrorMessage(`Failed to initialize SMCP Security: ${error}`);
        }
    }

    private async getWorkspaceFolder(): Promise<vscode.WorkspaceFolder | undefined> {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        
        if (!workspaceFolders || workspaceFolders.length === 0) {
            vscode.window.showErrorMessage('No workspace folder is open.');
            return undefined;
        }

        if (workspaceFolders.length === 1) {
            return workspaceFolders[0];
        }

        // Multiple workspace folders, let user choose
        const items = workspaceFolders.map(folder => ({
            label: folder.name,
            description: folder.uri.fsPath,
            folder: folder
        }));

        const selected = await vscode.window.showQuickPick(items, {
            placeHolder: 'Select workspace folder to initialize'
        });

        return selected?.folder;
    }

    private async selectLanguage(): Promise<string | undefined> {
        const languages = [
            { label: 'Python', description: 'FastAPI, Flask, Django support' },
            { label: 'Node.js/TypeScript', description: 'Express, Fastify, Koa support' },
            { label: 'Go', description: 'Gorilla Mux, Gin, Echo support' },
            { label: 'Rust', description: 'Axum, Warp, Actix-web support' },
            { label: 'Java', description: 'Spring Boot, Quarkus support' },
            { label: 'C#', description: 'ASP.NET Core support' }
        ];

        const selected = await vscode.window.showQuickPick(languages, {
            placeHolder: 'Select your project language'
        });

        return selected?.label.toLowerCase().replace('/', '-');
    }

    private async selectFramework(language: string): Promise<string | undefined> {
        const frameworks: { [key: string]: Array<{ label: string; description: string }> } = {
            'python': [
                { label: 'FastAPI', description: 'Modern, fast web framework' },
                { label: 'Flask', description: 'Lightweight WSGI framework' },
                { label: 'Django', description: 'High-level web framework' }
            ],
            'node.js-typescript': [
                { label: 'Express', description: 'Fast, unopinionated framework' },
                { label: 'Fastify', description: 'Fast and low overhead framework' },
                { label: 'Koa', description: 'Next generation framework' }
            ],
            'go': [
                { label: 'Gorilla Mux', description: 'Powerful HTTP router' },
                { label: 'Gin', description: 'High-performance framework' },
                { label: 'Echo', description: 'High performance, minimalist framework' }
            ],
            'rust': [
                { label: 'Axum', description: 'Ergonomic and modular framework' },
                { label: 'Warp', description: 'Super-easy, composable framework' },
                { label: 'Actix-web', description: 'Powerful, pragmatic framework' }
            ],
            'java': [
                { label: 'Spring Boot', description: 'Production-ready framework' },
                { label: 'Quarkus', description: 'Kubernetes Native Java stack' }
            ],
            'c#': [
                { label: 'ASP.NET Core', description: 'Cross-platform framework' },
                { label: 'Minimal APIs', description: 'Lightweight API framework' }
            ]
        };

        const frameworkOptions = frameworks[language] || [];
        if (frameworkOptions.length === 0) {
            return 'default';
        }

        const selected = await vscode.window.showQuickPick(frameworkOptions, {
            placeHolder: `Select ${language} framework`
        });

        return selected?.label.toLowerCase().replace(/[^a-z0-9]/g, '-');
    }

    private async getSecurityConfiguration(): Promise<any | undefined> {
        const config = vscode.workspace.getConfiguration('smcp');
        
        // Use VS Code settings as defaults
        const defaultConfig = {
            enableMFA: config.get('enableMFA', true),
            validationStrictness: config.get('validationStrictness', 'standard'),
            enableAIImmune: config.get('enableAIImmune', true),
            anomalyThreshold: config.get('anomalyThreshold', 0.7),
            defaultRateLimit: config.get('defaultRateLimit', 100),
            logLevel: config.get('logLevel', 'INFO')
        };

        // Show configuration options
        const customize = 'Customize Configuration';
        const useDefaults = 'Use Default Configuration';
        
        const choice = await vscode.window.showQuickPick(
            [useDefaults, customize],
            { placeHolder: 'Choose configuration approach' }
        );

        if (choice === customize) {
            return await this.customizeConfiguration(defaultConfig);
        } else if (choice === useDefaults) {
            return defaultConfig;
        }

        return undefined;
    }

    private async customizeConfiguration(defaultConfig: any): Promise<any | undefined> {
        // This would open a webview for configuration customization
        // For now, return the default config
        return defaultConfig;
    }

    private async createSMCPDirectory(workspaceUri: vscode.Uri): Promise<void> {
        const smcpDir = vscode.Uri.joinPath(workspaceUri, '.smcp');
        const keysDir = vscode.Uri.joinPath(smcpDir, 'keys');
        
        await vscode.workspace.fs.createDirectory(smcpDir);
        await vscode.workspace.fs.createDirectory(keysDir);
    }

    private async generateConfigurationFiles(workspaceUri: vscode.Uri, config: any): Promise<void> {
        const configPath = vscode.Uri.joinPath(workspaceUri, '.smcp', 'config.json');
        const policiesPath = vscode.Uri.joinPath(workspaceUri, '.smcp', 'policies.json');
        const gitignorePath = vscode.Uri.joinPath(workspaceUri, '.smcp', '.gitignore');

        // Generate main configuration
        const mainConfig = {
            version: '1.0.0',
            security: {
                enableInputValidation: true,
                validationStrictness: config.validationStrictness,
                enableMFA: config.enableMFA,
                enableRBAC: true,
                enableRateLimiting: true,
                defaultRateLimit: config.defaultRateLimit,
                enableEncryption: true,
                enableAIImmune: config.enableAIImmune,
                anomalyThreshold: config.anomalyThreshold,
                enableAuditLogging: true,
                logLevel: config.logLevel
            },
            jwt: {
                expirySeconds: 3600,
                algorithm: 'HS256'
            },
            rateLimit: {
                windowMs: 60000,
                adaptiveLimits: true
            },
            audit: {
                logFile: '.smcp/audit.log',
                maxFileSize: '10MB',
                maxFiles: 5
            }
        };

        // Generate security policies
        const policies = {
            roles: {
                admin: ['read', 'write', 'delete', 'admin', 'tools:*', 'resources:*', 'prompts:*'],
                user: ['read', 'tools:list', 'tools:call', 'resources:list', 'resources:read', 'prompts:list', 'prompts:get'],
                readonly: ['read', 'tools:list', 'resources:list', 'prompts:list']
            },
            validation: {
                maxRequestSize: '1MB',
                allowedMethods: ['tools/list', 'tools/call', 'resources/list', 'resources/read', 'prompts/list', 'prompts/get'],
                blockedPatterns: ['../../../', 'rm -rf', 'DROP TABLE', '<script>']
            },
            rateLimit: {
                global: config.defaultRateLimit,
                perUser: config.defaultRateLimit,
                perIP: config.defaultRateLimit * 2
            }
        };

        // Generate .gitignore
        const gitignoreContent = `# SMCP Security - Sensitive files
keys/
*.key
*.pem
*.p12
audit.log
secrets.json
`;

        // Write files
        await vscode.workspace.fs.writeFile(configPath, Buffer.from(JSON.stringify(mainConfig, null, 2)));
        await vscode.workspace.fs.writeFile(policiesPath, Buffer.from(JSON.stringify(policies, null, 2)));
        await vscode.workspace.fs.writeFile(gitignorePath, Buffer.from(gitignoreContent));
    }

    private async generateDocumentation(workspaceUri: vscode.Uri, language: string, framework: string): Promise<void> {
        const docsPath = vscode.Uri.joinPath(workspaceUri, 'SMCP_SECURITY.md');
        
        const documentation = `# SMCP Security Setup

This project has been configured with SMCP Security v1.0 for enhanced MCP protocol security.

## Configuration

- **Language**: ${language}
- **Framework**: ${framework}
- **Configuration**: \`.smcp/config.json\`
- **Policies**: \`.smcp/policies.json\`

## Features Enabled

- ✅ Input Validation
- ✅ Authentication & Authorization
- ✅ Rate Limiting
- ✅ Encryption
- ✅ AI Immune System
- ✅ Audit Logging

## Quick Start

1. Install dependencies (already done)
2. Review configuration in \`.smcp/config.json\`
3. Customize security policies in \`.smcp/policies.json\`
4. Run your application with SMCP security enabled

## Documentation

- [SMCP Security Documentation](https://github.com/wizardscurtain/SMCPv1)
- [${language} Library Documentation](https://github.com/wizardscurtain/SMCPv1/tree/main/libraries/${language})
- [Security Best Practices](https://github.com/wizardscurtain/SMCPv1/blob/main/docs/security-best-practices.md)

## Support

For support, please visit:
- [GitHub Issues](https://github.com/wizardscurtain/SMCPv1/issues)
- [Documentation](https://github.com/wizardscurtain/SMCPv1)
- [Email Support](mailto:support@smcp.dev)
`;

        await vscode.workspace.fs.writeFile(docsPath, Buffer.from(documentation));
    }
}
