import * as vscode from 'vscode';
import { ProjectInitializer } from './commands/projectInitializer';
import { ConfigurationGenerator } from './commands/configurationGenerator';
import { RequestTester } from './commands/requestTester';
import { AuditLogViewer } from './commands/auditLogViewer';
import { SecurityValidator } from './commands/securityValidator';
import { KeyGenerator } from './commands/keyGenerator';
import { SMCPTreeDataProvider } from './providers/treeDataProvider';
import { ConfigurationProvider } from './providers/configurationProvider';
import { DiagnosticsProvider } from './providers/diagnosticsProvider';

export function activate(context: vscode.ExtensionContext) {
    console.log('SMCP Security extension is now active!');

    // Initialize providers
    const treeDataProvider = new SMCPTreeDataProvider(context);
    const configProvider = new ConfigurationProvider(context);
    const diagnosticsProvider = new DiagnosticsProvider();

    // Register tree view
    const treeView = vscode.window.createTreeView('smcpSecurityView', {
        treeDataProvider: treeDataProvider,
        showCollapseAll: true
    });

    // Initialize command handlers
    const projectInitializer = new ProjectInitializer(context);
    const configGenerator = new ConfigurationGenerator(context);
    const requestTester = new RequestTester(context);
    const auditViewer = new AuditLogViewer(context);
    const securityValidator = new SecurityValidator(context, diagnosticsProvider);
    const keyGenerator = new KeyGenerator(context);

    // Register commands
    const commands = [
        vscode.commands.registerCommand('smcp.initializeProject', () => {
            projectInitializer.initializeProject();
        }),
        vscode.commands.registerCommand('smcp.generateConfig', () => {
            configGenerator.generateConfiguration();
        }),
        vscode.commands.registerCommand('smcp.testRequest', () => {
            requestTester.testRequest();
        }),
        vscode.commands.registerCommand('smcp.viewAuditLogs', () => {
            auditViewer.viewAuditLogs();
        }),
        vscode.commands.registerCommand('smcp.validateSecurity', () => {
            securityValidator.validateSecurity();
        }),
        vscode.commands.registerCommand('smcp.generateKeys', () => {
            keyGenerator.generateKeys();
        })
    ];

    // Register file watchers
    const configWatcher = vscode.workspace.createFileSystemWatcher('**/.smcp/config.json');
    configWatcher.onDidChange(() => {
        treeDataProvider.refresh();
        securityValidator.validateCurrentFile();
    });

    const codeWatcher = vscode.workspace.createFileSystemWatcher('**/*.{js,ts,py,go,rs,java,cs}');
    codeWatcher.onDidSave((uri) => {
        const config = vscode.workspace.getConfiguration('smcp');
        if (config.get('enableAutoValidation')) {
            securityValidator.validateFile(uri);
        }
    });

    // Register webview providers
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('smcp.configEditor', configProvider),
        vscode.window.registerWebviewViewProvider('smcp.auditViewer', auditViewer),
        vscode.window.registerWebviewViewProvider('smcp.requestTester', requestTester)
    );

    // Add all subscriptions
    context.subscriptions.push(
        ...commands,
        treeView,
        configWatcher,
        codeWatcher,
        diagnosticsProvider.diagnosticCollection
    );

    // Check if project is already initialized
    checkProjectInitialization();
}

export function deactivate() {
    console.log('SMCP Security extension is now deactivated.');
}

function checkProjectInitialization() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders) {
        for (const folder of workspaceFolders) {
            const configPath = vscode.Uri.joinPath(folder.uri, '.smcp', 'config.json');
            vscode.workspace.fs.stat(configPath).then(
                () => {
                    // Config exists, set context
                    vscode.commands.executeCommand('setContext', 'smcp.projectInitialized', true);
                },
                () => {
                    // Config doesn't exist
                    vscode.commands.executeCommand('setContext', 'smcp.projectInitialized', false);
                }
            );
        }
    }
}
