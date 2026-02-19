import type { Severity } from '@usekova/ccl';

export interface MCPServer {
  tools?: MCPTool[];
  handleToolCall?(name: string, args: Record<string, unknown>): Promise<unknown>;
  [key: string]: unknown;
}

export interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface KovaGuardOptions {
  constraints: string;
  mode?: 'enforce' | 'log_only';
  proofType?: 'audit_log' | 'capability_manifest';
  operatorKeyPair?: import('@usekova/crypto').KeyPair;
  agentIdentifier?: string;
  model?: import('@usekova/identity').ModelAttestation;
  onViolation?: (details: ViolationDetails) => void;
  onToolCall?: (details: ToolCallDetails) => void;
}

export interface WrappedMCPServer extends MCPServer {
  getMonitor(): import('@usekova/enforcement').Monitor;
  getIdentity(): import('@usekova/identity').AgentIdentity;
  getAuditLog(): import('@usekova/enforcement').AuditLog;
  generateProof(): Promise<import('@usekova/proof').ComplianceProof>;
  getReceipt(): import('@usekova/reputation').ExecutionReceipt | null;
  getCovenant(): import('@usekova/core').CovenantDocument;
}

export interface ViolationDetails {
  toolName: string;
  action: string;
  resource: string;
  constraint: string;
  severity: Severity;
  timestamp: string;
}

export interface ToolCallDetails {
  toolName: string;
  action: string;
  resource: string;
  permitted: boolean;
  timestamp: string;
  durationMs: number;
}
