import type { Severity } from '@kervyx/ccl';

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

export interface KervyxGuardOptions {
  constraints: string;
  mode?: 'enforce' | 'log_only';
  proofType?: 'audit_log' | 'capability_manifest';
  operatorKeyPair?: import('@kervyx/crypto').KeyPair;
  agentIdentifier?: string;
  model?: import('@kervyx/identity').ModelAttestation;
  onViolation?: (details: ViolationDetails) => void;
  onToolCall?: (details: ToolCallDetails) => void;
}

export interface WrappedMCPServer extends MCPServer {
  getMonitor(): import('@kervyx/enforcement').Monitor;
  getIdentity(): import('@kervyx/identity').AgentIdentity;
  getAuditLog(): import('@kervyx/enforcement').AuditLog;
  generateProof(): Promise<import('@kervyx/proof').ComplianceProof>;
  getReceipt(): import('@kervyx/reputation').ExecutionReceipt | null;
  getCovenant(): import('@kervyx/core').CovenantDocument;
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
