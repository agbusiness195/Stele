import type { Severity } from '@grith/ccl';

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

export interface GrithGuardOptions {
  constraints: string;
  mode?: 'enforce' | 'log_only';
  proofType?: 'audit_log' | 'capability_manifest';
  operatorKeyPair?: import('@grith/crypto').KeyPair;
  agentIdentifier?: string;
  model?: import('@grith/identity').ModelAttestation;
  onViolation?: (details: ViolationDetails) => void;
  onToolCall?: (details: ToolCallDetails) => void;
}

export interface WrappedMCPServer extends MCPServer {
  getMonitor(): import('@grith/enforcement').Monitor;
  getIdentity(): import('@grith/identity').AgentIdentity;
  getAuditLog(): import('@grith/enforcement').AuditLog;
  generateProof(): Promise<import('@grith/proof').ComplianceProof>;
  getReceipt(): import('@grith/reputation').ExecutionReceipt | null;
  getCovenant(): import('@grith/core').CovenantDocument;
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
