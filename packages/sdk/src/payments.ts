/**
 * Two-sided payment system for the Kervyx protocol.
 *
 * Manages agent accounts, tracks query income, processes payments between
 * agents, and maintains an immutable transaction ledger. Agents earn from
 * trust resolution queries and spend on certifications and marketplace fees.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** A payment account for an agent. */
export interface PaymentAccount {
  /** The agent this account belongs to. */
  agentId: string;
  /** Current balance. */
  balance: number;
  /** Total amount ever earned. */
  totalEarned: number;
  /** Total amount ever spent. */
  totalSpent: number;
  /** Total earned from trust resolution queries. */
  queryIncome: number;
  /** Rate earned per trust resolution query. */
  incomePerQuery: number;
}

/** A single payment transaction. */
export interface PaymentTransaction {
  /** Unique transaction identifier. */
  id: string;
  /** Sender agent ID or 'system'. */
  from: string;
  /** Recipient agent ID or 'protocol'. */
  to: string;
  /** Transaction amount. */
  amount: number;
  /** Type of transaction. */
  type: 'query_income' | 'trust_resolution' | 'certification_fee' | 'marketplace_fee';
  /** Timestamp of the transaction. */
  timestamp: number;
}

/** The full payment ledger tracking all accounts and transactions. */
export interface PaymentLedger {
  /** Map of agent IDs to their payment accounts. */
  accounts: Map<string, PaymentAccount>;
  /** Ordered list of all transactions. */
  transactions: PaymentTransaction[];
  /** Total revenue collected by the protocol. */
  protocolRevenue: number;
  /** Total amount in circulation across all accounts. */
  totalCirculation: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

let _txCounter = 0;

function generateTransactionId(): string {
  _txCounter += 1;
  return `tx-${Date.now()}-${_txCounter}`;
}

// ─── Ledger Factory ──────────────────────────────────────────────────────────

/**
 * Create a new, empty payment ledger.
 *
 * @returns A fresh PaymentLedger with no accounts or transactions.
 */
export function createLedger(): PaymentLedger {
  return {
    accounts: new Map(),
    transactions: [],
    protocolRevenue: 0,
    totalCirculation: 0,
  };
}

// ─── Account Management ─────────────────────────────────────────────────────

/**
 * Create a new payment account for an agent in the ledger.
 *
 * @param ledger - The current ledger.
 * @param agentId - The agent to create an account for.
 * @param incomePerQuery - Rate earned per query. Default: 0.0002.
 * @returns A new ledger with the account added.
 */
export function createAccount(
  ledger: PaymentLedger,
  agentId: string,
  incomePerQuery?: number,
): PaymentLedger {
  const accounts = new Map(ledger.accounts);

  accounts.set(agentId, {
    agentId,
    balance: 0,
    totalEarned: 0,
    totalSpent: 0,
    queryIncome: 0,
    incomePerQuery: incomePerQuery ?? 0.0002,
  });

  return {
    ...ledger,
    accounts,
  };
}

// ─── Query Income ────────────────────────────────────────────────────────────

/**
 * Record query income for an agent.
 *
 * Adds the agent's incomePerQuery to their balance, queryIncome, and
 * totalEarned. Creates a transaction record and updates total circulation.
 *
 * @param ledger - The current ledger.
 * @param agentId - The agent earning the income.
 * @returns A new ledger reflecting the income.
 */
export function recordQueryIncome(ledger: PaymentLedger, agentId: string): PaymentLedger {
  const account = ledger.accounts.get(agentId);
  if (!account) {
    return ledger;
  }

  const amount = account.incomePerQuery;

  const updatedAccount: PaymentAccount = {
    ...account,
    balance: account.balance + amount,
    totalEarned: account.totalEarned + amount,
    queryIncome: account.queryIncome + amount,
  };

  const transaction: PaymentTransaction = {
    id: generateTransactionId(),
    from: 'system',
    to: agentId,
    amount,
    type: 'query_income',
    timestamp: Date.now(),
  };

  const accounts = new Map(ledger.accounts);
  accounts.set(agentId, updatedAccount);

  return {
    accounts,
    transactions: [...ledger.transactions, transaction],
    protocolRevenue: ledger.protocolRevenue,
    totalCirculation: ledger.totalCirculation + amount,
  };
}

// ─── Payment Processing ─────────────────────────────────────────────────────

/**
 * Process a payment between two agents (or to the protocol).
 *
 * Checks that the sender has sufficient balance before processing.
 * Updates both sender and recipient accounts, and records the transaction.
 *
 * @param ledger - The current ledger.
 * @param params - Payment details: from, to, amount, type.
 * @returns An object with the updated ledger, success flag, and reason.
 */
export function processPayment(
  ledger: PaymentLedger,
  params: {
    from: string;
    to: string;
    amount: number;
    type: PaymentTransaction['type'];
  },
): { ledger: PaymentLedger; success: boolean; reason: string } {
  const { from, to, amount, type } = params;

  // Get sender account
  const senderAccount = ledger.accounts.get(from);
  if (!senderAccount) {
    return { ledger, success: false, reason: `Account not found: ${from}` };
  }

  // Check sufficient balance
  if (senderAccount.balance < amount) {
    return {
      ledger,
      success: false,
      reason: `Insufficient balance: ${senderAccount.balance} < ${amount}`,
    };
  }

  const accounts = new Map(ledger.accounts);

  // Update sender
  accounts.set(from, {
    ...senderAccount,
    balance: senderAccount.balance - amount,
    totalSpent: senderAccount.totalSpent + amount,
  });

  // Update recipient (if they have an account)
  let protocolRevenue = ledger.protocolRevenue;

  if (to === 'protocol') {
    protocolRevenue += amount;
  } else {
    const recipientAccount = accounts.get(to);
    if (recipientAccount) {
      accounts.set(to, {
        ...recipientAccount,
        balance: recipientAccount.balance + amount,
        totalEarned: recipientAccount.totalEarned + amount,
      });
    } else {
      // If recipient has no account, treat as protocol revenue
      protocolRevenue += amount;
    }
  }

  const transaction: PaymentTransaction = {
    id: generateTransactionId(),
    from,
    to,
    amount,
    type,
    timestamp: Date.now(),
  };

  return {
    ledger: {
      accounts,
      transactions: [...ledger.transactions, transaction],
      protocolRevenue,
      totalCirculation: ledger.totalCirculation,
    },
    success: true,
    reason: 'Payment processed successfully',
  };
}

// ─── Account Lookup ──────────────────────────────────────────────────────────

/**
 * Get the account summary for an agent.
 *
 * @param ledger - The current ledger.
 * @param agentId - The agent to look up.
 * @returns The PaymentAccount, or null if not found.
 */
export function getAccountSummary(
  ledger: PaymentLedger,
  agentId: string,
): PaymentAccount | null {
  return ledger.accounts.get(agentId) ?? null;
}
