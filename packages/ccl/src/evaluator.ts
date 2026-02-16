import type {
  CCLDocument,
  Condition,
  CompoundCondition,
  EvaluationContext,
  EvaluationResult,
  LimitStatement,
  NarrowingViolation,
  PermitDenyStatement,
  RequireStatement,
  Statement,
} from './types.js';

/**
 * Match an action string against a dot-separated pattern.
 *
 * Segments are split on `.`. Wildcard rules:
 * - `*` matches exactly one segment (e.g. `file.*` matches `file.read`)
 * - `**` matches zero or more segments (e.g. `file.**` matches `file.read.all`)
 *
 * @param pattern - The action pattern (e.g. `"file.*"`, `"**"`).
 * @param action - The concrete action string to test (e.g. `"file.read"`).
 * @returns `true` if the action matches the pattern.
 *
 * @example
 * ```typescript
 * matchAction('file.*', 'file.read');   // true
 * matchAction('file.*', 'file.a.b');    // false
 * matchAction('**', 'anything.here');   // true
 * ```
 */
export function matchAction(pattern: string, action: string): boolean {
  const patternParts = pattern.split('.');
  const actionParts = action.split('.');
  return matchSegments(patternParts, 0, actionParts, 0);
}

/**
 * Match a resource path against a slash-separated pattern.
 *
 * Segments are split on `/`. Leading/trailing slashes are normalized.
 * Wildcard rules:
 * - `*` matches exactly one path segment
 * - `**` matches zero or more segments
 *
 * Note: resource matching is exact per-segment. `/secrets` does NOT
 * match `/secrets/key` unless you use `/secrets/**`.
 *
 * @param pattern - The resource pattern (e.g. `"/data/**"`, `"/api/*"`).
 * @param resource - The concrete resource path to test.
 * @returns `true` if the resource matches the pattern.
 *
 * @example
 * ```typescript
 * matchResource('/data/**', '/data/users/123');  // true
 * matchResource('/data/*', '/data/users/123');   // false
 * matchResource('/data/*', '/data/users');       // true
 * ```
 */
export function matchResource(pattern: string, resource: string): boolean {
  // Normalize: remove leading/trailing slashes for matching
  const normPattern = pattern.replace(/^\/+|\/+$/g, '');
  const normResource = resource.replace(/^\/+|\/+$/g, '');

  // Handle empty patterns
  if (normPattern === '' && normResource === '') return true;
  if (normPattern === '**') return true;
  if (normPattern === '*' && !normResource.includes('/')) return true;

  const patternParts = normPattern.split('/');
  const resourceParts = normResource.split('/');
  return matchSegments(patternParts, 0, resourceParts, 0);
}

/**
 * Recursive segment matcher supporting single (`*`) and globstar (`**`) wildcards.
 *
 * Uses a greedy-with-backtracking algorithm:
 * 1. Walk pattern and target arrays in parallel from the given indices.
 * 2. On a literal or `*` segment, advance both cursors (literal must match
 *    exactly; `*` matches any single segment).
 * 3. On a `**` segment, try matching zero additional segments first (advance
 *    pattern index only). If that fails, consume one target segment and retry
 *    (recursive backtracking). This lets `**` match zero-or-more segments.
 * 4. After the loop, any trailing `**` in the pattern are consumed (they
 *    match zero remaining segments).
 * 5. Both cursors must reach their respective ends for a successful match.
 *
 * @param pattern - Array of pattern segments (e.g. `['file', '*']`).
 * @param pi      - Current index into the pattern array.
 * @param target  - Array of concrete segments to match against.
 * @param ti      - Current index into the target array.
 * @returns `true` if the target segments match the pattern from the given offsets.
 */
function matchSegments(
  pattern: string[],
  pi: number,
  target: string[],
  ti: number,
): boolean {
  while (pi < pattern.length && ti < target.length) {
    const p = pattern[pi]!;

    if (p === '**') {
      // ** (globstar) can match zero or more segments.
      // First, try matching zero segments by advancing only the pattern cursor.
      if (matchSegments(pattern, pi + 1, target, ti)) {
        return true;
      }
      // If zero-match failed, consume one target segment and retry with
      // the same ** pattern position (allows matching 1, 2, ... N segments).
      return matchSegments(pattern, pi, target, ti + 1);
    }

    if (p === '*') {
      // * (single wildcard) matches exactly one segment regardless of content.
      pi++;
      ti++;
      continue;
    }

    // Literal segment: must match the target segment exactly.
    if (p !== target[ti]) {
      return false;
    }

    pi++;
    ti++;
  }

  // Consume any trailing ** patterns in the pattern array, since they
  // can legally match zero remaining segments.
  while (pi < pattern.length && pattern[pi] === '**') {
    pi++;
  }

  // Both cursors must have reached the end for a full match.
  return pi === pattern.length && ti === target.length;
}

/**
 * Calculate the specificity score of an action+resource pattern pair.
 *
 * More specific patterns produce higher scores. Scoring per segment:
 * - Literal segment: 2 points
 * - Single wildcard (`*`): 1 point
 * - Double wildcard (`**`): 0 points
 *
 * Used internally by {@link evaluate} to resolve conflicts: when multiple
 * rules match, the most specific one wins.
 *
 * @param actionPattern - The action pattern (dot-separated).
 * @param resourcePattern - The resource pattern (slash-separated).
 * @returns A non-negative integer specificity score.
 *
 * @example
 * ```typescript
 * specificity('file.read', '/data/users'); // 8
 * specificity('**', '**');                 // 0
 * ```
 */
export function specificity(actionPattern: string, resourcePattern: string): number {
  let score = 0;

  const actionParts = actionPattern.split('.');
  for (const part of actionParts) {
    if (part === '**') {
      score += 0;
    } else if (part === '*') {
      score += 1;
    } else {
      score += 2;
    }
  }

  const normResource = resourcePattern.replace(/^\/+|\/+$/g, '');
  if (normResource.length > 0) {
    const resourceParts = normResource.split('/');
    for (const part of resourceParts) {
      if (part === '**') {
        score += 0;
      } else if (part === '*') {
        score += 1;
      } else {
        score += 2;
      }
    }
  }

  return score;
}

/**
 * Evaluate a simple or compound condition against a context object.
 *
 * Supports all CCL operators (`=`, `!=`, `<`, `>`, `contains`, `in`,
 * `matches`, etc.) and compound conditions (`and`, `or`, `not`).
 * Missing context fields evaluate to `false` (safe default-deny).
 *
 * @param condition - The condition (simple or compound) to evaluate.
 * @param context - Key-value context object; supports dotted field paths.
 * @returns `true` if the condition is satisfied.
 *
 * @example
 * ```typescript
 * const cond = { field: 'user.role', operator: '=' as const, value: 'admin' };
 * evaluateCondition(cond, { user: { role: 'admin' } }); // true
 * ```
 */
export function evaluateCondition(
  condition: Condition | CompoundCondition,
  context: EvaluationContext,
): boolean {
  if (isCompoundCondition(condition)) {
    return evaluateCompoundCondition(condition, context);
  }
  return evaluateSimpleCondition(condition, context);
}

/**
 * Evaluate a compound (logical) condition against a context.
 *
 * - `and`: all sub-conditions must be true (short-circuit on first false).
 * - `or`: at least one sub-condition must be true (short-circuit on first true).
 * - `not`: negates the single sub-condition.
 */
function evaluateCompoundCondition(
  condition: CompoundCondition,
  context: EvaluationContext,
): boolean {
  switch (condition.type) {
    case 'and':
      // All sub-conditions must hold; short-circuits on first failure.
      return condition.conditions.every((c) => evaluateCondition(c, context));
    case 'or':
      // At least one sub-condition must hold; short-circuits on first success.
      return condition.conditions.some((c) => evaluateCondition(c, context));
    case 'not':
      // Logical negation of the single sub-condition.
      return !evaluateCondition(condition.conditions[0]!, context);
    default:
      return false;
  }
}

/**
 * Evaluate a simple (field operator value) condition against a context.
 *
 * Resolves the field via dot-path lookup, then applies the operator.
 * Missing fields always evaluate to `false` (default-deny principle).
 */
function evaluateSimpleCondition(
  condition: Condition,
  context: EvaluationContext,
): boolean {
  // Resolve dotted field path (e.g. "user.role") against the context object.
  const fieldValue = resolveField(context, condition.field);

  // Default-deny: if the field doesn't exist in the context, the condition fails.
  if (fieldValue === undefined) {
    return false;
  }

  const { operator, value } = condition;

  switch (operator) {
    case '=':
      return fieldValue === value;
    case '!=':
      return fieldValue !== value;
    case '<':
      return typeof fieldValue === 'number' && typeof value === 'number' && fieldValue < value;
    case '>':
      return typeof fieldValue === 'number' && typeof value === 'number' && fieldValue > value;
    case '<=':
      return typeof fieldValue === 'number' && typeof value === 'number' && fieldValue <= value;
    case '>=':
      return typeof fieldValue === 'number' && typeof value === 'number' && fieldValue >= value;
    case 'contains':
      if (typeof fieldValue === 'string' && typeof value === 'string') {
        return fieldValue.includes(value);
      }
      if (Array.isArray(fieldValue)) {
        return fieldValue.includes(value);
      }
      return false;
    case 'not_contains':
      if (typeof fieldValue === 'string' && typeof value === 'string') {
        return !fieldValue.includes(value);
      }
      if (Array.isArray(fieldValue)) {
        return !fieldValue.includes(value);
      }
      return true;
    case 'in':
      if (Array.isArray(value)) {
        return value.includes(String(fieldValue));
      }
      return false;
    case 'not_in':
      if (Array.isArray(value)) {
        return !value.includes(String(fieldValue));
      }
      return true;
    case 'matches': {
      if (typeof fieldValue === 'string' && typeof value === 'string') {
        try {
          const re = new RegExp(value);
          return re.test(fieldValue);
        } catch {
          // Returns false for invalid regex patterns - treated as non-matching rather than error
          return false;
        }
      }
      return false;
    }
    case 'starts_with':
      return typeof fieldValue === 'string' && typeof value === 'string' && fieldValue.startsWith(value);
    case 'ends_with':
      return typeof fieldValue === 'string' && typeof value === 'string' && fieldValue.endsWith(value);
    default:
      return false;
  }
}

/**
 * Resolve a dotted field path against a context object.
 * e.g. "user.role" resolves context.user.role
 */
function resolveField(context: EvaluationContext, field: string): unknown {
  const parts = field.split('.');
  let current: unknown = context;

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

/**
 * Evaluate a CCL document against an action/resource pair.
 *
 * This is the core access-control decision function. It finds all
 * matching permit/deny statements, resolves conflicts using specificity
 * and deny-wins semantics, and returns a detailed result.
 *
 * Resolution order:
 * 1. Find all matching statements (action + resource match, conditions pass)
 * 2. Sort by specificity (most specific first)
 * 3. At equal specificity, deny wins over permit
 * 4. If no rules match, default is deny (`permitted: false`)
 *
 * @param doc - The parsed CCL document to evaluate against.
 * @param action - The action being attempted (e.g. `"read"`, `"api.call"`).
 * @param resource - The target resource path (e.g. `"/data/users"`).
 * @param context - Optional context for condition evaluation (e.g. `{ user: { role: 'admin' } }`).
 * @returns An EvaluationResult with `permitted`, `matchedRule`, and `allMatches`.
 *
 * @example
 * ```typescript
 * const doc = parse("permit read on '/data/**'\ndeny read on '/data/secret'");
 * const result = evaluate(doc, 'read', '/data/public');
 * console.log(result.permitted); // true
 * ```
 */
export function evaluate(
  doc: CCLDocument,
  action: string,
  resource: string,
  context?: EvaluationContext,
): EvaluationResult {
  const ctx = context ?? {};
  const allMatches: Statement[] = [];

  // Collect all matching permit/deny statements
  const matchedPermitDeny: PermitDenyStatement[] = [];

  for (const stmt of doc.permits) {
    if (matchAction(stmt.action, action) && matchResource(stmt.resource, resource)) {
      if (!stmt.condition || evaluateCondition(stmt.condition, ctx)) {
        matchedPermitDeny.push(stmt);
        allMatches.push(stmt);
      }
    }
  }

  for (const stmt of doc.denies) {
    if (matchAction(stmt.action, action) && matchResource(stmt.resource, resource)) {
      if (!stmt.condition || evaluateCondition(stmt.condition, ctx)) {
        matchedPermitDeny.push(stmt);
        allMatches.push(stmt);
      }
    }
  }

  // Also collect matching obligations (they don't affect permit/deny but are returned)
  for (const stmt of doc.obligations) {
    if (matchAction(stmt.action, action) && matchResource(stmt.resource, resource)) {
      if (!stmt.condition || evaluateCondition(stmt.condition, ctx)) {
        allMatches.push(stmt);
      }
    }
  }

  // No matching permit/deny rules: default deny
  if (matchedPermitDeny.length === 0) {
    return {
      permitted: false,
      allMatches,
      reason: 'No matching rules found; default deny',
    };
  }

  // Sort by specificity descending; at equal specificity, denies come first
  matchedPermitDeny.sort((a, b) => {
    const specA = specificity(a.action, a.resource);
    const specB = specificity(b.action, b.resource);

    if (specB !== specA) {
      return specB - specA; // higher specificity first
    }

    // At equal specificity, deny wins (comes first)
    if (a.type === 'deny' && b.type !== 'deny') return -1;
    if (a.type !== 'deny' && b.type === 'deny') return 1;
    return 0;
  });

  const winner = matchedPermitDeny[0]!;
  const permitted = winner.type === 'permit';

  return {
    permitted,
    matchedRule: winner,
    allMatches,
    reason: `Matched ${winner.type} rule for ${winner.action} on ${winner.resource}`,
    severity: winner.severity,
  };
}

/**
 * Check whether an action has exceeded its rate limit.
 *
 * Finds the most specific matching `limit` statement for the given action,
 * then checks whether `currentCount` exceeds the allowed count within
 * the time window starting at `periodStartTime`.
 *
 * @param doc - The parsed CCL document containing limit statements.
 * @param action - The action to check (e.g. `"api.call"`).
 * @param currentCount - How many times the action has been performed in the current window.
 * @param periodStartTime - Epoch milliseconds when the current window started.
 * @param now - Optional current time in epoch ms (defaults to `Date.now()`).
 * @returns An object with `exceeded`, the matched `limit`, and `remaining` count.
 *
 * @example
 * ```typescript
 * const doc = parse("limit api.call 100 per 1 hours");
 * const result = checkRateLimit(doc, 'api.call', 50, Date.now() - 1000);
 * console.log(result.remaining); // 50
 * ```
 */
export function checkRateLimit(
  doc: CCLDocument,
  action: string,
  currentCount: number,
  periodStartTime: number,
  now?: number,
): { exceeded: boolean; limit?: LimitStatement; remaining: number } {
  const currentTime = now ?? Date.now();

  // Find the most specific matching limit
  let matchedLimit: LimitStatement | undefined;
  let bestSpecificity = -1;

  for (const limit of doc.limits) {
    if (matchAction(limit.action, action)) {
      const spec = specificity(limit.action, '');
      if (spec > bestSpecificity) {
        bestSpecificity = spec;
        matchedLimit = limit;
      }
    }
  }

  if (!matchedLimit) {
    return { exceeded: false, remaining: Infinity };
  }

  // Check if we're still within the time window
  const periodMs = matchedLimit.periodSeconds * 1000;
  const elapsed = currentTime - periodStartTime;

  if (elapsed > periodMs) {
    // Period has expired; the count resets
    return {
      exceeded: false,
      limit: matchedLimit,
      remaining: matchedLimit.count,
    };
  }

  const remaining = Math.max(0, matchedLimit.count - currentCount);
  return {
    exceeded: currentCount >= matchedLimit.count,
    limit: matchedLimit,
    remaining,
  };
}

/**
 * Merge a parent and child CCL document with deny-wins semantics.
 *
 * Combines rules from both documents following delegation chain merge rules:
 * - All denies from both parent and child are included
 * - All permits from both are included (evaluate resolves conflicts)
 * - All obligations from both are included
 * - For limits on the same action, the more restrictive (lower count) wins
 *
 * @param parent - The parent (broader) CCL document.
 * @param child - The child (narrower) CCL document.
 * @returns A new merged CCLDocument.
 *
 * @example
 * ```typescript
 * const parent = parse("permit read on '**'");
 * const child = parse("deny read on '/secret/**'");
 * const merged = merge(parent, child);
 * console.log(merged.denies.length); // 1
 * ```
 */
export function merge(parent: CCLDocument, child: CCLDocument): CCLDocument {
  const statements: Statement[] = [];

  // All denies from both parent and child are included
  statements.push(...parent.denies);
  statements.push(...child.denies);

  // Permits: child permits are only included if they don't conflict with parent denies
  for (const permit of child.permits) {
    statements.push(permit);
  }
  for (const permit of parent.permits) {
    statements.push(permit);
  }

  // All obligations from both
  statements.push(...parent.obligations);
  statements.push(...child.obligations);

  // All limits: take the more restrictive limit if both specify for same action
  const limitsByAction = new Map<string, LimitStatement>();

  for (const limit of parent.limits) {
    const existing = limitsByAction.get(limit.action);
    if (!existing || limit.count < existing.count) {
      limitsByAction.set(limit.action, limit);
    }
  }

  for (const limit of child.limits) {
    const existing = limitsByAction.get(limit.action);
    if (!existing || limit.count < existing.count) {
      limitsByAction.set(limit.action, limit);
    }
  }

  statements.push(...limitsByAction.values());

  return buildDocumentFromStatements(statements);
}

/**
 * Validate that a child CCL document only narrows (restricts) the parent.
 *
 * A valid delegation chain requires that each child can only make
 * constraints more restrictive, never broader. Violations occur when:
 * - A child permits something the parent explicitly denies
 * - A child permit covers a broader scope than any parent permit
 *
 * @param parent - The parent CCL document.
 * @param child - The child CCL document to validate against the parent.
 * @returns An object with `valid` boolean and `violations` array.
 *
 * @example
 * ```typescript
 * const parent = parse("permit read on '/data/**'");
 * const child = parse("permit write on '/data/**'");
 * const result = validateNarrowing(parent, child);
 * console.log(result.valid); // false -- child broadens parent
 * ```
 */
export function validateNarrowing(
  parent: CCLDocument,
  child: CCLDocument,
): { valid: boolean; violations: NarrowingViolation[] } {
  const violations: NarrowingViolation[] = [];

  // Check each child permit against parent denies
  for (const childPermit of child.permits) {
    for (const parentDeny of parent.denies) {
      // If the child permits something the parent denies, that's a violation
      if (
        patternsOverlap(childPermit.action, parentDeny.action) &&
        patternsOverlap(childPermit.resource, parentDeny.resource)
      ) {
        violations.push({
          childRule: childPermit,
          parentRule: parentDeny,
          reason: `Child permits '${childPermit.action}' on '${childPermit.resource}' which parent denies`,
        });
      }
    }

    // Check if child permit is broader than any parent permit
    let hasMatchingParentPermit = false;
    for (const parentPermit of parent.permits) {
      if (
        isSubsetPattern(childPermit.action, parentPermit.action, '.') &&
        isSubsetPattern(childPermit.resource, parentPermit.resource, '/')
      ) {
        hasMatchingParentPermit = true;
        break;
      }
    }

    // If the parent has permits and the child permit doesn't fit within any, flag it
    if (parent.permits.length > 0 && !hasMatchingParentPermit) {
      // Find the closest parent permit for the violation report
      const closestParent = parent.permits[0]!;
      violations.push({
        childRule: childPermit,
        parentRule: closestParent,
        reason: `Child permit '${childPermit.action}' on '${childPermit.resource}' is not a subset of any parent permit`,
      });
    }
  }

  return {
    valid: violations.length === 0,
    violations,
  };
}

/**
 * Check if two patterns can match any of the same strings.
 *
 * Uses a heuristic approach: converts each pattern to a concrete representative
 * string (replacing wildcards with `"x"`) and checks whether the other pattern
 * can match that concrete string. Universal wildcards (`*`, `**`) always overlap.
 *
 * @param pattern1 - First pattern (action or resource).
 * @param pattern2 - Second pattern (action or resource).
 * @returns `true` if the two patterns could match at least one common string.
 */
function patternsOverlap(pattern1: string, pattern2: string): boolean {
  // If either is a universal wildcard, they overlap
  if (pattern1 === '**' || pattern2 === '**') return true;
  if (pattern1 === '*' || pattern2 === '*') return true;

  // If they're identical, they overlap
  if (pattern1 === pattern2) return true;

  // Check if one can match something the other matches
  // Simple heuristic: check if pattern1 matches pattern2 or vice versa
  // We use a representative concrete string derived from each pattern
  const concrete1 = patternToConcrete(pattern1);
  const concrete2 = patternToConcrete(pattern2);

  const sep1 = pattern1.includes('/') ? '/' : '.';
  const sep2 = pattern2.includes('/') ? '/' : '.';
  const matchFn = sep1 === '/' ? matchResource : matchAction;
  const matchFn2 = sep2 === '/' ? matchResource : matchAction;

  return matchFn(pattern1, concrete2) || matchFn2(pattern2, concrete1);
}

/**
 * Convert a wildcard pattern to a concrete representative string by
 * replacing all `**` and `*` with the literal `"x"`. Used by
 * {@link patternsOverlap} for heuristic overlap detection.
 *
 * @param pattern - A wildcard pattern (action or resource).
 * @returns A concrete string with wildcards replaced by `"x"`.
 */
function patternToConcrete(pattern: string): string {
  return pattern
    .replace(/\*\*/g, 'x')
    .replace(/\*/g, 'x');
}

/**
 * Check if `childPattern` is a subset of (at most as broad as) `parentPattern`.
 *
 * A pattern A is a subset of pattern B if every concrete string matched by A
 * is also matched by B. Used by {@link validateNarrowing} to ensure a child
 * covenant never permits a broader scope than its parent.
 *
 * @param childPattern  - The child pattern to test.
 * @param parentPattern - The parent pattern that should be at least as broad.
 * @param separator     - Segment separator (`"."` for actions, `"/"` for resources).
 * @returns `true` if every string matched by `childPattern` is also matched by `parentPattern`.
 */
function isSubsetPattern(childPattern: string, parentPattern: string, separator: string): boolean {
  // If parent is **, it matches everything, so child is always a subset
  if (parentPattern === '**') return true;

  // If child is ** but parent is not, child is broader
  if (childPattern === '**' && parentPattern !== '**') return false;

  const childParts = childPattern.split(separator).filter((p) => p.length > 0);
  const parentParts = parentPattern.split(separator).filter((p) => p.length > 0);

  // Check that child is at least as specific as parent
  return isSubsetSegments(childParts, 0, parentParts, 0);
}

function isSubsetSegments(
  child: string[],
  ci: number,
  parent: string[],
  pi: number,
): boolean {
  // Both exhausted: child is subset
  if (ci === child.length && pi === parent.length) return true;

  // Parent exhausted but child has more: child could match longer strings not matched by parent
  if (pi === parent.length) return false;

  // Child exhausted but parent has more
  if (ci === child.length) {
    // Only ok if remaining parent segments are all **
    for (let i = pi; i < parent.length; i++) {
      if (parent[i] !== '**') return false;
    }
    return true;
  }

  const pSeg = parent[pi]!;
  const cSeg = child[ci]!;

  if (pSeg === '**') {
    // Parent ** matches anything, try all possibilities
    // Skip the ** (match zero segments)
    if (isSubsetSegments(child, ci, parent, pi + 1)) return true;
    // Consume one child segment with the **
    return isSubsetSegments(child, ci + 1, parent, pi);
  }

  if (cSeg === '**') {
    // Child uses ** which is very broad. Parent must also use ** or something equally broad
    if (pSeg !== '**') return false;
    return isSubsetSegments(child, ci + 1, parent, pi + 1);
  }

  if (pSeg === '*') {
    // Parent * matches one segment. Child must also be * or a literal (which is narrower)
    return isSubsetSegments(child, ci + 1, parent, pi + 1);
  }

  if (cSeg === '*') {
    // Child * is broader than a literal parent - not a subset
    if (pSeg !== '*' && pSeg !== '**') return false;
    return isSubsetSegments(child, ci + 1, parent, pi + 1);
  }

  // Both literals: must match exactly
  if (cSeg !== pSeg) return false;
  return isSubsetSegments(child, ci + 1, parent, pi + 1);
}

/**
 * Serialize a CCLDocument back to human-readable CCL source text.
 *
 * Produces one line per statement. Time periods are converted to
 * the most natural unit (seconds, minutes, hours, days).
 * Conditions and severity annotations are included when present.
 *
 * @param doc - The CCL document to serialize.
 * @returns A multi-line CCL source string.
 *
 * @example
 * ```typescript
 * const doc = parse("permit read on '/data/**'");
 * const source = serialize(doc);
 * console.log(source); // "permit read on '/data/**'"
 * ```
 */
export function serialize(doc: CCLDocument): string {
  const lines: string[] = [];

  for (const stmt of doc.statements) {
    lines.push(serializeStatement(stmt));
  }

  return lines.join('\n');
}

function serializeStatement(stmt: Statement): string {
  switch (stmt.type) {
    case 'permit':
    case 'deny':
      return serializePermitDeny(stmt);
    case 'require':
      return serializeRequire(stmt);
    case 'limit':
      return serializeLimit(stmt);
  }
}

function serializePermitDeny(stmt: PermitDenyStatement): string {
  let line = `${stmt.type} ${stmt.action} on '${stmt.resource}'`;
  if (stmt.condition) {
    line += ` when ${serializeCondition(stmt.condition)}`;
  }
  if (stmt.severity !== 'high') {
    line += ` severity ${stmt.severity}`;
  }
  return line;
}

function serializeRequire(stmt: RequireStatement): string {
  let line = `require ${stmt.action} on '${stmt.resource}'`;
  if (stmt.condition) {
    line += ` when ${serializeCondition(stmt.condition)}`;
  }
  if (stmt.severity !== 'high') {
    line += ` severity ${stmt.severity}`;
  }
  return line;
}

function bestTimeUnit(seconds: number): { value: number; unit: string } {
  if (seconds % 86400 === 0 && seconds >= 86400) {
    return { value: seconds / 86400, unit: 'days' };
  }
  if (seconds % 3600 === 0 && seconds >= 3600) {
    return { value: seconds / 3600, unit: 'hours' };
  }
  if (seconds % 60 === 0 && seconds >= 60) {
    return { value: seconds / 60, unit: 'minutes' };
  }
  return { value: seconds, unit: 'seconds' };
}

function serializeLimit(stmt: LimitStatement): string {
  const { value, unit } = bestTimeUnit(stmt.periodSeconds);
  let line = `limit ${stmt.action} ${stmt.count} per ${value} ${unit}`;
  if (stmt.severity !== 'high') {
    line += ` severity ${stmt.severity}`;
  }
  return line;
}

function serializeCondition(cond: Condition | CompoundCondition): string {
  if (isCompoundCondition(cond)) {
    return serializeCompoundCondition(cond);
  }
  return serializeSimpleCondition(cond);
}

function serializeCompoundCondition(cond: CompoundCondition): string {
  if (cond.type === 'not') {
    return `not ${serializeCondition(cond.conditions[0]!)}`;
  }

  const parts = cond.conditions.map((c) => {
    // Wrap nested compound conditions in parens for clarity
    if (isCompoundCondition(c) && c.type !== cond.type) {
      return `(${serializeCondition(c)})`;
    }
    return serializeCondition(c);
  });

  return parts.join(` ${cond.type} `);
}

function serializeSimpleCondition(cond: Condition): string {
  const valueStr = serializeValue(cond.value);
  return `${cond.field} ${cond.operator} ${valueStr}`;
}

function serializeValue(value: string | number | boolean | string[]): string {
  if (Array.isArray(value)) {
    const items = value.map((v) => `'${v}'`);
    return `[${items.join(', ')}]`;
  }
  if (typeof value === 'string') {
    return `'${value}'`;
  }
  return String(value);
}

function isCompoundCondition(c: Condition | CompoundCondition): c is CompoundCondition {
  return 'type' in c && (c.type === 'and' || c.type === 'or' || c.type === 'not');
}

function buildDocumentFromStatements(statements: Statement[]): CCLDocument {
  const permits: PermitDenyStatement[] = [];
  const denies: PermitDenyStatement[] = [];
  const obligations: RequireStatement[] = [];
  const limits: LimitStatement[] = [];

  for (const stmt of statements) {
    switch (stmt.type) {
      case 'permit':
        permits.push(stmt);
        break;
      case 'deny':
        denies.push(stmt);
        break;
      case 'require':
        obligations.push(stmt);
        break;
      case 'limit':
        limits.push(stmt);
        break;
    }
  }

  return { statements, permits, denies, obligations, limits };
}
