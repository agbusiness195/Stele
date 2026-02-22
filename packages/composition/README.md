# @nobulex/composition

Covenant composition with merge, intersect, conflict detection, and complexity analysis. Composes multiple covenants into a single proof with deny-wins semantics.

## Installation

```bash
npm install @nobulex/composition
```

## Key APIs

- **compose(covenants)**: Merge multiple `CovenantSummary` objects into a `CompositionProof` with deny-wins filtering
- **validateComposition(proof)**: Verify hash integrity, CCL validity, and deny-wins consistency of a proof
- **proveSystemProperty(covenants, property)**: Test whether a safety property holds across composed covenants
- **intersectConstraints(a, b)**: Return constraints present in both arrays
- **findConflicts(covenants)**: Find permit/deny pairs whose action/resource patterns overlap
- **decomposeCovenants(covenants)**: Break compound covenants into atomic single-constraint sub-covenants
- **compositionComplexity(covenants)**: Measure weighted complexity (rules, condition depth, conflicts, distinct patterns)

## Usage

```typescript
import {
  compose,
  validateComposition,
  findConflicts,
  compositionComplexity,
} from '@nobulex/composition';

const covenants = [
  { id: 'c1', agentId: 'agent-a', constraints: ['permit read /data/**'] },
  { id: 'c2', agentId: 'agent-b', constraints: ['deny delete /data/critical'] },
];

// Compose with deny-wins semantics
const proof = compose(covenants);
console.log(proof.composedConstraints);

// Validate the composition proof
const valid = validateComposition(proof);

// Detect conflicts
const conflicts = findConflicts(covenants);

// Measure complexity
const complexity = compositionComplexity(covenants);
console.log(`Score: ${complexity.score}`);
```

## Types

- `CompositionProof` -- Agents, individual covenants, composed constraints, system properties, and integrity hash
- `ComposedConstraint` -- A single constraint with its source covenant and type
- `SystemProperty` -- Whether a named property holds, and which covenants it derives from
- `CovenantSummary` -- Input format: `{ id, agentId, constraints: string[] }`
- `DecomposedCovenant` -- Atomic constraint with source covenant ID, agent ID, and type
- `CompositionComplexityResult` -- Metrics including totalRules, maxConditionDepth, conflictCount, and score

## Docs

See the [Nobulex SDK root documentation](../../README.md) for the full API reference.
