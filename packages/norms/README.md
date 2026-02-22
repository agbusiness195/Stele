# @nobulex/norms

Social norm modeling with emergence detection, conflict resolution, and governance proposal generation from covenant data.

## Installation

```bash
npm install @nobulex/norms
```

## Key APIs

- **analyzeNorms(covenants)**: Analyze covenant data to produce clusters, emergent norms, and coverage gaps
- **discoverNorms(analysis, minPrevalence, minCorrelation, covenants?)**: Find norms that correlate with high trust scores using Pearson correlation
- **proposeStandard(norm)**: Create a governance proposal from a discovered norm (includes parsed CCL representation)
- **generateTemplate(norms)**: Generate a merged covenant template from discovered norms with proper CCL serialization
- **normConflictDetection(norms)**: Detect direct contradictions, resource overlaps, and action conflicts between norm pairs
- **normPrecedence(normA, normB)**: Resolve conflicts using weighted specificity (0.4), recency (0.3), and authority (0.3) scoring

## Usage

```typescript
import { analyzeNorms, proposeStandard, normConflictDetection } from '@nobulex/norms';
import type { CovenantData } from '@nobulex/norms';

const covenants: CovenantData[] = [
  {
    agentId: 'agent-1',
    constraints: ['deny write on "/secrets/**"', 'permit read on "/public/**"'],
    trustScore: 0.9,
  },
  {
    agentId: 'agent-2',
    constraints: ['deny write on "/secrets/**"', 'require audit on "/admin/**"'],
    trustScore: 0.85,
  },
];

// Analyze norms across the covenant population
const analysis = analyzeNorms(covenants);
console.log(analysis.clusters);       // Grouped by CCL statement type
console.log(analysis.emergentNorms);  // High-prevalence, trust-correlated norms
console.log(analysis.gaps);           // Missing norm categories

// Propose emergent norms as standards
for (const norm of analysis.emergentNorms) {
  const proposal = proposeStandard(norm);
  console.log(proposal.description);
}
```

## Docs

See the [Nobulex SDK root documentation](../../README.md) for the full API reference.
