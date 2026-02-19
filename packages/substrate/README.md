# @usekova/substrate

Cross-substrate layer for translating and enforcing covenants across heterogeneous platforms: AI agents, robots, drones, IoT devices, autonomous vehicles, and smart contracts.

## Installation

```bash
npm install @usekova/substrate
```

## Key APIs

- **createAdapter(type, config)**: Create a `SubstrateAdapter` from a substrate type and capabilities/sensors/actuators configuration
- **physicalCovenant(substrate, constraints, safetyBounds?)**: Build a `UniversalCovenant` from physical constraints (force, speed, temperature, etc.)
- **translateCovenant(constraints, targetSubstrate)**: Translate abstract covenant constraints to a target substrate, merging with substrate-specific defaults
- **checkPhysicalConstraint(constraint, actualValue)**: Check if a value satisfies a physical constraint (`lt`, `gt`, `equals`, `between`)
- **checkSafetyBound(bound, actualValue)**: Check a value against hard/soft safety limits, returning whether to `halt`, `degrade`, or `alert`
- **substrateCompatibility(source, target)**: Assess compatibility between two substrates based on shared protocols, domain overlap, and capabilities
- **constraintTranslation(constraint, targetSubstrate)**: Translate a single CCL constraint into substrate-specific enforcement rules with mechanism and feasibility
- **substrateCapabilityMatrix(substrateTypes?)**: Generate a matrix of what each substrate type can enforce (rate limits, geofencing, hardware interlocks, etc.)
- **SUBSTRATE_DEFAULTS**: Default constraints and safety bounds per substrate type

## Usage

```typescript
import {
  createAdapter,
  physicalCovenant,
  checkSafetyBound,
  substrateCompatibility,
  constraintTranslation,
} from '@usekova/substrate';

// Create substrate adapters
const robot = createAdapter('robot', {
  capabilities: ['movement', 'manipulation'],
  sensors: ['lidar', 'force-torque'],
  actuators: ['arm', 'gripper'],
  attestation: 'tpm',
});

// Build a physical covenant with safety bounds
const covenant = physicalCovenant(robot, [
  { parameter: 'force', operator: 'lt', value: 100, unit: 'N' },
], [
  { property: 'force', hardLimit: 150, softLimit: 100, action: 'halt' },
]);

// Runtime safety check
const result = checkSafetyBound(
  { property: 'force', hardLimit: 150, softLimit: 100, action: 'halt' },
  120,
);
console.log(result.limitHit); // 'soft'
console.log(result.action);   // 'halt'

// Translate a constraint for a specific substrate
const translation = constraintTranslation("deny force on '**' when force_value > 100", 'robot');
console.log(translation.rules[0].mechanism); // 'hardware-interlock'

// Check substrate compatibility
const agent = createAdapter('ai-agent', {
  capabilities: ['movement'], sensors: [], actuators: [], attestation: 'software',
});
const compat = substrateCompatibility(agent, robot);
console.log(compat.compatible);           // true
console.log(compat.interactionProtocol);  // 'bridged'
```

## Supported Substrate Types

`ai-agent` | `robot` | `iot-device` | `autonomous-vehicle` | `smart-contract` | `drone`

## Types

- `SubstrateType`, `SubstrateAdapter`, `AdapterConfig`
- `UniversalCovenant`, `PhysicalConstraint`, `SafetyBound`, `SafetyBoundResult`
- `CompatibilityResult`, `ConstraintTranslationResult`, `EnforcementRule`
- `CapabilityMatrix`, `CapabilityMatrixRow`, `CapabilityEntry`

## Docs

See the [Stele SDK root documentation](../../README.md) for the full API reference.
