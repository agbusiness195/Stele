# @kervyx/react

Reactive primitives and React hooks for building Kervyx-powered UIs with observable state management.

## Installation

```bash
npm install @kervyx/react
```

## Key APIs

### Reactive Primitives (framework-agnostic)

- **Observable\<T\>**: Reactive value container with `get()`, `set()`, `subscribe()`, and `map()` for derived observables
- **CovenantState**: Observable state machine for the covenant lifecycle (create, verify, evaluate)
- **IdentityState**: Observable state machine for agent identity lifecycle (create, evolve)
- **StoreState**: Observable query layer over a `CovenantStore` with auto-refresh on store events

### Factory Functions

- **createCovenantState(client)**: Create a `CovenantState` bound to a `KervyxClient`
- **createIdentityState(client)**: Create an `IdentityState` bound to a `KervyxClient`
- **createStoreState(store)**: Create a `StoreState` bound to a `CovenantStore`

### React Hooks (requires React >= 18)

- **useObservable(observable)**: Subscribe to any `Observable<T>` and re-render on changes
- **useCovenant(client)**: Full covenant lifecycle hook (create, verify, evaluateAction)
- **useIdentity(client)**: Agent identity lifecycle hook (create, evolve)
- **useCovenantStore(store)**: Store query hook with filtering and auto-refresh

## Usage

```typescript
import { useCovenant, useIdentity, useCovenantStore } from '@kervyx/react';
import { KervyxClient } from '@kervyx/sdk';
import { MemoryStore } from '@kervyx/store';

function CovenantPanel() {
  const client = new KervyxClient();
  const { status, document, error, create, verify } = useCovenant(client);

  // status: 'idle' | 'creating' | 'created' | 'verifying' | 'verified' | 'error'
  return <div>Status: {status}</div>;
}

// Framework-agnostic usage
import { Observable, createCovenantState } from '@kervyx/react';

const count = new Observable(0);
const doubled = count.map(n => n * 2);
doubled.subscribe(v => console.log('doubled:', v));
count.set(5); // logs "doubled: 10"
```

## Docs

See the [Kervyx SDK root documentation](../../README.md) for the full API reference.
