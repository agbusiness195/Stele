/**
 * OpenTelemetry-compatible instrumentation for the Kervyx SDK.
 *
 * Follows the "bring your own tracer" pattern: all OTel interfaces are
 * defined inline so consumers can plug in their own OTel SDK without
 * introducing any external dependency on `@opentelemetry/*` packages.
 *
 * @packageDocumentation
 */

import type { KervyxMiddleware, MiddlewareContext, MiddlewareResult } from './middleware.js';
import type {
  KervyxEventType,
  KervyxEventMap,
  KervyxEvent,
  CovenantCreatedEvent,
  CovenantVerifiedEvent,
  EvaluationCompletedEvent,
} from './types.js';

// ─── OTel-compatible interfaces ──────────────────────────────────────────────

/** Status code constants compatible with @opentelemetry/api SpanStatusCode. */
export const SpanStatusCode = {
  UNSET: 0,
  OK: 1,
  ERROR: 2,
} as const;

/** Minimal Span interface compatible with @opentelemetry/api. */
export interface Span {
  setAttribute(key: string, value: string | number | boolean): void;
  setStatus(status: { code: number; message?: string }): void;
  recordException(error: Error): void;
  end(): void;
}

/** Minimal Tracer interface compatible with @opentelemetry/api. */
export interface Tracer {
  startSpan(name: string, options?: { attributes?: Record<string, string | number | boolean> }): Span;
}

/** Minimal Counter interface compatible with @opentelemetry/api. */
export interface Counter {
  add(value: number, attributes?: Record<string, string>): void;
}

/** Minimal Histogram interface compatible with @opentelemetry/api. */
export interface Histogram {
  record(value: number, attributes?: Record<string, string>): void;
}

/** Minimal Meter interface compatible with @opentelemetry/api. */
export interface Meter {
  createCounter(name: string, options?: { description?: string }): Counter;
  createHistogram(name: string, options?: { description?: string }): Histogram;
}

// ─── No-op implementations ──────────────────────────────────────────────────

/** No-op Span that silently discards all calls. */
export class NoopSpan implements Span {
  setAttribute(_key: string, _value: string | number | boolean): void {}
  setStatus(_status: { code: number; message?: string }): void {}
  recordException(_error: Error): void {}
  end(): void {}
}

/** No-op Counter that silently discards all calls. */
export class NoopCounter implements Counter {
  add(_value: number, _attributes?: Record<string, string>): void {}
}

/** No-op Histogram that silently discards all calls. */
export class NoopHistogram implements Histogram {
  record(_value: number, _attributes?: Record<string, string>): void {}
}

/** No-op Tracer that returns NoopSpan instances. */
export class NoopTracer implements Tracer {
  startSpan(_name: string, _options?: { attributes?: Record<string, string | number | boolean> }): Span {
    return new NoopSpan();
  }
}

/** No-op Meter that returns NoopCounter and NoopHistogram instances. */
export class NoopMeter implements Meter {
  createCounter(_name: string, _options?: { description?: string }): Counter {
    return new NoopCounter();
  }
  createHistogram(_name: string, _options?: { description?: string }): Histogram {
    return new NoopHistogram();
  }
}

// ─── Telemetry middleware ────────────────────────────────────────────────────

/** Options for the telemetry middleware. */
export interface TelemetryMiddlewareOptions {
  /** Tracer instance for creating spans. Defaults to NoopTracer. */
  tracer?: Tracer;
}

/**
 * Create a KervyxMiddleware that wraps each operation with an OTel span.
 *
 * For every operation that passes through the middleware pipeline, this
 * middleware:
 * - Creates a span named after the operation (e.g. `kervyx.createCovenant`)
 * - Sets attributes: `kervyx.operation`, and any result-specific attributes
 *   such as `kervyx.covenant.id`, `kervyx.evaluation.permitted`
 * - Records duration via `kervyx.duration_ms`
 * - Sets the span status to OK or ERROR
 * - Records exceptions on failure
 *
 * @param options - Optional configuration with a custom tracer.
 * @returns A KervyxMiddleware instance.
 */
export function telemetryMiddleware(options?: TelemetryMiddlewareOptions): KervyxMiddleware {
  const tracer = options?.tracer ?? new NoopTracer();

  return {
    name: 'telemetry',

    async before(ctx: MiddlewareContext): Promise<MiddlewareResult> {
      const span = tracer.startSpan(`kervyx.${ctx.operation}`, {
        attributes: {
          'kervyx.operation': ctx.operation,
        },
      });
      ctx.metadata._telemetrySpan = span;
      ctx.metadata._telemetryStart = performance.now();
      return { proceed: true };
    },

    async after(ctx: MiddlewareContext, result: unknown): Promise<unknown> {
      const span = ctx.metadata._telemetrySpan as Span | undefined;
      if (span) {
        const start = ctx.metadata._telemetryStart as number;
        const durationMs = performance.now() - start;
        span.setAttribute('kervyx.duration_ms', durationMs);

        // Set result-specific attributes
        if (result && typeof result === 'object') {
          const r = result as Record<string, unknown>;
          if ('id' in r && typeof r.id === 'string') {
            span.setAttribute('kervyx.covenant.id', r.id);
          }
          if ('valid' in r && typeof r.valid === 'boolean') {
            span.setAttribute('kervyx.verification.valid', r.valid);
          }
          if ('permitted' in r && typeof r.permitted === 'boolean') {
            span.setAttribute('kervyx.evaluation.permitted', r.permitted);
          }
        }

        span.setStatus({ code: SpanStatusCode.OK });
        span.end();

        delete ctx.metadata._telemetrySpan;
        delete ctx.metadata._telemetryStart;
      }
      return result;
    },

    async onError(ctx: MiddlewareContext, error: Error): Promise<void> {
      const span = ctx.metadata._telemetrySpan as Span | undefined;
      if (span) {
        const start = ctx.metadata._telemetryStart as number;
        const durationMs = performance.now() - start;
        span.setAttribute('kervyx.duration_ms', durationMs);
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        span.recordException(error);
        span.end();

        delete ctx.metadata._telemetrySpan;
        delete ctx.metadata._telemetryStart;
      }
    },
  };
}

// ─── KervyxMetrics ───────────────────────────────────────────────────────────

/**
 * A minimal interface for an object that exposes `on()` for event subscription.
 *
 * This matches KervyxClient's public API without importing the class directly,
 * keeping the telemetry module loosely coupled.
 */
export interface EventSource {
  on<T extends KervyxEventType>(event: T, handler: (data: KervyxEventMap[T]) => void): () => void;
}

/**
 * Metrics collector for Kervyx SDK operations.
 *
 * Creates OTel-compatible counters and histograms and exposes a `record()`
 * method to update them from KervyxClient lifecycle events.
 */
export class KervyxMetrics {
  private readonly _covenantsCreated: Counter;
  private readonly _covenantsVerified: Counter;
  private readonly _evaluationsTotal: Counter;
  private readonly _evaluationsDenied: Counter;
  private readonly _operationDuration: Histogram;

  constructor(meter: Meter) {
    this._covenantsCreated = meter.createCounter('kervyx.covenants.created', {
      description: 'Number of covenants created',
    });
    this._covenantsVerified = meter.createCounter('kervyx.covenants.verified', {
      description: 'Number of covenants verified',
    });
    this._evaluationsTotal = meter.createCounter('kervyx.evaluations.total', {
      description: 'Total number of evaluations performed',
    });
    this._evaluationsDenied = meter.createCounter('kervyx.evaluations.denied', {
      description: 'Number of evaluations that were denied',
    });
    this._operationDuration = meter.createHistogram('kervyx.operation.duration', {
      description: 'Duration of operations in milliseconds',
    });
  }

  /**
   * Record a KervyxClient event, updating the appropriate metrics.
   *
   * @param event - A KervyxClient lifecycle event (from the `on()` callback).
   */
  record(event: KervyxEvent): void {
    switch (event.type) {
      case 'covenant:created':
        this._covenantsCreated.add(1);
        break;

      case 'covenant:verified':
        this._covenantsVerified.add(1);
        break;

      case 'evaluation:completed': {
        const evalEvent = event as EvaluationCompletedEvent;
        this._evaluationsTotal.add(1);
        if (!evalEvent.result.permitted) {
          this._evaluationsDenied.add(1);
        }
        break;
      }

      default:
        // Other event types are observed but do not drive specific counters.
        break;
    }
  }

  /**
   * Record an operation duration.
   *
   * @param durationMs - Duration in milliseconds.
   * @param attributes - Optional attributes to attach to the measurement.
   */
  recordDuration(durationMs: number, attributes?: Record<string, string>): void {
    this._operationDuration.record(durationMs, attributes);
  }

  /**
   * Subscribe to all KervyxClient events and automatically record metrics.
   *
   * @param client - An object with an `on()` method matching KervyxClient's API.
   * @returns An array of disposal functions that unsubscribe all listeners.
   */
  bindToClient(client: EventSource): (() => void)[] {
    const disposers: (() => void)[] = [];

    const eventTypes: KervyxEventType[] = [
      'covenant:created',
      'covenant:verified',
      'covenant:countersigned',
      'identity:created',
      'identity:evolved',
      'chain:resolved',
      'chain:validated',
      'evaluation:completed',
    ];

    for (const eventType of eventTypes) {
      const dispose = client.on(eventType, (data) => {
        this.record(data as KervyxEvent);
      });
      disposers.push(dispose);
    }

    return disposers;
  }
}

// ─── Factory ────────────────────────────────────────────────────────────────

/** Options for the `createTelemetry` factory. */
export interface CreateTelemetryOptions {
  /** Tracer for span creation. Defaults to NoopTracer. */
  tracer?: Tracer;
  /** Meter for metrics collection. Defaults to NoopMeter. */
  meter?: Meter;
}

/**
 * Create a matched pair of telemetry middleware and metrics collector.
 *
 * This is the recommended entry point for instrumenting the Kervyx SDK.
 * If no tracer or meter is provided, no-op implementations are used
 * so that application code compiles and runs without any OTel dependency.
 *
 * @param options - Optional tracer and meter instances.
 * @returns An object containing the middleware and metrics instances.
 *
 * @example
 * ```typescript
 * import { createTelemetry } from '@kervyx/sdk';
 *
 * // With real OTel SDK:
 * const { middleware, metrics } = createTelemetry({
 *   tracer: otelTrace.getTracer('my-app'),
 *   meter: otelMetrics.getMeter('my-app'),
 * });
 *
 * // Without OTel (no-op, zero overhead):
 * const { middleware, metrics } = createTelemetry();
 * ```
 */
export function createTelemetry(options?: CreateTelemetryOptions): {
  middleware: KervyxMiddleware;
  metrics: KervyxMetrics;
} {
  const tracer = options?.tracer ?? new NoopTracer();
  const meter = options?.meter ?? new NoopMeter();

  return {
    middleware: telemetryMiddleware({ tracer }),
    metrics: new KervyxMetrics(meter),
  };
}
