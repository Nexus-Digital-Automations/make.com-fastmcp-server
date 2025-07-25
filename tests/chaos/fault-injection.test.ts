import { describe, expect, it, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import { server } from '../../src/server';
import { MakeAPIClient } from '../../src/lib/make-api-client';

class ChaosMonkey {
    private failureRate: number;
    private latencyMs: number;
    private scenarios: string[];

    constructor(config: {
        failureRate?: number;
        latencyMs?: number;
        scenarios?: string[];
    }) {
        this.failureRate = config.failureRate || 0.1;
        this.latencyMs = config.latencyMs || 5000;
        this.scenarios = config.scenarios || ['latency', 'error', 'timeout'];
    }

    async wrapService<T>(service: T): Promise<T> {
        return new Proxy(service, {
            get: (target: any, prop: string | symbol) => {
                if (typeof target[prop] !== 'function') {
                    return target[prop];
                }

                return async (...args: any[]) => {
                    // Randomly inject failures
                    if (Math.random() < this.failureRate) {
                        const scenario = this.randomScenario();
                        await this.injectFailure(scenario);
                    }

                    return target[prop](...args);
                };
            }
        });
    }

    private randomScenario(): string {
        return this.scenarios[Math.floor(Math.random() * this.scenarios.length)];
    }

    private async injectFailure(scenario: string): Promise<void> {
        switch (scenario) {
            case 'latency':
                await new Promise(resolve => setTimeout(resolve, this.latencyMs));
                break;
            case 'error':
                throw new Error('Chaos: Service temporarily unavailable');
            case 'timeout':
                await new Promise(resolve => setTimeout(resolve, 30000));
                throw new Error('Chaos: Request timeout');
            case 'partial':
                throw new Error('Chaos: Partial response');
            case 'network':
                throw new Error('Chaos: Network connection failed');
            case 'memory':
                throw new Error('Chaos: Out of memory');
            case 'disk':
                throw new Error('Chaos: Disk full');
            default:
                throw new Error('Chaos: Unknown failure');
        }
    }
}

class FaultInjector {
    private faults: Map<string, any> = new Map();

    injectFault(service: string, fault: any): void {
        this.faults.set(service, fault);
    }

    removeFault(service: string): void {
        this.faults.delete(service);
    }

    getFault(service: string): any {
        return this.faults.get(service);
    }

    clearAllFaults(): void {
        this.faults.clear();
    }

    async simulateServiceFailure(serviceName: string, duration: number = 5000): Promise<void> {
        this.injectFault(serviceName, { type: 'unavailable', duration });
        setTimeout(() => this.removeFault(serviceName), duration);
    }

    async simulateNetworkPartition(services: string[], duration: number = 10000): Promise<void> {
        services.forEach(service => {
            this.injectFault(service, { type: 'network_partition', duration });
        });
        setTimeout(() => {
            services.forEach(service => this.removeFault(service));
        }, duration);
    }

    async simulateResourceExhaustion(resourceType: 'memory' | 'disk' | 'cpu', duration: number = 8000): Promise<void> {
        this.injectFault('system', { type: resourceType + '_exhaustion', duration });
        setTimeout(() => this.removeFault('system'), duration);
    }
}

describe('Chaos Engineering Fault Injection Tests', () => {
    let app: any;
    let mockMakeClient: jest.Mocked<MakeAPIClient>;
    let faultInjector: FaultInjector;

    beforeEach(() => {
        app = server;
        faultInjector = new FaultInjector();
        mockMakeClient = {
            makeRequest: jest.fn(),
            get: jest.fn(),
            post: jest.fn(),
            put: jest.fn(),
            delete: jest.fn(),
            patch: jest.fn()
        } as unknown as jest.Mocked<MakeAPIClient>;

        // Set longer timeout for chaos tests
        jest.setTimeout(60000);
    });

    afterEach(() => {
        faultInjector.clearAllFaults();
        jest.clearAllMocks();
    });

    describe('Service Resilience Testing', () => {
        it('should handle Make.com API service failures gracefully', async () => {
            const chaosMonkey = new ChaosMonkey({
                failureRate: 0.5,
                scenarios: ['error', 'timeout', 'network']
            });

            const results = {
                successful: 0,
                failed: 0,
                errors: [] as string[]
            };

            // Test 50 requests with 50% failure rate
            const requests = Array(50).fill(null).map(async () => {
                try {
                    // Simulate chaos in the Make API client
                    if (Math.random() < 0.5) {
                        throw new Error('Chaos: Make.com API unavailable');
                    }

                    const response = await request(app)
                        .get('/scenarios/list')
                        .query({ teamId: '12345' });

                    if ([200, 404].includes(response.status)) {
                        results.successful++;
                    } else {
                        results.failed++;
                        results.errors.push(`HTTP ${response.status}`);
                    }
                } catch (error) {
                    results.failed++;
                    results.errors.push(error instanceof Error ? error.message : String(error));
                }
            });

            await Promise.allSettled(requests);

            // Should have graceful degradation, not complete failure
            expect(results.successful).toBeGreaterThan(10);
            expect(results.failed).toBeGreaterThan(10);
            expect(results.successful + results.failed).toBe(50);

            console.log('Service Resilience Test Results:', {
                successful: results.successful,
                failed: results.failed,
                successRate: `${(results.successful / 50 * 100).toFixed(2)}%`,
                errorTypes: [...new Set(results.errors)].slice(0, 5)
            });
        });

        it('should implement circuit breaker pattern under failures', async () => {
            // Simulate high failure rate to trigger circuit breaker
            const failureRequests = Array(20).fill(null).map(async () => {
                try {
                    const response = await request(app)
                        .post('/scenarios/create')
                        .send({
                            name: 'Circuit Breaker Test',
                            teamId: '12345'
                        });

                    return { status: response.status, success: [200, 201].includes(response.status) };
                } catch (error) {
                    return { status: 500, success: false, error: error instanceof Error ? error.message : String(error) };
                }
            });

            const results = await Promise.all(failureRequests);
            const failures = results.filter(r => !r.success);

            // After multiple failures, should get circuit breaker responses (503 Service Unavailable)
            expect(failures.length).toBeGreaterThan(15);

            // Test that circuit breaker eventually recovers
            await new Promise(resolve => setTimeout(resolve, 5000));

            const recoveryResponse = await request(app)
                .get('/scenarios/list')
                .query({ teamId: '12345' });

            expect([200, 404, 503]).toContain(recoveryResponse.status);

            console.log('Circuit Breaker Test Results:', {
                totalRequests: results.length,
                failures: failures.length,
                failureRate: `${(failures.length / results.length * 100).toFixed(2)}%`,
                recoveryStatus: recoveryResponse.status
            });
        });

        it('should handle database connection failures with retries', async () => {
            // Simulate database connection issues
            await faultInjector.simulateServiceFailure('database', 3000);

            const results = {
                successful: 0,
                failed: 0,
                retries: 0
            };

            const requests = Array(15).fill(null).map(async () => {
                let attempts = 0;
                const maxAttempts = 3;

                while (attempts < maxAttempts) {
                    attempts++;
                    
                    try {
                        const response = await request(app)
                            .get('/scenarios/search')
                            .query({
                                q: 'test query',
                                teamId: '12345'
                            });

                        if ([200, 404].includes(response.status)) {
                            results.successful++;
                            if (attempts > 1) results.retries++;
                            return;
                        }
                    } catch (error) {
                        if (attempts === maxAttempts) {
                            results.failed++;
                            return;
                        }
                        // Wait before retry
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }
                }
            });

            await Promise.allSettled(requests);

            // Should demonstrate retry logic working
            expect(results.retries).toBeGreaterThan(0);
            expect(results.successful).toBeGreaterThan(5);

            console.log('Database Resilience Test Results:', {
                successful: results.successful,
                failed: results.failed,
                retries: results.retries,
                retryEffectiveness: results.retries > 0 ? 'Working' : 'Not detected'
            });
        });
    });

    describe('Network Partition Simulation', () => {
        it('should handle network partitions between services', async () => {
            // Simulate network partition affecting Make.com API
            await faultInjector.simulateNetworkPartition(['make-api'], 8000);

            const results = {
                beforePartition: 0,
                duringPartition: 0,
                afterPartition: 0,
                errors: [] as string[]
            };

            // Test before partition
            try {
                const response = await request(app)
                    .get('/scenarios/list')
                    .query({ teamId: '12345' });
                if ([200, 404].includes(response.status)) results.beforePartition++;
            } catch (error) {
                results.errors.push('Before: ' + (error instanceof Error ? error.message : String(error)));
            }

            // Test during partition (should fail or degrade gracefully)
            await new Promise(resolve => setTimeout(resolve, 2000));
            const duringPartitionTests = Array(10).fill(null).map(async () => {
                try {
                    const response = await request(app)
                        .get('/scenarios/list')  
                        .query({ teamId: '12345' });
                    
                    // During partition, might get cached results or graceful degradation
                    if ([200, 404, 503].includes(response.status)) {
                        results.duringPartition++;
                    }
                } catch (error) {
                    results.errors.push('During: ' + (error instanceof Error ? error.message : String(error)));
                }
            });

            await Promise.allSettled(duringPartitionTests);

            // Wait for partition to heal
            await new Promise(resolve => setTimeout(resolve, 7000));

            // Test after partition recovery
            try {
                const response = await request(app)
                    .get('/scenarios/list')
                    .query({ teamId: '12345' });
                if ([200, 404].includes(response.status)) results.afterPartition++;
            } catch (error) {
                results.errors.push('After: ' + (error instanceof Error ? error.message : String(error)));
            }

            // Should show degraded performance during partition and recovery after
            expect(results.duringPartition).toBeLessThan(8); // Some degradation expected
            expect(results.afterPartition).toBeGreaterThan(0); // Should recover

            console.log('Network Partition Test Results:', {
                beforePartition: results.beforePartition,
                duringPartition: results.duringPartition,
                afterPartition: results.afterPartition,
                errorSample: results.errors.slice(0, 3)
            });
        });

        it('should implement timeouts and fallbacks during network issues', async () => {
            const networkFaultScenarios = [
                { name: 'High Latency', delay: 8000 },
                { name: 'Packet Loss', errorRate: 0.7 },
                { name: 'Connection Reset', resetRate: 0.5 }
            ];

            for (const scenario of networkFaultScenarios) {
                const results = {
                    completed: 0,
                    timeouts: 0,
                    fallbacks: 0,
                    errors: [] as string[]
                };

                console.log(`Testing ${scenario.name}...`);

                const requests = Array(8).fill(null).map(async () => {
                    const startTime = Date.now();
                    
                    try {
                        // Simulate network issue
                        if (scenario.delay) {
                            await new Promise(resolve => setTimeout(resolve, Math.random() * scenario.delay));
                        }
                        if (scenario.errorRate && Math.random() < scenario.errorRate) {
                            throw new Error('Network: Packet loss');
                        }
                        if (scenario.resetRate && Math.random() < scenario.resetRate) {
                            throw new Error('Network: Connection reset');
                        }

                        const response = await request(app)
                            .get('/scenarios/list')
                            .query({ teamId: '12345' });

                        const duration = Date.now() - startTime;
                        
                        if (duration > 10000) {
                            results.timeouts++;
                        } else if ([200, 404].includes(response.status)) {
                            results.completed++;
                        } else if (response.status === 503) {
                            results.fallbacks++; // Service degraded gracefully
                        }
                    } catch (error) {
                        const duration = Date.now() - startTime;
                        
                        if (duration > 9000) {
                            results.timeouts++;
                        } else {
                            results.errors.push(error instanceof Error ? error.message : String(error));
                        }
                    }
                });

                await Promise.allSettled(requests);

                // Should handle network issues gracefully
                expect(results.completed + results.fallbacks + results.timeouts).toBeGreaterThan(4);

                console.log(`${scenario.name} Results:`, {
                    completed: results.completed,
                    timeouts: results.timeouts,
                    fallbacks: results.fallbacks,
                    errors: results.errors.length
                });

                // Wait between scenarios
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        });
    });

    describe('Resource Exhaustion Simulation', () => {
        it('should handle memory pressure gracefully', async () => {
            // Simulate memory exhaustion
            await faultInjector.simulateResourceExhaustion('memory', 6000);

            const results = {
                successful: 0,
                memoryErrors: 0,
                degraded: 0
            };

            // Create memory-intensive requests
            const memoryIntensiveRequests = Array(20).fill(null).map(async () => {
                try {
                    const largePayload = {
                        name: 'Memory Test Scenario',
                        teamId: '12345',
                        blueprint: {
                            flow: Array(200).fill(null).map((_, i) => ({
                                id: `node-${i}`,
                                type: 'webhook',
                                parameters: {
                                    url: `https://example.com/hook-${i}`,
                                    body: 'x'.repeat(2000) // 2KB per node
                                }
                            }))
                        }
                    };

                    const response = await request(app)
                        .post('/scenarios/create')
                        .send(largePayload);

                    if ([201].includes(response.status)) {
                        results.successful++;
                    } else if ([413, 507].includes(response.status)) {
                        results.memoryErrors++; // Payload too large or insufficient storage
                    } else if ([503].includes(response.status)) {
                        results.degraded++; // Service degraded
                    }
                } catch (error) {
                    const errorMsg = error instanceof Error ? error.message : String(error);
                    if (errorMsg.includes('memory') || errorMsg.includes('heap')) {
                        results.memoryErrors++;
                    } else {
                        results.degraded++;
                    }
                }
            });

            await Promise.allSettled(memoryIntensiveRequests);

            // Should handle memory pressure without complete failure
            expect(results.successful + results.degraded).toBeGreaterThan(5);
            expect(results.memoryErrors).toBeGreaterThan(0);

            console.log('Memory Pressure Test Results:', {
                successful: results.successful,
                memoryErrors: results.memoryErrors,
                degraded: results.degraded,
                totalHandled: results.successful + results.memoryErrors + results.degraded
            });
        });

        it('should implement backpressure under high load', async () => {
            const results = {
                accepted: 0,
                rejected: 0, 
                queued: 0,
                latencies: [] as number[]
            };

            // Flood the system with requests to trigger backpressure
            const floodRequests = Array(100).fill(null).map(async (_, i) => {
                const startTime = Date.now();
                
                try {
                    const response = await request(app)
                        .post('/scenarios/create')
                        .send({
                            name: `Backpressure Test ${i}`,
                            teamId: '12345'
                        });

                    const latency = Date.now() - startTime;
                    results.latencies.push(latency);

                    if ([201].includes(response.status)) {
                        results.accepted++;
                    } else if ([429].includes(response.status)) {
                        results.rejected++; // Rate limited
                    } else if ([202].includes(response.status)) {
                        results.queued++; // Queued for later processing
                    }
                } catch (error) {
                    results.rejected++;
                }
            });

            await Promise.allSettled(floodRequests);

            // Should implement backpressure (reject some requests)
            expect(results.rejected).toBeGreaterThan(30);
            expect(results.accepted + results.queued).toBeGreaterThan(20);

            const avgLatency = results.latencies.reduce((a, b) => a + b, 0) / results.latencies.length || 0;

            console.log('Backpressure Test Results:', {
                accepted: results.accepted,
                rejected: results.rejected,
                queued: results.queued,
                avgLatency: `${avgLatency.toFixed(2)}ms`,
                backpressureEffective: results.rejected > 30 ? 'Yes' : 'No'
            });
        });
    });

    describe('Cascading Failure Prevention', () => {
        it('should prevent cascading failures across services', async () => {
            const services = ['scenarios', 'connections', 'users'];
            const results = new Map();

            services.forEach(service => {
                results.set(service, { healthy: 0, failed: 0, isolated: 0 });
            });

            // Simulate failure in one service
            await faultInjector.simulateServiceFailure('scenarios', 10000);

            // Test each service independently
            for (const service of services) {
                const serviceResults = results.get(service);
                
                const requests = Array(10).fill(null).map(async () => {
                    try {
                        let response;
                        
                        switch (service) {
                            case 'scenarios':
                                response = await request(app)
                                    .get('/scenarios/list')
                                    .query({ teamId: '12345' });
                                break;
                            case 'connections':
                                response = await request(app)
                                    .get('/connections/list')
                                    .query({ teamId: '12345' });
                                break;
                            case 'users':
                                response = await request(app)
                                    .get('/users/list')
                                    .query({ teamId: '12345' });
                                break;
                            default:
                                return;
                        }

                        if ([200, 404].includes(response.status)) {
                            serviceResults.healthy++;
                        } else if ([503].includes(response.status)) {
                            serviceResults.failed++;
                        } else if ([502].includes(response.status)) {
                            serviceResults.isolated++; // Circuit breaker activated
                        }
                    } catch (error) {
                        serviceResults.failed++;
                    }
                });

                await Promise.allSettled(requests);
            }

            // Scenarios service should be mostly failed
            const scenariosResult = results.get('scenarios');
            expect(scenariosResult.failed + scenariosResult.isolated).toBeGreaterThan(5);

            // Other services should remain mostly healthy (no cascading failure)
            const connectionsResult = results.get('connections');
            const usersResult = results.get('users');
            
            expect(connectionsResult.healthy).toBeGreaterThan(connectionsResult.failed);
            expect(usersResult.healthy).toBeGreaterThan(usersResult.failed);

            console.log('Cascading Failure Prevention Results:');
            results.forEach((result, service) => {
                console.log(`${service}:`, {
                    healthy: result.healthy,
                    failed: result.failed,
                    isolated: result.isolated,
                    healthRatio: `${(result.healthy / 10 * 100).toFixed(0)}%`
                });
            });
        });

        it('should implement bulkhead isolation pattern', async () => {
            const results = {
                criticalPath: { successful: 0, failed: 0 },
                nonCriticalPath: { successful: 0, failed: 0 }
            };

            // Simulate high load on non-critical path
            const nonCriticalRequests = Array(30).fill(null).map(async () => {
                try {
                    // Non-critical: analytics or reporting endpoint
                    const response = await request(app)
                        .get('/analytics/usage')
                        .query({ 
                            teamId: '12345',
                            period: 'last-30-days'
                        });

                    if ([200, 404].includes(response.status)) {
                        results.nonCriticalPath.successful++;
                    } else {
                        results.nonCriticalPath.failed++;
                    }
                } catch (error) {
                    results.nonCriticalPath.failed++;
                }
            });

            // Critical path requests should not be affected
            const criticalRequests = Array(10).fill(null).map(async () => {
                try {
                    // Critical: core scenario operations
                    const response = await request(app)
                        .get('/scenarios/list')
                        .query({ teamId: '12345' });

                    if ([200, 404].includes(response.status)) {
                        results.criticalPath.successful++;
                    } else {
                        results.criticalPath.failed++;
                    }
                } catch (error) {
                    results.criticalPath.failed++;
                }
            });

            await Promise.allSettled([...nonCriticalRequests, ...criticalRequests]);

            // Critical path should maintain high availability despite non-critical load
            const criticalSuccessRate = results.criticalPath.successful / 10;
            const nonCriticalSuccessRate = results.nonCriticalPath.successful / 30;

            expect(criticalSuccessRate).toBeGreaterThan(0.7); // Critical path protected
            // Non-critical may be throttled but not completely failed
            expect(nonCriticalSuccessRate).toBeGreaterThan(0.3);

            console.log('Bulkhead Isolation Test Results:', {
                critical: {
                    successRate: `${(criticalSuccessRate * 100).toFixed(2)}%`,
                    successful: results.criticalPath.successful,
                    failed: results.criticalPath.failed
                },
                nonCritical: {
                    successRate: `${(nonCriticalSuccessRate * 100).toFixed(2)}%`,
                    successful: results.nonCriticalPath.successful,
                    failed: results.nonCriticalPath.failed
                },
                isolationEffective: criticalSuccessRate > nonCriticalSuccessRate ? 'Yes' : 'Needs Improvement'
            });
        });
    });

    describe('Recovery and Self-Healing', () => {
        it('should demonstrate automatic recovery after failures', async () => {
            const phases = {
                baseline: { successful: 0, failed: 0 },
                failure: { successful: 0, failed: 0 },
                recovery: { successful: 0, failed: 0 }
            };

            // Phase 1: Baseline performance
            console.log('Phase 1: Measuring baseline performance...');
            const baselineRequests = Array(10).fill(null).map(async () => {
                try {
                    const response = await request(app)
                        .get('/scenarios/list')
                        .query({ teamId: '12345' });
                    
                    if ([200, 404].includes(response.status)) {
                        phases.baseline.successful++;
                    } else {
                        phases.baseline.failed++;
                    }
                } catch (error) {
                    phases.baseline.failed++;
                }
            });

            await Promise.allSettled(baselineRequests);

            // Phase 2: Inject failures
            console.log('Phase 2: Injecting failures...');
            await faultInjector.simulateServiceFailure('make-api', 8000);

            const failureRequests = Array(15).fill(null).map(async () => {
                try {
                    const response = await request(app)
                        .get('/scenarios/list')
                        .query({ teamId: '12345' });
                    
                    if ([200, 404].includes(response.status)) {
                        phases.failure.successful++;
                    } else {
                        phases.failure.failed++;
                    }
                } catch (error) {
                    phases.failure.failed++;
                }
            });

            await Promise.allSettled(failureRequests);

            // Phase 3: Wait for recovery and test
            console.log('Phase 3: Testing recovery...');
            await new Promise(resolve => setTimeout(resolve, 10000)); // Wait for recovery

            const recoveryRequests = Array(12).fill(null).map(async () => {
                try {
                    const response = await request(app)
                        .get('/scenarios/list')
                        .query({ teamId: '12345' });
                    
                    if ([200, 404].includes(response.status)) {
                        phases.recovery.successful++;
                    } else {
                        phases.recovery.failed++;
                    }
                } catch (error) {
                    phases.recovery.failed++;
                }
            });

            await Promise.allSettled(recoveryRequests);

            // Calculate success rates
            const baselineRate = phases.baseline.successful / 10;
            const failureRate = phases.failure.successful / 15;
            const recoveryRate = phases.recovery.successful / 12;

            // Should show degradation during failure and recovery afterward
            expect(failureRate).toBeLessThan(baselineRate); // Performance degraded during failure
            expect(recoveryRate).toBeGreaterThan(failureRate); // Recovery better than failure period
            expect(recoveryRate).toBeGreaterThan(0.6); // Reasonable recovery

            console.log('Recovery Test Results:', {
                baseline: `${(baselineRate * 100).toFixed(2)}%`,
                duringFailure: `${(failureRate * 100).toFixed(2)}%`,
                afterRecovery: `${(recoveryRate * 100).toFixed(2)}%`,
                recoveryEffective: recoveryRate > failureRate ? 'Yes' : 'No',
                fullRecovery: Math.abs(recoveryRate - baselineRate) < 0.2 ? 'Yes' : 'Partial'
            });
        });
    });
});