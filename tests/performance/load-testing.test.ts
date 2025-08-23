import { describe, expect, it, beforeAll, afterAll, jest } from '@jest/globals';
import request from 'supertest';
import { server } from '../../src/server';
import { MakeAPIClient } from '../../src/lib/make-api-client';

class StressTest {
    private concurrent: number;
    private duration: number;
    private rampUp: number;

    constructor(config: { concurrent?: number; duration?: number; rampUp?: number }) {
        this.concurrent = config.concurrent || 100;
        this.duration = config.duration || 60000;
        this.rampUp = config.rampUp || 10000;
    }

    async run(testFunction: () => Promise<void>) {
        const results = {
            successful: 0,
            failed: 0,
            latencies: [] as number[],
            errors: [] as string[]
        };

        const startTime = Date.now();
        const workers: Promise<void>[] = [];

        // Ramp up workers gradually
        for (let i = 0; i < this.concurrent; i++) {
            await new Promise(resolve => 
                setTimeout(resolve, this.rampUp / this.concurrent)
            );
            
            workers.push(this.worker(testFunction, results, startTime));
        }

        await Promise.all(workers);

        return {
            ...results,
            avgLatency: results.latencies.reduce((a, b) => a + b, 0) / results.latencies.length || 0,
            p95Latency: this.percentile(results.latencies, 0.95),
            p99Latency: this.percentile(results.latencies, 0.99),
            successRate: results.successful / (results.successful + results.failed) || 0
        };
    }

    private async worker(testFunction: () => Promise<void>, results: any, startTime: number) {
        while (Date.now() - startTime < this.duration) {
            const start = Date.now();
            
            try {
                await testFunction();
                results.successful++;
                results.latencies.push(Date.now() - start);
            } catch (error) {
                results.failed++;
                results.errors.push(error instanceof Error ? error.message : String(error));
            }
            
            // Small delay to prevent overwhelming
            await new Promise(resolve => setTimeout(resolve, 10));
        }
    }

    private percentile(arr: number[], p: number): number {
        if (arr.length === 0) return 0;
        const sorted = arr.sort((a, b) => a - b);
        const index = Math.ceil(sorted.length * p) - 1;
        return sorted[index] || 0;
    }
}

describe('Performance Load Testing', () => {
    let app: any;
    let mockMakeClient: jest.Mocked<MakeAPIClient>;

    beforeAll(() => {
        app = server;
        mockMakeClient = {
            makeRequest: jest.fn(),
            get: jest.fn(),
            post: jest.fn(),
            put: jest.fn(),
            delete: jest.fn(),
            patch: jest.fn()
        } as unknown as jest.Mocked<MakeAPIClient>;

        // Set longer timeout for load tests
        jest.setTimeout(240000); // 4 minutes to accommodate long-running stress tests
    });

    afterAll(() => {
        jest.setTimeout(5000); // Reset to default
    });

    describe('Concurrent User Load Testing', () => {
        it('should handle 50 concurrent API authentication requests', async () => {
            const stress = new StressTest({
                concurrent: 50,
                duration: 15000, // 15 seconds
                rampUp: 2000     // 2 seconds ramp-up
            });

            const results = await stress.run(async () => {
                const response = await request(app)
                    .post('/api/authenticate')
                    .send({
                        apiKey: `load-test-key-${Math.random()}`,
                        baseUrl: 'https://api.make.com'
                    });
                
                // Accept both successful auth and expected failures
                expect([200, 401, 429]).toContain(response.status);
            });

            // Performance assertions
            expect(results.successRate).toBeGreaterThan(0.7); // At least 70% success rate
            expect(results.avgLatency).toBeLessThan(2000);     // Average under 2 seconds
            expect(results.p95Latency).toBeLessThan(5000);     // 95th percentile under 5 seconds
            expect(results.p99Latency).toBeLessThan(10000);    // 99th percentile under 10 seconds

            console.log('Authentication Load Test Results:', {
                totalRequests: results.successful + results.failed,
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`,
                p95Latency: `${results.p95Latency.toFixed(2)}ms`,
                p99Latency: `${results.p99Latency.toFixed(2)}ms`
            });
        }, 30000); // 30 second timeout for authentication load test

        it('should handle 100 concurrent scenario list requests', async () => {
            const stress = new StressTest({
                concurrent: 100,
                duration: 20000, // 20 seconds
                rampUp: 3000     // 3 seconds ramp-up
            });

            const results = await stress.run(async () => {
                const response = await request(app)
                    .get('/scenarios/list')
                    .query({ 
                        teamId: `team-${Math.floor(Math.random() * 10)}`,
                        limit: 20
                    });
                
                expect([200, 401, 404, 429]).toContain(response.status);
            });

            // Performance requirements for read operations should be stricter
            expect(results.successRate).toBeGreaterThan(0.8); // At least 80% success rate
            expect(results.avgLatency).toBeLessThan(1000);     // Average under 1 second
            expect(results.p95Latency).toBeLessThan(2000);     // 95th percentile under 2 seconds
            expect(results.p99Latency).toBeLessThan(5000);     // 99th percentile under 5 seconds

            console.log('Scenario List Load Test Results:', {
                totalRequests: results.successful + results.failed,
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`,
                p95Latency: `${results.p95Latency.toFixed(2)}ms`,
                p99Latency: `${results.p99Latency.toFixed(2)}ms`
            });
        }, 40000); // 40 second timeout for scenario list load test

        it('should handle mixed workload with concurrent operations', async () => {
            const stress = new StressTest({
                concurrent: 75,
                duration: 25000, // 25 seconds
                rampUp: 5000     // 5 seconds ramp-up
            });

            const operations = [
                // Read operations (60% of load)
                () => request(app).get('/scenarios/list').query({ teamId: '12345' }),
                () => request(app).get('/scenarios/list').query({ teamId: '12345' }),
                () => request(app).get('/scenarios/list').query({ teamId: '12345' }),
                
                // Create operations (30% of load)  
                () => request(app).post('/scenarios/create').send({
                    name: `Load Test Scenario ${Math.random()}`,
                    teamId: '12345'
                }),
                () => request(app).post('/scenarios/create').send({
                    name: `Load Test Scenario ${Math.random()}`,
                    teamId: '12345'
                }),
                
                // Update operations (10% of load)
                () => request(app).put('/scenarios/12345').send({
                    name: `Updated Scenario ${Math.random()}`
                })
            ];

            const results = await stress.run(async () => {
                const operation = operations[Math.floor(Math.random() * operations.length)];
                const response = await operation();
                
                expect([200, 201, 401, 404, 422, 429]).toContain(response.status);
            });

            // Mixed workload should handle diverse operations efficiently
            expect(results.successRate).toBeGreaterThan(0.6); // At least 60% success rate
            expect(results.avgLatency).toBeLessThan(3000);     // Average under 3 seconds
            expect(results.p95Latency).toBeLessThan(8000);     // 95th percentile under 8 seconds

            console.log('Mixed Workload Test Results:', {
                totalRequests: results.successful + results.failed,
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`,
                p95Latency: `${results.p95Latency.toFixed(2)}ms`,
                errorTypes: results.errors.slice(0, 5) // First 5 error types
            });
        }, 45000); // 45 second timeout for mixed workload test
    });

    describe('Resource Exhaustion Testing', () => {
        it('should handle memory-intensive operations under load', async () => {
            const stress = new StressTest({
                concurrent: 30,
                duration: 10000, // 10 seconds
                rampUp: 2000
            });

            const results = await stress.run(async () => {
                // Create a scenario with large blueprint data
                const largeBlueprint = {
                    name: `Memory Test Scenario ${Math.random()}`,
                    teamId: '12345',
                    blueprint: {
                        flow: Array(100).fill(null).map((_, i) => ({
                            id: `node-${i}`,
                            type: 'webhook',
                            parameters: {
                                url: `https://example.com/webhook-${i}`,
                                method: 'POST',
                                body: JSON.stringify({
                                    largeData: 'x'.repeat(1000), // 1KB of data per node
                                    nodeId: i,
                                    timestamp: Date.now()
                                })
                            }
                        }))
                    }
                };

                const response = await request(app)
                    .post('/scenarios/create')
                    .send(largeBlueprint);
                
                expect([200, 201, 413, 422, 429]).toContain(response.status);
            });

            // Memory-intensive operations may have lower success rates
            expect(results.successRate).toBeGreaterThan(0.4); // At least 40% success rate
            expect(results.avgLatency).toBeLessThan(5000);     // Average under 5 seconds

            console.log('Memory Intensive Test Results:', {
                totalRequests: results.successful + results.failed,
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`
            });
        }, 25000); // 25 second timeout for memory intensive test

        it('should handle database connection pool exhaustion gracefully', async () => {
            const stress = new StressTest({
                concurrent: 200, // Higher concurrency to stress DB connections
                duration: 15000,
                rampUp: 3000
            });

            const results = await stress.run(async () => {
                const response = await request(app)
                    .get('/scenarios/search')
                    .query({
                        q: `search-${Math.random()}`,
                        teamId: '12345',
                        limit: 50 // Force database query
                    });
                
                expect([200, 404, 429, 503]).toContain(response.status);
            });

            // Should handle DB pressure without complete failure
            expect(results.successRate).toBeGreaterThan(0.3); // At least 30% success rate
            expect(results.avgLatency).toBeLessThan(10000);    // Average under 10 seconds

            console.log('Database Pool Test Results:', {
                totalRequests: results.successful + results.failed,
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`,
                errorTypes: [...new Set(results.errors)].slice(0, 3)
            });
        }, 30000); // 30 second timeout for database pool test
    });

    describe('Scalability and Rate Limiting', () => {
        it('should implement proper rate limiting under high load', async () => {
            const rapidRequests = [];
            
            // Create 500 rapid requests from same client
            for (let i = 0; i < 500; i++) {
                rapidRequests.push(
                    request(app)
                        .get('/scenarios/list')
                        .set('X-Client-ID', 'rate-limit-test-client')
                        .query({ teamId: '12345' })
                );
            }

            const responses = await Promise.allSettled(rapidRequests);
            const rateLimited = responses.filter(result => 
                result.status === 'fulfilled' && 
                (result.value as any).status === 429
            );

            // Should have significant rate limiting
            expect(rateLimited.length).toBeGreaterThan(100);
            
            console.log('Rate Limiting Test Results:', {
                totalRequests: responses.length,
                rateLimitedRequests: rateLimited.length,
                rateLimitPercentage: `${(rateLimited.length / responses.length * 100).toFixed(2)}%`
            });
        }, 20000); // 20 second timeout for rate limiting test

        it('should maintain response quality under sustained load', async () => {
            const sustainedTest = new StressTest({
                concurrent: 25,
                duration: 30000, // 30 seconds sustained load
                rampUp: 5000
            });

            let responseTimeSamples: number[] = [];
            let errorRateSamples: number[] = [];
            
            // Sample performance every 5 seconds
            const samplingInterval = setInterval(() => {
                // This would collect real-time metrics in a production scenario
                responseTimeSamples.push(Date.now());
            }, 5000);

            const results = await sustainedTest.run(async () => {
                const start = Date.now();
                const response = await request(app)
                    .get('/scenarios/list')
                    .query({ teamId: '12345' });
                
                const latency = Date.now() - start;
                
                expect([200, 401, 404, 429]).toContain(response.status);
                
                // Collect metrics for degradation detection
                if (response.status === 200) {
                    if (latency > 5000) { // Flag slow responses
                        throw new Error(`Slow response: ${latency}ms`);
                    }
                }
            });

            clearInterval(samplingInterval);

            // Performance should not degrade significantly over time
            expect(results.successRate).toBeGreaterThan(0.7);
            expect(results.avgLatency).toBeLessThan(2000);
            
            // Check for performance degradation patterns
            const firstHalfLatencies = results.latencies.slice(0, Math.floor(results.latencies.length / 2));
            const secondHalfLatencies = results.latencies.slice(Math.floor(results.latencies.length / 2));
            
            const firstHalfAvg = firstHalfLatencies.reduce((a, b) => a + b, 0) / firstHalfLatencies.length || 0;
            const secondHalfAvg = secondHalfLatencies.reduce((a, b) => a + b, 0) / secondHalfLatencies.length || 0;
            
            // Performance should not degrade by more than 50% over time
            expect(secondHalfAvg).toBeLessThan(firstHalfAvg * 1.5);

            console.log('Sustained Load Test Results:', {
                totalRequests: results.successful + results.failed,
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`,
                firstHalfAvgLatency: `${firstHalfAvg.toFixed(2)}ms`,
                secondHalfAvgLatency: `${secondHalfAvg.toFixed(2)}ms`,
                performanceDegradation: `${((secondHalfAvg / firstHalfAvg - 1) * 100).toFixed(2)}%`
            });
        }, 60000); // 60 second timeout for sustained load test
    });

    describe('API Endpoint Specific Load Tests', () => {
        it('should handle concurrent scenario creation requests', async () => {
            const stress = new StressTest({
                concurrent: 20,
                duration: 10000,
                rampUp: 2000
            });

            const results = await stress.run(async () => {
                const response = await request(app)
                    .post('/scenarios/create')
                    .send({
                        name: `Concurrent Test ${Math.random()}`,
                        teamId: '12345',
                        blueprint: {
                            flow: [{
                                id: '1',
                                type: 'webhook',
                                parameters: {
                                    url: 'https://example.com',
                                    method: 'POST'
                                }
                            }]
                        }
                    });
                
                expect([201, 400, 422, 429]).toContain(response.status);
            });

            expect(results.successRate).toBeGreaterThan(0.5);
            expect(results.avgLatency).toBeLessThan(3000);

            console.log('Scenario Creation Load Test:', {
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`
            });
        }, 25000); // 25 second timeout for scenario creation test

        it('should handle concurrent connection management requests', async () => {
            const stress = new StressTest({
                concurrent: 30,
                duration: 12000,
                rampUp: 3000
            });

            const results = await stress.run(async () => {
                const operations = [
                    () => request(app).get('/connections/list').query({ teamId: '12345' }),
                    () => request(app).post('/connections/create').send({
                        name: `Load Test Connection ${Math.random()}`,
                        type: 'webhook',
                        teamId: '12345'
                    }),
                    () => request(app).get('/connections/test/12345')
                ];

                const operation = operations[Math.floor(Math.random() * operations.length)];
                const response = await operation();
                
                expect([200, 201, 400, 401, 404, 422, 429]).toContain(response.status);
            });

            expect(results.successRate).toBeGreaterThan(0.6);
            expect(results.avgLatency).toBeLessThan(2500);

            console.log('Connection Management Load Test:', {
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`
            });
        }, 30000); // 30 second timeout for connection management test

        it('should handle data store operations under concurrent load', async () => {
            const stress = new StressTest({
                concurrent: 40,
                duration: 15000,
                rampUp: 4000
            });

            const results = await stress.run(async () => {
                const operations = [
                    // Read operations (70% of load)
                    () => request(app).get('/data-stores/get').query({
                        key: `test-key-${Math.floor(Math.random() * 100)}`,
                        dataStructureId: 'test-structure'
                    }),
                    () => request(app).get('/data-stores/get').query({
                        key: `test-key-${Math.floor(Math.random() * 100)}`,
                        dataStructureId: 'test-structure'
                    }),
                    () => request(app).get('/data-stores/get').query({
                        key: `test-key-${Math.floor(Math.random() * 100)}`,
                        dataStructureId: 'test-structure'
                    }),

                    // Write operations (30% of load)
                    () => request(app).post('/data-stores/set').send({
                        key: `test-key-${Math.random()}`,
                        value: { data: `test-value-${Math.random()}` },
                        dataStructureId: 'test-structure'
                    })
                ];

                const operation = operations[Math.floor(Math.random() * operations.length)];
                const response = await operation();
                
                expect([200, 201, 400, 401, 404, 422, 429]).toContain(response.status);
            });

            expect(results.successRate).toBeGreaterThan(0.5);
            expect(results.avgLatency).toBeLessThan(4000);

            console.log('Data Store Load Test:', {
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`
            });
        }, 35000); // 35 second timeout for data store test
    });

    describe('Error Recovery and Resilience', () => {
        it('should recover gracefully from temporary overload', async () => {
            // Phase 1: Overload the system
            const overloadTest = new StressTest({
                concurrent: 150,
                duration: 5000, // 5 seconds of heavy load
                rampUp: 1000
            });

            await overloadTest.run(async () => {
                await request(app)
                    .get('/scenarios/list')
                    .query({ teamId: '12345' });
            });

            // Phase 2: Allow recovery time
            await new Promise(resolve => setTimeout(resolve, 3000));

            // Phase 3: Test normal load performance
            const recoveryTest = new StressTest({
                concurrent: 25,
                duration: 8000,
                rampUp: 2000
            });

            const results = await recoveryTest.run(async () => {
                const response = await request(app)
                    .get('/scenarios/list')
                    .query({ teamId: '12345' });
                
                expect([200, 401, 404, 429]).toContain(response.status);
            });

            // After recovery, performance should be acceptable
            expect(results.successRate).toBeGreaterThan(0.7);
            expect(results.avgLatency).toBeLessThan(2000);

            console.log('Recovery Test Results:', {
                successRate: `${(results.successRate * 100).toFixed(2)}%`,
                avgLatency: `${results.avgLatency.toFixed(2)}ms`
            });
        }, 40000); // 40 second timeout for recovery test
    });
});