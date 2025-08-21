/**
 * Mock audit logger for testing
 */

export const auditLogger = {
  logEvent: async (event: any) => {
    return {
      id: 'mock_audit_id',
      timestamp: new Date().toISOString(),
      ...event,
    };
  },
  
  generateComplianceReport: async (startDate: Date, endDate: Date) => {
    return {
      summary: {
        totalEvents: 1000,
        criticalEvents: 5,
        securityEvents: 50,
        complianceScore: 85,
      },
      events: [],
      period: {
        startDate: startDate.toISOString(),
        endDate: endDate.toISOString(),
      },
    };
  },
  
  performMaintenance: async () => {
    return {
      deletedFiles: 2,
      rotatedFiles: 3,
      errors: [],
    };
  },
  
  searchEvents: async (filters: any) => {
    return {
      events: [],
      total: 0,
      hasMore: false,
    };
  },
};

export default auditLogger;