/**
 * Test fixtures for scenario testing
 * Provides mock data for various scenario testing scenarios
 */

export const mockScenarios = {
  simple: {
    id: 'scenario-simple-123',
    name: 'Simple Test Scenario',
    teamId: 'team-123',
    folderId: null,
    blueprint: {
      modules: [
        { id: 1, app: 'webhook', type: 'trigger' }
      ],
      connections: []
    },
    isActive: false
  },
  
  complex: {
    id: 'scenario-complex-456', 
    name: 'Complex Test Scenario',
    teamId: 'team-123',
    folderId: 'folder-789',
    blueprint: {
      modules: [
        { id: 1, app: 'webhook', type: 'trigger' },
        { id: 2, app: 'filter', type: 'filter' },
        { id: 3, app: 'email', type: 'action' }
      ],
      connections: [
        { source: 1, target: 2 },
        { source: 2, target: 3 }
      ]
    },
    isActive: true
  },
  
  withOptionals: {
    id: 'scenario-optional-789',
    name: 'Scenario with Optional Fields',
    teamId: '123e4567-e89b-12d3-a456-426614174000',
    folderId: '987fcdeb-51d2-12d3-a456-426614174000',
    blueprint: {
      modules: [
        { id: 1, app: 'webhook', type: 'trigger' }
      ],
      connections: []
    },
    isActive: true,
    scheduling: {
      type: 'interval',
      interval: 15
    }
  }
};

export const mockBlueprints = {
  validSimple: {
    modules: [{ id: 1, app: 'webhook', type: 'trigger' }],
    connections: []
  },
  
  highComplexity: {
    modules: Array(20).fill(0).map((_, i) => ({
      id: i + 1,
      app: `test-app-${i}`,
      type: i === 0 ? 'trigger' : 'action'
    })),
    connections: Array(19).fill(0).map((_, i) => ({
      source: i + 1,
      target: i + 2
    }))
  },
  
  needsOptimization: {
    modules: [
      { id: 1, app: 'webhook', type: 'trigger' },
      { id: 2, app: 'delay', type: 'action', config: { delay: 30 } },
      { id: 3, app: 'delay', type: 'action', config: { delay: 30 } } // Redundant delay
    ],
    connections: [
      { source: 1, target: 2 },
      { source: 2, target: 3 }
    ]
  },
  
  invalid: {
    modules: [], // Missing modules
    // Missing connections property
  }
};

export const mockApiResponses = {
  createScenario: {
    success: {
      id: 'scenario-created-123',
      name: 'Created Scenario',
      teamId: 'team-123',
      isActive: false
    },
    error: {
      error: {
        message: 'Team not found',
        code: 'TEAM_NOT_FOUND'
      }
    }
  },
  
  listScenarios: {
    success: {
      scenarios: [
        mockScenarios.simple,
        mockScenarios.complex
      ],
      pagination: {
        page: 1,
        limit: 10,
        total: 2
      }
    },
    empty: {
      scenarios: [],
      pagination: {
        page: 1,
        limit: 10,
        total: 0
      }
    }
  },
  
  getScenario: {
    success: mockScenarios.complex,
    notFound: {
      error: {
        message: 'Scenario not found',
        code: 'SCENARIO_NOT_FOUND'
      }
    }
  }
};

export const mockTroubleshootingData = {
  healthyScenario: {
    scenarioId: 'scenario-healthy-123',
    status: 'healthy',
    issues: [],
    performanceMetrics: {
      averageExecutionTime: 1200,
      successRate: 0.98,
      errorRate: 0.02
    }
  },
  
  problematicScenario: {
    scenarioId: 'scenario-problem-456',
    status: 'warning',
    issues: [
      {
        type: 'performance',
        severity: 'warning',
        message: 'High execution time detected',
        recommendation: 'Consider optimizing module configuration'
      },
      {
        type: 'connectivity',
        severity: 'info',
        message: 'Intermittent connection issues',
        recommendation: 'Check webhook URL availability'
      }
    ],
    performanceMetrics: {
      averageExecutionTime: 5400,
      successRate: 0.85,
      errorRate: 0.15
    }
  }
};

// Valid UUID for testing
export const validUUIDs = {
  teamId: '123e4567-e89b-12d3-a456-426614174000',
  scenarioId: '987fcdeb-51d2-12d3-a456-426614174001',
  folderId: '456e7890-12d3-a456-426614174002',
  organizationId: '789abcde-f012-3456-7890-abcdef123456'
};

// Invalid data for negative testing
export const invalidData = {
  emptyStrings: {
    name: '',
    teamId: ''
  },
  invalidUUIDs: {
    teamId: 'invalid-uuid',
    scenarioId: 'not-a-uuid'
  },
  wrongTypes: {
    name: 123,
    isActive: 'true',
    blueprint: 'not-an-object'
  }
};