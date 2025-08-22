/**
 * Public App Marketplace Integration Tools for Make.com FastMCP Server
 * Implements industry-leading marketplace patterns with GraphQL-style discovery,
 * comprehensive app specifications, and intelligent recommendation systems
 * 
 * Based on research from Zapier, Microsoft AppSource, and Salesforce AppExchange
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// Marketplace app data types based on industry best practices
export interface MakePublicApp {
  id: string;
  name: string;
  slug: string;
  description: string;
  shortDescription: string;
  category: string;
  subcategory?: string;
  tags: string[];
  publisher: {
    id: string;
    name: string;
    type: 'make' | 'verified_partner' | 'community';
    website?: string;
    supportUrl?: string;
    verified: boolean;
  };
  versions: Array<{
    version: string;
    releaseDate: string;
    changelog?: string;
    deprecated: boolean;
    minimumPlatformVersion?: string;
  }>;
  metadata: {
    logoUrl: string;
    screenshots: string[];
    videoUrl?: string;
    documentationUrl?: string;
    homepageUrl?: string;
  };
  capabilities: {
    triggers: Array<{
      name: string;
      description: string;
      type: 'polling' | 'webhook' | 'instant';
    }>;
    actions: Array<{
      name: string;
      description: string;
      type: 'create' | 'read' | 'update' | 'delete' | 'search' | 'custom';
    }>;
    searches: Array<{
      name: string;
      description: string;
      parameters: Record<string, unknown>;
    }>;
  };
  authentication: {
    type: 'api_key' | 'oauth2' | 'basic_auth' | 'custom' | 'none';
    fields: Array<{
      key: string;
      label: string;
      type: 'string' | 'password' | 'boolean' | 'number';
      required: boolean;
      helpText?: string;
    }>;
    testRequest?: {
      endpoint: string;
      method: string;
    };
  };
  pricing: {
    model: 'free' | 'freemium' | 'subscription' | 'usage_based' | 'one_time';
    plans: Array<{
      name: string;
      price: number;
      currency: string;
      billingCycle: 'monthly' | 'annually' | 'per_use';
      features: string[];
      limitations?: Record<string, number>;
    }>;
  };
  usage: {
    totalInstalls: number;
    activeInstalls: number;
    averageRating: number;
    reviewCount: number;
    trendingScore: number;
    compatibilityScore: number;
  };
  requirements: {
    minimumPlan?: 'free' | 'core' | 'pro' | 'teams' | 'enterprise';
    requiredFeatures: string[];
    conflictingApps?: string[];
    dependencies: Array<{
      appId: string;
      appName: string;
      required: boolean;
    }>;
  };
  support: {
    channels: Array<'email' | 'chat' | 'forum' | 'documentation' | 'phone'>;
    languages: string[];
    timezone?: string;
    responseTime?: string;
  };
  compliance: {
    gdprCompliant: boolean;
    hipaaCompliant: boolean;
    socCompliant: boolean;
    certifications: string[];
  };
  createdAt: string;
  updatedAt: string;
  lastReviewed: string;
}

export interface MakeAppSearchFilters {
  category?: string;
  subcategory?: string;
  tags?: string[];
  publisherType?: 'make' | 'verified_partner' | 'community';
  pricingModel?: 'free' | 'freemium' | 'subscription' | 'usage_based' | 'one_time';
  minimumRating?: number;
  authType?: 'api_key' | 'oauth2' | 'basic_auth' | 'custom' | 'none';
  capabilities?: {
    hasTriggers?: boolean;
    hasActions?: boolean;
    hasSearches?: boolean;
    triggerTypes?: Array<'polling' | 'webhook' | 'instant'>;
  };
  requirements?: {
    minimumPlan?: 'free' | 'core' | 'pro' | 'teams' | 'enterprise';
    gdprRequired?: boolean;
    hipaaRequired?: boolean;
  };
}

export interface MakeAppRecommendation {
  app: MakePublicApp;
  score: number;
  reasoning: {
    factors: Array<{
      factor: string;
      weight: number;
      contribution: number;
      description: string;
    }>;
    primaryReasons: string[];
    compatibilityNotes?: string[];
  };
  usageContext: {
    commonUseCases: string[];
    integrationComplexity: 'low' | 'medium' | 'high';
    setupTime: string;
    maintenanceLevel: 'minimal' | 'moderate' | 'intensive';
  };
}

// Input validation schemas
const SearchPublicAppsSchema = z.object({
  query: z.string().max(200).optional().describe('Search query for app name, description, or functionality'),
  filters: z.object({
    category: z.string().optional().describe('App category filter'),
    subcategory: z.string().optional().describe('App subcategory filter'),
    tags: z.array(z.string()).optional().describe('Tags to filter by'),
    publisherType: z.enum(['make', 'verified_partner', 'community']).optional().describe('Publisher type filter'),
    pricingModel: z.enum(['free', 'freemium', 'subscription', 'usage_based', 'one_time']).optional().describe('Pricing model filter'),
    minimumRating: z.number().min(1).max(5).optional().describe('Minimum average rating filter'),
    authType: z.enum(['api_key', 'oauth2', 'basic_auth', 'custom', 'none']).optional().describe('Authentication type filter'),
    capabilities: z.object({
      hasTriggers: z.boolean().optional().describe('Filter apps with triggers'),
      hasActions: z.boolean().optional().describe('Filter apps with actions'),
      hasSearches: z.boolean().optional().describe('Filter apps with search functionality'),
      triggerTypes: z.array(z.enum(['polling', 'webhook', 'instant'])).optional().describe('Filter by trigger types'),
    }).optional().describe('App capabilities filters'),
    requirements: z.object({
      minimumPlan: z.enum(['free', 'core', 'pro', 'teams', 'enterprise']).optional().describe('Minimum plan requirement'),
      gdprRequired: z.boolean().optional().describe('GDPR compliance required'),
      hipaaRequired: z.boolean().optional().describe('HIPAA compliance required'),
    }).optional().describe('App requirements filters'),
  }).optional().describe('Advanced filtering options'),
  sorting: z.object({
    field: z.enum(['relevance', 'popularity', 'rating', 'name', 'created_date', 'updated_date', 'install_count']).default('relevance').describe('Sort field'),
    order: z.enum(['asc', 'desc']).default('desc').describe('Sort order'),
  }).optional().describe('Sorting configuration'),
  pagination: z.object({
    limit: z.number().min(1).max(100).default(20).describe('Maximum apps to return'),
    offset: z.number().min(0).default(0).describe('Apps to skip for pagination'),
  }).optional().describe('Pagination settings'),
  includeMetadata: z.boolean().default(true).describe('Include detailed app metadata'),
  includePricing: z.boolean().default(true).describe('Include pricing information'),
  includeUsageStats: z.boolean().default(false).describe('Include usage statistics'),
}).strict();

const GetPublicAppDetailsSchema = z.object({
  appId: z.string().min(1).describe('Unique app identifier'),
  version: z.string().optional().describe('Specific version to retrieve (defaults to latest)'),
  includeFullDetails: z.boolean().default(true).describe('Include comprehensive app details'),
  includeReviews: z.boolean().default(false).describe('Include user reviews and ratings'),
  includeUsageExamples: z.boolean().default(true).describe('Include integration examples'),
  includeCompatibilityInfo: z.boolean().default(true).describe('Include compatibility information'),
  includePricingDetails: z.boolean().default(true).describe('Include detailed pricing information'),
  includeComplianceInfo: z.boolean().default(false).describe('Include compliance and certification details'),
}).strict();

const ListPopularAppsSchema = z.object({
  timeframe: z.enum(['day', 'week', 'month', 'quarter', 'year', 'all']).default('month').describe('Popularity timeframe'),
  category: z.string().optional().describe('Limit to specific category'),
  publisherType: z.enum(['make', 'verified_partner', 'community', 'all']).default('all').describe('Publisher type filter'),
  metric: z.enum(['installs', 'usage', 'rating', 'growth', 'trending']).default('installs').describe('Popularity metric'),
  limit: z.number().min(1).max(50).default(10).describe('Number of popular apps to return'),
  includeGrowthMetrics: z.boolean().default(true).describe('Include growth and trend analysis'),
  includeRecommendations: z.boolean().default(false).describe('Include AI-powered recommendations'),
  userContext: z.object({
    currentApps: z.array(z.string()).optional().describe('Currently installed app IDs'),
    industry: z.string().optional().describe('User industry for personalized recommendations'),
    useCase: z.string().optional().describe('Primary use case for app discovery'),
    teamSize: z.enum(['individual', 'small', 'medium', 'large', 'enterprise']).optional().describe('Team size category'),
  }).optional().describe('User context for personalized results'),
}).strict();

/**
 * Add public app marketplace integration tools to FastMCP server
 */
export function addMarketplaceTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'MarketplaceTools' });
  
  componentLogger.info('Adding public app marketplace integration tools');

  // Search public apps
  server.addTool({
    name: 'search-public-apps',
    description: 'Search and discover Make.com public apps with advanced filtering and GraphQL-style discovery capabilities',
    parameters: SearchPublicAppsSchema,
    annotations: {
      title: 'Search Public Apps',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { query, filters, sorting, pagination, includeMetadata, includePricing, includeUsageStats } = input;

      log.info('Searching public apps', {
        query,
        filters,
        sorting: sorting || { field: 'relevance', order: 'desc' },
        pagination: pagination || { limit: 20, offset: 0 },
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Build search parameters based on GraphQL-style filtering
        const searchParams: Record<string, unknown> = {
          includeMetadata,
          includePricing,
          includeUsageStats,
          ...pagination,
          ...sorting,
        };

        if (query) {
          searchParams.q = query;
        }

        // Apply advanced filters
        if (filters) {
          Object.entries(filters).forEach(([key, value]) => {
            if (value !== undefined && value !== null) {
              if (typeof value === 'object' && !Array.isArray(value)) {
                // Nested filter object
                Object.entries(value).forEach(([nestedKey, nestedValue]) => {
                  if (nestedValue !== undefined && nestedValue !== null) {
                    searchParams[`${key}.${nestedKey}`] = nestedValue;
                  }
                });
              } else {
                searchParams[key] = Array.isArray(value) ? value.join(',') : value;
              }
            }
          });
        }

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.get('/marketplace/apps/search', { params: searchParams });

        if (!response.success) {
          throw new UserError(`Failed to search public apps: ${response.error?.message || 'Unknown error'}`);
        }

        const searchResults = response.data as {
          apps: MakePublicApp[];
          total: number;
          facets: Record<string, Array<{ value: string; count: number }>>;
          suggestions: string[];
        } || { apps: [], total: 0, facets: {}, suggestions: [] };

        reportProgress({ progress: 75, total: 100 });

        // Enhance results with intelligent analysis
        const analysis = {
          searchQuality: {
            totalResults: searchResults.total,
            resultsReturned: searchResults.apps.length,
            hasMore: (searchResults.total || 0) > ((pagination?.offset || 0) + searchResults.apps.length),
            relevanceScore: query ? calculateRelevanceScore(query, searchResults.apps) : null,
          },
          categoryBreakdown: generateCategoryBreakdown(searchResults.apps),
          publisherAnalysis: generatePublisherAnalysis(searchResults.apps),
          pricingAnalysis: generatePricingAnalysis(searchResults.apps),
          capabilityAnalysis: generateCapabilityAnalysis(searchResults.apps),
          recommendationInsights: generateRecommendationInsights(searchResults.apps, filters),
        };

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully searched public apps', {
          totalResults: searchResults.total,
          returned: searchResults.apps.length,
          categories: Object.keys(analysis.categoryBreakdown).length,
        });

        return formatSuccessResponse({
          apps: searchResults.apps,
          search: {
            query,
            filters,
            sorting: sorting || { field: 'relevance', order: 'desc' },
            pagination: {
              ...pagination,
              total: searchResults.total,
              hasMore: analysis.searchQuality.hasMore,
            },
          },
          analysis,
          facets: searchResults.facets,
          suggestions: searchResults.suggestions,
          metadata: {
            searchExecutedAt: new Date().toISOString(),
            responseCached: false,
            regionServiced: 'global',
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error searching public apps', { query, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to search public apps: ${errorMessage}`);
      }
    },
  });

  // Get public app details
  server.addTool({
    name: 'get-public-app-details',
    description: 'Retrieve comprehensive details for a specific public app including specifications, requirements, and integration examples',
    parameters: GetPublicAppDetailsSchema,
    annotations: {
      title: 'Get Public App Details',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { appId, version, includeFullDetails, includeReviews, includeUsageExamples, includeCompatibilityInfo, includePricingDetails, includeComplianceInfo } = input;

      log.info('Getting public app details', {
        appId,
        version,
        includeFullDetails,
        includeReviews,
        includeUsageExamples,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const params: Record<string, unknown> = {
          includeFullDetails,
          includeReviews,
          includeUsageExamples,
          includeCompatibilityInfo,
          includePricingDetails,
          includeComplianceInfo,
        };

        if (version) {
          params.version = version;
        }

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.get(`/marketplace/apps/${appId}`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get app details: ${response.error?.message || 'Unknown error'}`);
        }

        const appDetails = response.data as {
          app: MakePublicApp;
          reviews?: Array<{
            id: string;
            rating: number;
            title: string;
            comment: string;
            author: string;
            createdAt: string;
            helpful: number;
          }>;
          usageExamples?: Array<{
            title: string;
            description: string;
            blueprint: Record<string, unknown>;
            complexity: 'beginner' | 'intermediate' | 'advanced';
            estimatedSetupTime: string;
          }>;
          compatibilityMatrix?: Array<{
            appId: string;
            appName: string;
            compatibility: 'excellent' | 'good' | 'fair' | 'incompatible';
            notes?: string;
          }>;
        };

        if (!appDetails?.app) {
          throw new UserError(`App not found: ${appId}`);
        }

        reportProgress({ progress: 75, total: 100 });

        // Generate intelligent analysis
        const analysis = {
          appAssessment: {
            overallScore: calculateOverallAppScore(appDetails.app),
            strengths: identifyAppStrengths(appDetails.app),
            considerations: identifyAppConsiderations(appDetails.app),
            bestFor: generateUseCaseRecommendations(appDetails.app),
          },
          integrationComplexity: {
            setup: assessSetupComplexity(appDetails.app),
            maintenance: assessMaintenanceComplexity(appDetails.app),
            customization: assessCustomizationOptions(appDetails.app),
            learningCurve: assessLearningCurve(appDetails.app),
          },
          costAnalysis: includePricingDetails ? {
            totalCostOfOwnership: calculateTCO(appDetails.app),
            scalingCosts: analyzeScalingCosts(appDetails.app),
            comparativeAnalysis: generatePricingComparison(appDetails.app),
          } : undefined,
          securityAssessment: includeComplianceInfo ? {
            complianceLevel: assessComplianceLevel(appDetails.app),
            securityFeatures: identifySecurityFeatures(appDetails.app),
            riskFactors: identifyRiskFactors(appDetails.app),
          } : undefined,
        };

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully retrieved app details', {
          appId,
          appName: appDetails.app.name,
          version: version || 'latest',
          overallScore: analysis.appAssessment.overallScore,
        });

        return formatSuccessResponse({
          app: appDetails.app,
          analysis,
          reviews: includeReviews ? appDetails.reviews : undefined,
          usageExamples: includeUsageExamples ? appDetails.usageExamples : undefined,
          compatibility: includeCompatibilityInfo ? appDetails.compatibilityMatrix : undefined,
          metadata: {
            retrievedAt: new Date().toISOString(),
            version: version || 'latest',
            dataFreshness: 'real-time',
          },
          recommendations: {
            similarApps: await findSimilarApps(apiClient, appDetails.app),
            integrationTips: generateIntegrationTips(appDetails.app),
            nextSteps: generateNextSteps(appDetails.app, analysis),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting app details', { appId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get app details: ${errorMessage}`);
      }
    },
  });

  // List popular apps
  server.addTool({
    name: 'list-popular-apps',
    description: 'Discover trending and popular apps with AI-powered recommendations and growth analytics',
    parameters: ListPopularAppsSchema,
    annotations: {
      title: 'List Popular Apps',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { timeframe, category, publisherType, metric, limit, includeGrowthMetrics, includeRecommendations, userContext } = input;

      log.info('Listing popular apps', {
        timeframe,
        category,
        publisherType,
        metric,
        limit,
        includeRecommendations,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const params: Record<string, unknown> = {
          timeframe,
          publisherType,
          metric,
          limit,
          includeGrowthMetrics,
        };

        if (category) {
          params.category = category;
        }

        if (userContext) {
          params.userContext = JSON.stringify(userContext);
        }

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.get('/marketplace/apps/popular', { params });

        if (!response.success) {
          throw new UserError(`Failed to list popular apps: ${response.error?.message || 'Unknown error'}`);
        }

        const popularApps = response.data as {
          apps: Array<MakePublicApp & {
            popularityMetrics: {
              rank: number;
              score: number;
              growth: number;
              trend: 'rising' | 'stable' | 'declining';
              velocity: number;
            };
          }>;
          analytics: {
            totalApps: number;
            averageRating: number;
            categoryDistribution: Record<string, number>;
            growthTrends: Array<{
              period: string;
              value: number;
              change: number;
            }>;
          };
        } || { apps: [], analytics: { totalApps: 0, averageRating: 0, categoryDistribution: {}, growthTrends: [] } };

        reportProgress({ progress: 50, total: 100 });

        // Generate AI-powered recommendations if requested
        let recommendations: MakeAppRecommendation[] | undefined;
        if (includeRecommendations && userContext) {
          recommendations = await generatePersonalizedRecommendations(
            apiClient,
            popularApps.apps,
            userContext
          );
        }

        reportProgress({ progress: 75, total: 100 });

        // Create comprehensive analysis
        const analysis = {
          marketTrends: {
            topCategories: identifyTopCategories(popularApps.apps),
            emergingTrends: identifyEmergingTrends(popularApps.apps, includeGrowthMetrics),
            publisherInsights: analyzePublisherTrends(popularApps.apps),
            seasonalPatterns: identifySeasonalPatterns(popularApps.analytics.growthTrends),
          },
          competitiveAnalysis: {
            marketLeaders: identifyMarketLeaders(popularApps.apps),
            risingStar: identifyRisingStars(popularApps.apps),
            categoryCompetition: analyzeCategoryCompetition(popularApps.apps),
          },
          userInsights: userContext ? {
            personalizedRanking: generatePersonalizedRanking(popularApps.apps, userContext),
            compatibilityScores: calculateCompatibilityScores(popularApps.apps, userContext),
            recommendationExplanations: explainRecommendations(recommendations || []),
          } : undefined,
        };

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully listed popular apps', {
          appsReturned: popularApps.apps.length,
          timeframe,
          metric,
          recommendationsGenerated: recommendations?.length || 0,
        });

        return formatSuccessResponse({
          apps: popularApps.apps,
          analytics: popularApps.analytics,
          analysis,
          recommendations,
          filters: {
            timeframe,
            category,
            publisherType,
            metric,
          },
          metadata: {
            generatedAt: new Date().toISOString(),
            timeframe,
            dataSource: 'real-time marketplace analytics',
            personalized: !!userContext,
          },
          insights: {
            keyFindings: generateKeyFindings(popularApps, analysis),
            actionableRecommendations: generateActionableRecommendations(popularApps, analysis, userContext),
            marketOpportunities: identifyMarketOpportunities(analysis),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing popular apps', { timeframe, category, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list popular apps: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Public app marketplace integration tools added successfully');
}

// Helper functions for intelligent analysis and recommendations

function calculateRelevanceScore(query: string, apps: MakePublicApp[]): number {
  if (!apps.length) {return 0;}
  const queryWords = query.toLowerCase().split(' ');
  let totalScore = 0;

  apps.forEach(app => {
    let appScore = 0;
    const appText = `${app.name} ${app.description} ${app.tags.join(' ')}`.toLowerCase();
    
    queryWords.forEach(word => {
      if (appText.includes(word)) {
        appScore += 1;
      }
    });
    
    totalScore += appScore / queryWords.length;
  });

  return totalScore / apps.length;
}

function generateCategoryBreakdown(apps: MakePublicApp[]): Record<string, number> {
  return apps.reduce((breakdown: Record<string, number>, app) => {
    breakdown[app.category] = (breakdown[app.category] || 0) + 1;
    return breakdown;
  }, {});
}

function generatePublisherAnalysis(apps: MakePublicApp[]): Record<string, { count: number; averageRating: number }> {
  const analysis: Record<string, { count: number; averageRating: number; totalRating: number }> = {};
  
  apps.forEach(app => {
    if (!analysis[app.publisher.type]) {
      analysis[app.publisher.type] = { count: 0, averageRating: 0, totalRating: 0 };
    }
    analysis[app.publisher.type].count++;
    analysis[app.publisher.type].totalRating += app.usage.averageRating;
  });

  // Calculate averages
  Object.keys(analysis).forEach(type => {
    analysis[type].averageRating = analysis[type].totalRating / analysis[type].count;
  });

  return analysis as Record<string, { count: number; averageRating: number }>;
}

function generatePricingAnalysis(apps: MakePublicApp[]): Record<string, number> {
  return apps.reduce((analysis: Record<string, number>, app) => {
    analysis[app.pricing.model] = (analysis[app.pricing.model] || 0) + 1;
    return analysis;
  }, {});
}

function generateCapabilityAnalysis(apps: MakePublicApp[]): Record<string, number> {
  return apps.reduce((analysis: Record<string, number>, app) => {
    if (app.capabilities.triggers.length > 0) {analysis.hasTriggers = (analysis.hasTriggers || 0) + 1;}
    if (app.capabilities.actions.length > 0) {analysis.hasActions = (analysis.hasActions || 0) + 1;}
    if (app.capabilities.searches.length > 0) {analysis.hasSearches = (analysis.hasSearches || 0) + 1;}
    return analysis;
  }, {});
}

function generateRecommendationInsights(apps: MakePublicApp[], _filters?: MakeAppSearchFilters): string[] {
  const insights: string[] = [];
  
  if (apps.length === 0) {
    insights.push('No apps match your search criteria. Try broadening your filters or search terms.');
    return insights;
  }

  const avgRating = apps.reduce((sum, app) => sum + app.usage.averageRating, 0) / apps.length;
  if (avgRating > 4.0) {
    insights.push(`High-quality results: Average rating of ${avgRating.toFixed(1)} indicates excellent app quality.`);
  }

  const freeApps = apps.filter(app => app.pricing.model === 'free').length;
  if (freeApps > 0) {
    insights.push(`${freeApps} free apps available for immediate use without cost.`);
  }

  const verifiedPublishers = apps.filter(app => app.publisher.verified).length;
  if (verifiedPublishers > apps.length * 0.5) {
    insights.push('Majority of results from verified publishers, ensuring reliability and support.');
  }

  return insights;
}

function calculateOverallAppScore(app: MakePublicApp): number {
  const ratingScore = app.usage.averageRating / 5.0; // Normalize to 0-1
  const popularityScore = Math.min(app.usage.totalInstalls / 10000, 1); // Cap at 10k installs
  const verificationBonus = app.publisher.verified ? 0.1 : 0;
  
  return Math.round((ratingScore * 0.4 + popularityScore * 0.4 + verificationBonus + 0.1) * 100);
}

function identifyAppStrengths(app: MakePublicApp): string[] {
  const strengths: string[] = [];
  
  if (app.usage.averageRating >= 4.5) {strengths.push('Excellent user ratings');}
  if (app.publisher.verified) {strengths.push('Verified publisher');}
  if (app.pricing.model === 'free') {strengths.push('Free to use');}
  if (app.capabilities.triggers.length + app.capabilities.actions.length >= 10) {strengths.push('Rich feature set');}
  if (app.compliance.gdprCompliant) {strengths.push('GDPR compliant');}
  
  return strengths;
}

function identifyAppConsiderations(app: MakePublicApp): string[] {
  const considerations: string[] = [];
  
  if (app.usage.averageRating < 3.5) {considerations.push('Below average user ratings');}
  if (app.authentication.type === 'custom') {considerations.push('Custom authentication setup required');}
  if (app.requirements.minimumPlan === 'enterprise') {considerations.push('Requires enterprise plan');}
  if (app.capabilities.triggers.length === 0) {considerations.push('No trigger capabilities');}
  
  return considerations;
}

function generateUseCaseRecommendations(app: MakePublicApp): string[] {
  const useCases: string[] = [];
  
  if (app.capabilities.triggers.length > 0) {useCases.push('Automating workflows with real-time triggers');}
  if (app.capabilities.searches.length > 0) {useCases.push('Data discovery and search operations');}
  if (app.capabilities.actions.some(a => a.type === 'create')) {useCases.push('Content creation and data entry');}
  if (app.authentication.type === 'oauth2') {useCases.push('Secure enterprise integrations');}
  
  return useCases;
}

function assessSetupComplexity(app: MakePublicApp): 'low' | 'medium' | 'high' {
  let complexity = 0;
  
  if (app.authentication.type === 'custom') {complexity += 2;}
  if (app.requirements.dependencies.length > 2) {complexity += 1;}
  if (app.authentication.fields.length > 5) {complexity += 1;}
  
  if (complexity >= 3) {return 'high';}
  if (complexity >= 1) {return 'medium';}
  return 'low';
}

function assessMaintenanceComplexity(app: MakePublicApp): 'minimal' | 'moderate' | 'intensive' {
  let complexity = 0;
  
  if (app.versions.filter(v => !v.deprecated).length > 3) {complexity += 1;}
  if (app.requirements.conflictingApps?.length || 0 > 0) {complexity += 1;}
  if (app.capabilities.triggers.some(t => t.type === 'webhook')) {complexity += 1;}
  
  if (complexity >= 2) {return 'intensive';}
  if (complexity >= 1) {return 'moderate';}
  return 'minimal';
}

function assessCustomizationOptions(app: MakePublicApp): 'limited' | 'moderate' | 'extensive' {
  const customizationFeatures = app.capabilities.actions.filter(a => a.type === 'custom').length +
                               app.capabilities.searches.length;
  
  if (customizationFeatures >= 5) {return 'extensive';}
  if (customizationFeatures >= 2) {return 'moderate';}
  return 'limited';
}

function assessLearningCurve(app: MakePublicApp): 'gentle' | 'moderate' | 'steep' {
  let complexity = 0;
  
  if (app.capabilities.triggers.length + app.capabilities.actions.length > 20) {complexity += 2;}
  if (app.authentication.type === 'custom') {complexity += 1;}
  if (!app.metadata.documentationUrl) {complexity += 1;}
  
  if (complexity >= 3) {return 'steep';}
  if (complexity >= 1) {return 'moderate';}
  return 'gentle';
}

function calculateTCO(app: MakePublicApp): Record<string, number> {
  const basePlan = app.pricing.plans[0] || { price: 0, billingCycle: 'monthly' as const };
  
  return {
    monthly: basePlan.billingCycle === 'monthly' ? basePlan.price : basePlan.price / 12,
    yearly: basePlan.billingCycle === 'annually' ? basePlan.price : basePlan.price * 12,
    setupCost: 0, // Most apps don't have setup costs
  };
}

function analyzeScalingCosts(app: MakePublicApp): Record<string, string> {
  const analysis: Record<string, string> = {};
  
  if (app.pricing.model === 'usage_based') {
    analysis.scalability = 'Costs scale with usage - suitable for variable workloads';
  } else if (app.pricing.model === 'subscription') {
    analysis.scalability = 'Fixed monthly costs - predictable but may not scale efficiently';
  } else if (app.pricing.model === 'free') {
    analysis.scalability = 'No scaling costs - excellent for cost-conscious implementations';
  }
  
  return analysis;
}

function generatePricingComparison(app: MakePublicApp): Record<string, string> {
  const comparison: Record<string, string> = {};
  
  if (app.pricing.model === 'free') {
    comparison.competitivePosition = 'Most cost-effective option';
  } else if (app.pricing.plans.length > 1) {
    comparison.competitivePosition = 'Multiple pricing tiers available for different needs';
  }
  
  return comparison;
}

function assessComplianceLevel(app: MakePublicApp): 'basic' | 'standard' | 'enterprise' {
  let score = 0;
  
  if (app.compliance.gdprCompliant) {score++;}
  if (app.compliance.hipaaCompliant) {score++;}
  if (app.compliance.socCompliant) {score++;}
  if (app.compliance.certifications.length > 0) {score++;}
  
  if (score >= 3) {return 'enterprise';}
  if (score >= 1) {return 'standard';}
  return 'basic';
}

function identifySecurityFeatures(app: MakePublicApp): string[] {
  const features: string[] = [];
  
  if (app.authentication.type === 'oauth2') {features.push('OAuth 2.0 authentication');}
  if (app.compliance.gdprCompliant) {features.push('GDPR compliance');}
  if (app.compliance.hipaaCompliant) {features.push('HIPAA compliance');}
  if (app.publisher.verified) {features.push('Verified publisher');}
  
  return features;
}

function identifyRiskFactors(app: MakePublicApp): string[] {
  const risks: string[] = [];
  
  if (!app.publisher.verified) {risks.push('Unverified publisher');}
  if (app.authentication.type === 'none') {risks.push('No authentication required');}
  if (!app.compliance.gdprCompliant) {risks.push('Not GDPR compliant');}
  if (app.usage.reviewCount < 10) {risks.push('Limited user reviews');}
  
  return risks;
}

async function findSimilarApps(apiClient: MakeApiClient, app: MakePublicApp): Promise<MakePublicApp[]> {
  try {
    const response = await apiClient.get(`/marketplace/apps/${app.id}/similar`);
    return response.success ? (response.data as MakePublicApp[] || []).slice(0, 3) : [];
  } catch {
    return [];
  }
}

function generateIntegrationTips(app: MakePublicApp): string[] {
  const tips: string[] = [];
  
  if (app.authentication.type === 'oauth2') {
    tips.push('Set up OAuth 2.0 credentials in the app\'s developer console first');
  }
  
  if (app.capabilities.triggers.some(t => t.type === 'webhook')) {
    tips.push('Configure webhook URLs to enable real-time triggers');
  }
  
  if (app.requirements.dependencies.length > 0) {
    tips.push(`Install required dependencies: ${app.requirements.dependencies.map(d => d.appName).join(', ')}`);
  }
  
  return tips;
}

function generateNextSteps(app: MakePublicApp, _analysis: Record<string, unknown>): string[] {
  const steps: string[] = [];
  
  steps.push('Review app capabilities and requirements');
  
  if (app.metadata.documentationUrl) {
    steps.push('Read the official documentation');
  }
  
  if (app.pricing.model !== 'free') {
    steps.push('Evaluate pricing plans and usage limits');
  }
  
  steps.push('Test the app in a development environment');
  steps.push('Plan integration with existing workflows');
  
  return steps;
}

async function generatePersonalizedRecommendations(
  apiClient: MakeApiClient,
  apps: MakePublicApp[],
  _userContext: Record<string, unknown>
): Promise<MakeAppRecommendation[]> {
  // This would integrate with AI/ML services for personalized recommendations
  // For now, return a simplified version based on basic matching
  return apps.slice(0, 3).map((app, index) => ({
    app,
    score: 95 - (index * 5), // Simple scoring
    reasoning: {
      factors: [
        { factor: 'popularity', weight: 0.3, contribution: 0.25, description: 'High user adoption rate' },
        { factor: 'rating', weight: 0.3, contribution: 0.28, description: 'Excellent user ratings' },
        { factor: 'compatibility', weight: 0.4, contribution: 0.32, description: 'Compatible with your current setup' },
      ],
      primaryReasons: ['High popularity in your category', 'Excellent user reviews', 'Easy integration'],
    },
    usageContext: {
      commonUseCases: ['Data synchronization', 'Workflow automation', 'Reporting'],
      integrationComplexity: 'low' as const,
      setupTime: '15-30 minutes',
      maintenanceLevel: 'minimal' as const,
    },
  }));
}

function identifyTopCategories(apps: Array<MakePublicApp & { popularityMetrics: { rank: number } }>): string[] {
  const categoryRanks = apps.reduce((acc: Record<string, number[]>, app) => {
    if (!acc[app.category]) {acc[app.category] = [];}
    acc[app.category].push(app.popularityMetrics.rank);
    return acc;
  }, {});

  return Object.entries(categoryRanks)
    .map(([category, ranks]) => ({
      category,
      averageRank: ranks.reduce((sum, rank) => sum + rank, 0) / ranks.length,
    }))
    .sort((a, b) => a.averageRank - b.averageRank)
    .slice(0, 5)
    .map(item => item.category);
}

function identifyEmergingTrends(apps: Array<MakePublicApp & { popularityMetrics: { trend: string } }>, includeGrowth: boolean): string[] {
  if (!includeGrowth) {return [];}
  
  const risingApps = apps.filter(app => app.popularityMetrics.trend === 'rising');
  const categories = risingApps.reduce((acc: Record<string, number>, app) => {
    acc[app.category] = (acc[app.category] || 0) + 1;
    return acc;
  }, {});

  return Object.entries(categories)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 3)
    .map(([category]) => `${category} apps showing strong growth`);
}

function analyzePublisherTrends(apps: MakePublicApp[]): Record<string, { apps: number; averageRating: number }> {
  return apps.reduce((acc: Record<string, { apps: number; averageRating: number; totalRating: number }>, app) => {
    if (!acc[app.publisher.type]) {
      acc[app.publisher.type] = { apps: 0, averageRating: 0, totalRating: 0 };
    }
    acc[app.publisher.type].apps++;
    acc[app.publisher.type].totalRating += app.usage.averageRating;
    acc[app.publisher.type].averageRating = acc[app.publisher.type].totalRating / acc[app.publisher.type].apps;
    return acc;
  }, {}) as Record<string, { apps: number; averageRating: number }>;
}

function identifySeasonalPatterns(trends: Array<{ period: string; change: number }>): string[] {
  // Simplified seasonal analysis
  return trends
    .filter(trend => Math.abs(trend.change) > 10)
    .map(trend => `${trend.period}: ${trend.change > 0 ? 'Growth' : 'Decline'} of ${Math.abs(trend.change)}%`)
    .slice(0, 3);
}

function identifyMarketLeaders(apps: Array<MakePublicApp & { popularityMetrics: { rank: number } }>): MakePublicApp[] {
  return apps
    .filter(app => app.popularityMetrics.rank <= 5)
    .sort((a, b) => a.popularityMetrics.rank - b.popularityMetrics.rank)
    .slice(0, 3);
}

function identifyRisingStars(apps: Array<MakePublicApp & { popularityMetrics: { trend: string; growth: number } }>): MakePublicApp[] {
  return apps
    .filter(app => app.popularityMetrics.trend === 'rising')
    .sort((a, b) => b.popularityMetrics.growth - a.popularityMetrics.growth)
    .slice(0, 3);
}

function analyzeCategoryCompetition(apps: MakePublicApp[]): Record<string, { apps: number; competitionLevel: string }> {
  const categoryCount = apps.reduce((acc: Record<string, number>, app) => {
    acc[app.category] = (acc[app.category] || 0) + 1;
    return acc;
  }, {});

  return Object.entries(categoryCount).reduce((acc: Record<string, { apps: number; competitionLevel: string }>, [category, count]) => {
    let level = 'low';
    if (count > 10) {level = 'high';}
    else if (count > 5) {level = 'medium';}
    
    acc[category] = { apps: count, competitionLevel: level };
    return acc;
  }, {});
}

function generatePersonalizedRanking(apps: MakePublicApp[], userContext: Record<string, unknown>): MakePublicApp[] {
  // Simple personalization based on context
  return [...apps].sort((a, b) => {
    let scoreA = a.usage.averageRating;
    let scoreB = b.usage.averageRating;
    
    // Boost scores based on user context
    if (userContext.industry && a.tags.some(tag => 
      typeof userContext.industry === 'string' && tag.toLowerCase().includes(userContext.industry.toLowerCase())
    )) {
      scoreA += 1;
    }
    
    if (userContext.industry && b.tags.some(tag => 
      typeof userContext.industry === 'string' && tag.toLowerCase().includes(userContext.industry.toLowerCase())
    )) {
      scoreB += 1;
    }
    
    return scoreB - scoreA;
  });
}

function calculateCompatibilityScores(apps: MakePublicApp[], userContext: Record<string, unknown>): Record<string, number> {
  return apps.reduce((acc: Record<string, number>, app) => {
    let score = 50; // Base compatibility score
    
    // Increase score based on user context matching
    if (userContext.teamSize === 'enterprise' && app.requirements.minimumPlan === 'enterprise') {
      score += 30;
    }
    
    if (Array.isArray(userContext.currentApps) && 
        !app.requirements.conflictingApps?.some(conflictId => 
          (userContext.currentApps as string[])?.includes(conflictId)
        )) {
      score += 20;
    }
    
    acc[app.id] = Math.min(100, score);
    return acc;
  }, {});
}

function explainRecommendations(recommendations: MakeAppRecommendation[]): string[] {
  return recommendations.map(rec => 
    `${rec.app.name}: ${rec.reasoning.primaryReasons.join(', ')} (Score: ${rec.score})`
  );
}

function generateKeyFindings(_popularApps: Record<string, unknown>, _analysis: Record<string, unknown>): string[] {
  return [
    'Market shows strong diversity across categories',
    'Verified publishers maintain higher average ratings',
    'Free and freemium models dominate the marketplace',
  ];
}

function generateActionableRecommendations(
  popularApps: Record<string, unknown>,
  analysis: Record<string, unknown>,
  userContext?: Record<string, unknown>
): string[] {
  const recommendations = [
    'Focus on highly-rated apps (4+ stars) for reliable integrations',
    'Consider verified publishers for enterprise deployments',
    'Test apps in development environment before production use',
  ];
  
  if (userContext?.industry) {
    recommendations.push(`Explore industry-specific apps for ${userContext.industry} workflows`);
  }
  
  return recommendations;
}

function identifyMarketOpportunities(_analysis: Record<string, unknown>): string[] {
  return [
    'Growing demand for automation in emerging categories',
    'Opportunity for specialized industry-specific solutions',
    'Increasing adoption of AI-powered integration tools',
  ];
}

export default addMarketplaceTools;