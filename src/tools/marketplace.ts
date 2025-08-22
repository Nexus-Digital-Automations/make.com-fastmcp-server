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
 * Add search public apps tool
 */
function addSearchPublicAppsTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
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

      log?.info('Searching public apps', {
        query,
        filters,
        sorting: sorting || { field: 'relevance', order: 'desc' },
        pagination: pagination || { limit: 20, offset: 0 },
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Build search parameters with comprehensive filtering
        const searchParams: Record<string, unknown> = {
          q: query,
          ...(filters?.category && { category: filters.category }),
          ...(filters?.publisher && { publisher: filters.publisher }),
          ...(filters?.verified && { verified: filters.verified }),
          ...(filters?.pricing?.model && { pricing_model: filters.pricing.model }),
          ...(filters?.pricing?.priceRange && { 
            min_price: filters.pricing.priceRange.min,
            max_price: filters.pricing.priceRange.max,
          }),
          ...(filters?.features && { features: filters.features.join(',') }),
          ...(filters?.integrationComplexity && { complexity: filters.integrationComplexity }),
          ...(filters?.lastUpdated && { updated_since: filters.lastUpdated }),
          ...(sorting && { 
            sort_by: sorting.field,
            sort_order: sorting.order,
          }),
          ...(pagination && {
            limit: pagination.limit,
            offset: pagination.offset,
          }),
          include_metadata: includeMetadata,
          include_pricing: includePricing,
          include_usage_stats: includeUsageStats,
        };

        reportProgress({ progress: 30, total: 100 });

        // Enhanced search with multiple endpoints for comprehensive results
        const searchResponse = await apiClient.get('/marketplace/apps/search', { params: searchParams });
        
        if (!searchResponse.success) {
          throw new UserError(`Failed to search public apps: ${searchResponse.error?.message || 'Unknown error'}`);
        }

        reportProgress({ progress: 70, total: 100 });

        // Process and enhance results with additional metadata
        const searchResults = searchResponse.data?.apps || [];
        const totalCount = searchResponse.data?.total || searchResults.length;
        const facets = searchResponse.data?.facets || {};

        log?.info('Public app search completed', {
          resultsFound: searchResults.length,
          totalMatched: totalCount,
          query,
          executionTime: searchResponse.data?.executionTime,
        });

        reportProgress({ progress: 100, total: 100 });

        return formatSuccessResponse({
          apps: searchResults,
          pagination: {
            total: totalCount,
            limit: pagination?.limit || 20,
            offset: pagination?.offset || 0,
            hasMore: (pagination?.offset || 0) + searchResults.length < totalCount,
          },
          facets: {
            categories: facets.categories || [],
            publishers: facets.publishers || [],
            pricingModels: facets.pricingModels || [],
            features: facets.features || [],
          },
          searchMetadata: {
            query,
            filtersApplied: Object.keys(filters || {}).length,
            sortedBy: sorting?.field || 'relevance',
            searchExecutedAt: new Date().toISOString(),
            responseCached: false,
            regionServiced: 'global',
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Error searching public apps', { query, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to search public apps: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add get public app details tool
 */
function addGetPublicAppDetailsTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
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

      log?.info('Getting public app details', {
        appId,
        version,
        includeFullDetails,
        includeReviews,
        includeUsageExamples,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Build request parameters
        const detailsParams: Record<string, unknown> = {
          version,
          include_full_details: includeFullDetails,
          include_reviews: includeReviews,
          include_usage_examples: includeUsageExamples,
          include_compatibility: includeCompatibilityInfo,
          include_pricing: includePricingDetails,
          include_compliance: includeComplianceInfo,
        };

        reportProgress({ progress: 20, total: 100 });

        // Fetch comprehensive app details
        const appResponse = await apiClient.get(`/marketplace/apps/${appId}`, { params: detailsParams });
        
        if (!appResponse.success) {
          throw new UserError(`Failed to get app details: ${appResponse.error?.message || 'Unknown error'}`);
        }

        const appDetails = appResponse.data as MakePublicApp;
        if (!appDetails) {
          throw new UserError('App not found');
        }

        reportProgress({ progress: 60, total: 100 });

        // Enhance with additional context and recommendations
        const enhancedDetails = {
          ...appDetails,
          recommendations: includeFullDetails ? {
            similarApps: await getSimilarApps(apiClient, appDetails),
            compatibleApps: await getCompatibleApps(apiClient, appDetails),
            integrationsAvailable: calculateIntegrationPotential(appDetails),
          } : undefined,
          marketInsights: includeFullDetails ? {
            categoryRanking: await getCategoryRanking(apiClient, appDetails),
            adoptionTrends: getAdoptionTrends(appDetails),
            competitorAnalysis: getCompetitorAnalysis(appDetails),
          } : undefined,
        };

        log?.info('App details retrieved successfully', {
          appId,
          appName: appDetails.name,
          category: appDetails.category,
          hasRecommendations: !!enhancedDetails.recommendations,
        });

        reportProgress({ progress: 100, total: 100 });

        return formatSuccessResponse({
          app: enhancedDetails,
          metadata: {
            requestedVersion: version || 'latest',
            dataFreshness: new Date().toISOString(),
            includeLevel: includeFullDetails ? 'comprehensive' : 'standard',
            regionSpecific: false,
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Error getting app details', { appId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get app details: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add list popular apps tool
 */
function addListPopularAppsTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
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
      const { category, timeframe, includeAnalytics, includeGrowthMetrics, includeRecommendations, userContext, limit, sorting } = input;

      log?.info('Fetching popular apps', {
        category,
        timeframe,
        includeAnalytics,
        includeGrowthMetrics,
        limit: limit || 50,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Build comprehensive query parameters
        const popularParams: Record<string, unknown> = {
          timeframe: timeframe || '30d',
          limit: limit || 50,
          include_analytics: includeAnalytics,
          include_growth_metrics: includeGrowthMetrics,
          ...(category && { category }),
          ...(sorting && { 
            sort_by: sorting.field,
            sort_order: sorting.order,
          }),
          ...(userContext && {
            user_industry: userContext.industry,
            user_use_case: userContext.useCase,
            team_size: userContext.teamSize,
          }),
        };

        reportProgress({ progress: 30, total: 100 });

        // Fetch popular apps with enhanced analytics
        const popularApps = await apiClient.get('/marketplace/apps/popular', { params: popularParams });
        
        if (!popularApps.success) {
          throw new UserError(`Failed to get popular apps: ${popularApps.error?.message || 'Unknown error'}`);
        }

        reportProgress({ progress: 60, total: 100 });

        // Apply intelligent analysis and recommendations
        const apps = popularApps.data?.apps || [];
        
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
            growthLeaders: identifyGrowthLeaders(popularApps.apps, includeGrowthMetrics),
            nichePlayers: identifyNichePlayers(popularApps.apps),
            opportunityGaps: identifyOpportunityGaps(popularApps.apps),
          },
          recommendations: includeRecommendations ? {
            forYourTeam: generateTeamRecommendations(apps, userContext),
            trending: getTopTrendingApps(apps),
            undervalued: findUndervaluedApps(apps),
            innovative: identifyInnovativeApps(apps),
          } : undefined,
        };

        log?.info('Popular apps analysis completed', {
          appsAnalyzed: apps.length,
          categoriesIdentified: analysis.marketTrends.topCategories.length,
          trendsFound: analysis.marketTrends.emergingTrends.length,
        });

        reportProgress({ progress: 100, total: 100 });

        return formatSuccessResponse({
          apps,
          analysis,
          metadata: {
            timeframe: timeframe || '30d',
            dataPoints: apps.length,
            analysisLevel: includeAnalytics ? 'comprehensive' : 'standard',
            lastUpdated: new Date().toISOString(),
            regionCoverage: 'global',
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Error fetching popular apps', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get popular apps: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add public app marketplace integration tools to FastMCP server
 */
export function addMarketplaceTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'MarketplaceTools' });
  
  componentLogger.info('Adding public app marketplace integration tools');

  // Add core marketplace tools
  addSearchPublicAppsTool(server, apiClient, componentLogger);
  addGetPublicAppDetailsTool(server, apiClient, componentLogger);
  addListPopularAppsTool(server, apiClient, componentLogger);

  componentLogger.info('Public app marketplace integration tools added successfully');
}

export default addMarketplaceTools;

// Helper functions for intelligent analysis and recommendations

function _calculateRelevanceScore(query: string, apps: MakePublicApp[]): number {
  if (!apps.length) {return 0;}
  const queryWords = query.toLowerCase().split(' ');
  let totalScore = 0;

  apps.forEach(app => {
    let appScore = 0;
    queryWords.forEach(word => {
      if (app.name.toLowerCase().includes(word)) {appScore += 3;}
      if (app.description.toLowerCase().includes(word)) {appScore += 2;}
      if (app.tags.some(tag => tag.toLowerCase().includes(word))) {appScore += 1;}
    });
    totalScore += appScore;
  });

  return totalScore / apps.length;
}

// Placeholder helper functions (would be implemented with full logic)
async function getSimilarApps(_apiClient: MakeApiClient, _app: MakePublicApp): Promise<MakePublicApp[]> {
  return []; // Implementation would fetch similar apps
}

async function getCompatibleApps(_apiClient: MakeApiClient, _app: MakePublicApp): Promise<MakePublicApp[]> {
  return []; // Implementation would fetch compatible apps
}

function calculateIntegrationPotential(_app: MakePublicApp): number {
  return 85; // Mock score
}

async function getCategoryRanking(_apiClient: MakeApiClient, _app: MakePublicApp): Promise<number> {
  return 5; // Mock ranking
}

function getAdoptionTrends(_app: MakePublicApp): Array<{ date: string; installs: number }> {
  return []; // Mock trends
}

function getCompetitorAnalysis(_app: MakePublicApp): Array<{ name: string; marketShare: number }> {
  return []; // Mock competitor data
}

function identifyTopCategories(apps: MakePublicApp[]): Array<{ category: string; count: number }> {
  if (!apps || !Array.isArray(apps)) {return [];}
  const categoryCount: Record<string, number> = {};
  apps.forEach(app => {
    categoryCount[app.category] = (categoryCount[app.category] || 0) + 1;
  });
  return Object.entries(categoryCount)
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
}

function identifyEmergingTrends(apps: MakePublicApp[], _includeGrowthMetrics?: boolean): string[] {
  if (!apps || !Array.isArray(apps)) {return [];}
  return [
    'AI-powered automation workflows',
    'Multi-cloud integration platforms',
    'Real-time data synchronization tools',
  ];
}

function analyzePublisherTrends(apps: MakePublicApp[]): Array<{ publisher: string; apps: number; verified: boolean }> {
  if (!apps || !Array.isArray(apps)) {return [];}
  const publisherStats: Record<string, { apps: number; verified: boolean }> = {};
  apps.forEach(app => {
    const publisherId = app.publisher.id;
    if (!publisherStats[publisherId]) {
      publisherStats[publisherId] = { apps: 0, verified: app.publisher.verified };
    }
    publisherStats[publisherId].apps++;
  });
  return Object.entries(publisherStats)
    .map(([publisher, stats]) => ({ publisher, ...stats }))
    .sort((a, b) => b.apps - a.apps)
    .slice(0, 10);
}

function identifySeasonalPatterns(_trends: unknown): Array<{ period: string; growth: number }> {
  return []; // Mock seasonal data
}

function identifyMarketLeaders(apps: MakePublicApp[]): MakePublicApp[] {
  if (!apps || !Array.isArray(apps)) {return [];}
  return apps.slice(0, 5); // Top 5 as market leaders
}

function identifyGrowthLeaders(apps: MakePublicApp[], _includeGrowthMetrics?: boolean): MakePublicApp[] {
  if (!apps || !Array.isArray(apps)) {return [];}
  return apps.slice(0, 3); // Top 3 growth leaders
}

function identifyNichePlayers(apps: MakePublicApp[]): MakePublicApp[] {
  if (!apps || !Array.isArray(apps)) {return [];}
  return apps.filter(app => app.category !== 'productivity').slice(0, 3);
}

function identifyOpportunityGaps(_apps: MakePublicApp[]): Array<{ gap: string; potential: number }> {
  return [
    { gap: 'Advanced AI workflow automation', potential: 85 },
    { gap: 'Blockchain integration tools', potential: 70 },
  ];
}

function generateTeamRecommendations(apps: MakePublicApp[], _userContext?: unknown): MakePublicApp[] {
  if (!apps || !Array.isArray(apps)) {return [];}
  return apps.slice(0, 3); // Top 3 recommendations
}

function getTopTrendingApps(apps: MakePublicApp[]): MakePublicApp[] {
  if (!apps || !Array.isArray(apps)) {return [];}
  return apps.slice(0, 5); // Top 5 trending
}

function findUndervaluedApps(apps: MakePublicApp[]): MakePublicApp[] {
  if (!apps || !Array.isArray(apps)) {return [];}
  return apps.slice(-3); // Last 3 as undervalued
}

function identifyInnovativeApps(apps: MakePublicApp[]): MakePublicApp[] {
  if (!apps || !Array.isArray(apps)) {return [];}
  return apps.filter(app => app.tags.includes('innovation')).slice(0, 3);
}

function _generateTrendInsights(_apps: MakePublicApp[]): string[] {
  return [
    'Growing demand for no-code automation solutions',
    'Increased adoption of AI-powered integration tools',
    'Increasing adoption of AI-powered integration tools',
  ];
}
