export type GraphNodeType = 'entry' | 'identity' | 'permission' | 'network' | 'asset'

export type GraphNode = {
  id: string
  type: GraphNodeType
  label: string
  public?: boolean
  critical?: boolean
  attributes: Record<string, string | boolean | number>
}

export type GraphEdge = {
  from: string
  to: string
  relation: 'trusts' | 'assumes' | 'grants' | 'reaches' | 'contains'
  evidence: string
}

export type SecurityGraph = {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export type AttackPathResult = {
  id: string
  nodeIds: string[]
  score: number
  confidence: number
  evidence: string[]
  assumptions: string[]
}

export type ValidationResult = {
  brokenPaths: string[]
  remainingPaths: string[]
  regressions: string[]
  beforeScore: number
  afterScore: number
}

export const demoGraph: SecurityGraph = {
  nodes: [
    { id: 'github-oidc', type: 'entry', label: 'GitHub Actions runner', public: true, attributes: { provider: 'GitHub OIDC', repositoryScope: 'organization-wide' } },
    { id: 'build-role-prod', type: 'identity', label: 'build-role-prod', attributes: { trustedIssuer: 'token.actions.githubusercontent.com', wildcardRepository: true } },
    { id: 'secret-permission', type: 'permission', label: 'secretsmanager:*', attributes: { action: 'secretsmanager:GetSecretValue', resource: '*' } },
    { id: 'stripe-signing-key', type: 'asset', label: 'prod/stripe-signing-key', critical: true, attributes: { service: 'Secrets Manager', owner: 'Platform team' } },
    { id: 'vendor-role', type: 'entry', label: 'vendor-support role', attributes: { externalId: false, account: 'analytics' } },
    { id: 'analytics-trust', type: 'identity', label: 'analytics cross-account trust', attributes: { externalIdRequired: false } },
    { id: 'customer-exports', type: 'asset', label: 'customer-exports-prod', critical: true, attributes: { service: 'S3', encrypted: false, owner: 'Data platform' } },
    { id: 'payments-pod', type: 'entry', label: 'payments-api pod', public: true, attributes: { subnet: 'public', workloadIdentity: 'payments' } },
    { id: 'payments-sg', type: 'network', label: 'payments security group', attributes: { ingressToAdmin: true } },
    { id: 'admin-api', type: 'asset', label: 'admin-api.internal', critical: true, attributes: { service: 'Private service', owner: 'Runtime team' } },
  ],
  edges: [
    { from: 'github-oidc', to: 'build-role-prod', relation: 'trusts', evidence: 'GitHub OIDC trust accepts any repository in the organization.' },
    { from: 'build-role-prod', to: 'secret-permission', relation: 'grants', evidence: 'build-role-prod grants secretsmanager:GetSecretValue on all resources.' },
    { from: 'secret-permission', to: 'stripe-signing-key', relation: 'reaches', evidence: 'Wildcard resource includes prod/stripe-signing-key.' },
    { from: 'vendor-role', to: 'analytics-trust', relation: 'trusts', evidence: 'Cross-account trust does not require an external ID.' },
    { from: 'analytics-trust', to: 'customer-exports', relation: 'reaches', evidence: 'Analytics account can read customer-exports-prod.' },
    { from: 'payments-pod', to: 'payments-sg', relation: 'contains', evidence: 'Public workload inherits payments security group.' },
    { from: 'payments-sg', to: 'admin-api', relation: 'reaches', evidence: 'Ingress allows traffic to the internal admin service.' },
  ],
}

function outgoing(graph: SecurityGraph, from: string) {
  return graph.edges.filter((edge) => edge.from === from)
}

function node(graph: SecurityGraph, id: string) {
  return graph.nodes.find((item) => item.id === id)
}

function walkToCriticalAssets(graph: SecurityGraph, current: string, nodePath: string[], edgePath: string[], visited: Set<string>, results: AttackPathResult[]) {
  if (visited.has(current)) return
  visited.add(current)
  const currentNode = node(graph, current)
  if (currentNode?.type === 'asset' && currentNode.critical) {
    const evidence = edgePath.flatMap((edgeId) => {
      const edge = graph.edges.find((item) => `${item.from}->${item.to}` === edgeId)
      return edge ? [edge.evidence] : []
    })
    const entry = node(graph, nodePath[0])
    const hops = edgePath.length
    const exposureBoost = entry?.public ? 18 : 8
    const score = Math.min(99, 50 + exposureBoost + (currentNode.critical ? 15 : 0) + Math.max(0, 18 - hops * 4))
    results.push({ id: `derived-${results.length + 1}`, nodeIds: nodePath, score, confidence: Math.max(82, 100 - hops * 3), evidence, assumptions: ['Initial access is modeled as a bounded compromise of the entry point.'] })
  }
  outgoing(graph, current).forEach((edge) => walkToCriticalAssets(graph, edge.to, [...nodePath, edge.to], [...edgePath, `${edge.from}->${edge.to}`], new Set(visited), results))
}

export function analyzeEnvironment(graph: SecurityGraph): { paths: AttackPathResult[]; score: number } {
  const results: AttackPathResult[] = []
  graph.nodes.filter((item) => item.type === 'entry').forEach((entry) => walkToCriticalAssets(graph, entry.id, [entry.id], [], new Set(), results))
  const score = results.length ? Math.round(results.reduce((total, path) => total + path.score, 0) / results.length) : 0
  return { paths: results, score }
}

export function validateGraph(before: SecurityGraph, after: SecurityGraph): ValidationResult {
  const beforeAnalysis = analyzeEnvironment(before)
  const afterAnalysis = analyzeEnvironment(after)
  const beforeIds = new Set(beforeAnalysis.paths.map((path) => path.nodeIds.join('>')))
  const afterIds = new Set(afterAnalysis.paths.map((path) => path.nodeIds.join('>')))
  return {
    brokenPaths: [...beforeIds].filter((id) => !afterIds.has(id)),
    remainingPaths: [...afterIds],
    regressions: afterAnalysis.score > beforeAnalysis.score ? ['Aggregate risk score increased after the proposed change.'] : [],
    beforeScore: beforeAnalysis.score,
    afterScore: afterAnalysis.score,
  }
}

export function createRegressionTest(path: AttackPathResult) {
  const target = path.nodeIds[path.nodeIds.length - 1] ?? 'critical asset'
  return {
    name: `No reachable path for ${target}`,
    sourcePath: path.id,
    assertion: `reachable(${path.nodeIds[0]}, ${target}) === false`,
    bounded: true,
  }
}
