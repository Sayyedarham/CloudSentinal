import { useRef, useState, type ReactNode } from 'react'
import {
  Activity,
  AlertCircle,
  ArrowDownRight,
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  BarChart3,
  Bell,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Cloud,
  CloudCog,
  Code2,
  Database,
  Download,
  ExternalLink,
  FileCheck2,
  FileJson2,
  Filter,
  GitBranch,
  Globe2,
  Headphones,
  Info,
  KeyRound,
  Layers3,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  Network,
  Play,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Target,
  UserRound,
  Users,
  X,
  Zap,
} from 'lucide-react'
import { analyzeEnvironment, demoGraph } from './security-engine'

type View = 'overview' | 'attack-paths' | 'findings' | 'validation' | 'regressions' | 'assets' | 'activity' | 'settings'
type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type Path = {
  id: string
  title: string
  description: string
  severity: Severity
  score: number
  scoreLabel: string
  entry: string
  asset: string
  assetType: string
  owner: string
  updated: string
  delta: string
  tags: string[]
}

const paths: Path[] = [
  {
    id: 'path-iam-001',
    title: 'Public CI runner → production secrets',
    description: 'An internet-facing runner can assume a build role with wildcard Secrets Manager access, then read the production Stripe signing key.',
    severity: 'Critical',
    score: 96,
    scoreLabel: 'Critical exposure',
    entry: 'GitHub Actions runner',
    asset: 'prod/stripe-signing-key',
    assetType: 'Secrets Manager secret',
    owner: 'Platform team',
    updated: '9 min ago',
    delta: '+18',
    tags: ['IAM', 'Public exposure', 'Secrets'],
  },
  {
    id: 'path-s3-014',
    title: 'Vendor role → customer exports bucket',
    description: 'A third-party support role is trusted by the analytics account and can reach an unencrypted customer export bucket.',
    severity: 'High',
    score: 82,
    scoreLabel: 'High exposure',
    entry: 'vendor-support role',
    asset: 'customer-exports-prod',
    assetType: 'S3 bucket',
    owner: 'Data platform',
    updated: '24 min ago',
    delta: '+11',
    tags: ['Trust policy', 'Data access', 'S3'],
  },
  {
    id: 'path-net-007',
    title: 'Compromised web pod → internal admin plane',
    description: 'A vulnerable workload in a public subnet inherits a security group that permits access to the internal admin API.',
    severity: 'High',
    score: 78,
    scoreLabel: 'High exposure',
    entry: 'payments-api pod',
    asset: 'admin-api.internal',
    assetType: 'Private service',
    owner: 'Runtime team',
    updated: '1 hr ago',
    delta: '+7',
    tags: ['Network', 'Kubernetes', 'Lateral movement'],
  },
]

const findings = [
  { id: 'FND-2048', title: 'Wildcard secrets read on build role', severity: 'Critical' as Severity, confidence: 98, path: 'Public CI runner → production secrets', status: 'Open', source: 'Deterministic rule', asset: 'prod/stripe-signing-key' },
  { id: 'FND-2047', title: 'GitHub OIDC trust allows all repositories', severity: 'High' as Severity, confidence: 94, path: 'Public CI runner → production secrets', status: 'Open', source: 'AI hypothesis', asset: 'build-role-prod' },
  { id: 'FND-2045', title: 'Cross-account vendor trust lacks external ID', severity: 'High' as Severity, confidence: 92, path: 'Vendor role → customer exports bucket', status: 'In review', source: 'Deterministic rule', asset: 'vendor-support role' },
  { id: 'FND-2042', title: 'Customer exports bucket is not encrypted', severity: 'Medium' as Severity, confidence: 89, path: 'Vendor role → customer exports bucket', status: 'Open', source: 'Deterministic rule', asset: 'customer-exports-prod' },
  { id: 'FND-2039', title: 'Public workload can reach admin service', severity: 'High' as Severity, confidence: 87, path: 'Compromised web pod → internal admin plane', status: 'Open', source: 'AI hypothesis', asset: 'admin-api.internal' },
]

const navItems: { id: View; label: string; icon: typeof LayoutDashboard; count?: number }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'attack-paths', label: 'Attack paths', icon: GitBranch, count: 12 },
  { id: 'findings', label: 'Findings', icon: ShieldAlert, count: 38 },
  { id: 'validation', label: 'Validation', icon: FileCheck2 },
  { id: 'regressions', label: 'Regression tests', icon: RefreshCw },
]

const libraryItems: { id: View; label: string; icon: typeof Database }[] = [
  { id: 'assets', label: 'Assets & graph', icon: Network },
  { id: 'activity', label: 'Activity log', icon: Activity },
]

function App() {
  const [activeView, setActiveView] = useState<View>('overview')
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false)
  const [analysisVersion, setAnalysisVersion] = useState(24)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const selectedPath = paths.find((path) => path.id === selectedPathId)

  const showToast = (message: string) => {
    setToast(message)
    window.setTimeout(() => setToast(null), 3500)
  }

  const navigate = (view: View) => {
    setActiveView(view)
    setSelectedPathId(null)
    setIsMobileNavOpen(false)
  }

  const openPath = (pathId: string) => {
    setSelectedPathId(pathId)
    setActiveView('attack-paths')
    setIsMobileNavOpen(false)
  }

  const runAnalysis = () => {
    if (isAnalyzing) return
    const result = analyzeEnvironment(demoGraph)
    setIsAnalyzing(true)
    showToast('Analysis queued — rebuilding the relationship graph')
    window.setTimeout(() => {
      setIsAnalyzing(false)
      setAnalysisVersion((version) => version + 1)
      showToast(`Analysis complete — ${result.paths.length} critical paths confirmed`)
    }, 1800)
  }

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) showToast(`${file.name} staged for read-only ingestion`)
    event.target.value = ''
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${isMobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="sidebar-topline" />
        <div className="brand-row">
          <div className="brand-mark"><ShieldCheck size={19} strokeWidth={2.5} /></div>
          <div className="brand-name">cloud<span>sentinel</span></div>
          <button className="mobile-close" onClick={() => setIsMobileNavOpen(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>

        <button className="workspace-switcher" onClick={() => showToast('Workspace switcher is ready for multi-tenant wiring')}>
          <div className="workspace-avatar">AC</div>
          <div className="workspace-copy"><strong>Acme Cloud</strong><span>Security workspace</span></div>
          <ChevronDown size={15} />
        </button>

        <div className="nav-label">Monitor</div>
        <nav className="main-nav">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = activeView === item.id && !selectedPath
            return <button key={item.id} className={`nav-item ${isActive ? 'active' : ''}`} onClick={() => navigate(item.id)}><Icon size={17} /><span>{item.label}</span>{item.count && <span className="nav-count">{item.count}</span>}</button>
          })}
        </nav>

        <div className="nav-label library-label">Library</div>
        <nav className="main-nav">
          {libraryItems.map((item) => {
            const Icon = item.icon
            return <button key={item.id} className={`nav-item ${activeView === item.id ? 'active' : ''}`} onClick={() => navigate(item.id)}><Icon size={17} /><span>{item.label}</span></button>
          })}
        </nav>

        <div className="sidebar-spacer" />
        <div className="coverage-card">
          <div className="coverage-title"><span>Environment coverage</span><Info size={13} /></div>
          <div className="coverage-number">94<span>%</span></div>
          <div className="coverage-track"><span style={{ width: '94%' }} /></div>
          <div className="coverage-meta"><span>12,842 resources</span><span>+3.2%</span></div>
        </div>
        <button className="nav-item bottom-nav" onClick={() => navigate('settings')}><Settings2 size={17} /><span>Settings</span></button>
        <div className="user-row"><div className="user-avatar">JD</div><div><strong>Jordan Davis</strong><span>Security engineer</span></div><MoreDots /></div>
      </aside>

      {isMobileNavOpen && <button className="sidebar-scrim" onClick={() => setIsMobileNavOpen(false)} aria-label="Close menu" />}

      <div className="main-area">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setIsMobileNavOpen(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <div className="breadcrumb"><span>Acme Cloud</span><ChevronRight size={14} /><strong>{selectedPath ? 'Attack path detail' : viewTitle(activeView)}</strong></div>
          <div className="topbar-actions">
            <div className="search-box"><Search size={16} /><input placeholder="Search anything" /><span className="search-shortcut">⌘ K</span></div>
            <button className="icon-button" aria-label="Open notifications" onClick={() => showToast('No new alerts — you are all caught up')}><Bell size={17} /><span className="notification-dot" /></button>
            <button className="help-button" onClick={() => showToast('Support workspace opened')}><Headphones size={15} /> <span>Support</span></button>
          </div>
        </header>

        <main className="content-area">
          {activeView === 'overview' && <Overview onRunAnalysis={runAnalysis} isAnalyzing={isAnalyzing} onImport={() => fileInputRef.current?.click()} onOpenPath={openPath} analysisVersion={analysisVersion} />}
          {activeView === 'attack-paths' && (selectedPath ? <PathDetail path={selectedPath} onBack={() => setSelectedPathId(null)} onRunValidation={() => showToast('Validation run started for this path')} /> : <AttackPaths onOpenPath={openPath} onRunAnalysis={runAnalysis} isAnalyzing={isAnalyzing} />)}
          {activeView === 'findings' && <Findings onOpenPath={openPath} />}
          {activeView === 'validation' && <Validation onRunAnalysis={runAnalysis} isAnalyzing={isAnalyzing} />}
          {activeView === 'regressions' && <Regressions onToast={showToast} />}
          {activeView === 'assets' && <Assets onToast={showToast} />}
          {activeView === 'activity' && <ActivityView />}
          {activeView === 'settings' && <Settings onToast={showToast} />}
        </main>
      </div>

      <input ref={fileInputRef} type="file" accept=".json,.yaml,.yml,.csv" className="hidden-input" onChange={handleImport} />
      {toast && <div className="toast"><CheckCircle2 size={17} /><span>{toast}</span><button onClick={() => setToast(null)} aria-label="Dismiss"><X size={14} /></button></div>}
    </div>
  )
}

function viewTitle(view: View) {
  return ({ overview: 'Overview', 'attack-paths': 'Attack paths', findings: 'Findings', validation: 'Validation', regressions: 'Regression tests', assets: 'Assets & graph', activity: 'Activity log', settings: 'Settings' })[view]
}

function MoreDots() {
  return <span className="more-dots"><i /><i /><i /></span>
}

function Overview({ onRunAnalysis, isAnalyzing, onImport, onOpenPath, analysisVersion }: { onRunAnalysis: () => void; isAnalyzing: boolean; onImport: () => void; onOpenPath: (id: string) => void; analysisVersion: number }) {
  return <div className="page-stack">
    <section className="page-heading heading-with-actions">
      <div><div className="eyebrow"><span className="live-dot" />Live environment</div><h1>Cloud risk, explained.</h1><p>See how small configuration weaknesses combine into the paths attackers can actually use.</p></div>
      <div className="heading-actions"><button className="button button-secondary" onClick={onImport}><FileJson2 size={16} /> Import data</button><button className="button button-primary" onClick={onRunAnalysis} disabled={isAnalyzing}><Sparkles size={16} className={isAnalyzing ? 'spin' : ''} /> {isAnalyzing ? 'Analyzing…' : 'Run analysis'} <span className="button-kbd">⌘ ↵</span></button></div>
    </section>
    <section className="analysis-banner"><div className="banner-icon"><Zap size={17} /></div><div><strong>Analysis #{analysisVersion} finished 9 minutes ago</strong><span>3 high-confidence paths need attention. Your graph is 94% covered across AWS production.</span></div><button className="text-button">View run <ArrowRight size={15} /></button></section>
    <section className="metric-grid">
      <MetricCard label="Critical paths" value="12" delta="+3" deltaTone="bad" helper="vs. last analysis" icon={<GitBranch size={18} />} accent="purple" />
      <MetricCard label="Exploitable findings" value="38" delta="+8" deltaTone="bad" helper="across 21 assets" icon={<ShieldAlert size={18} />} accent="red" />
      <MetricCard label="Risk score" value="74.2" delta="−6.8" deltaTone="good" helper="after remediation" icon={<Target size={18} />} accent="amber" />
      <MetricCard label="Control coverage" value="94%" delta="+3.2%" deltaTone="good" helper="12,842 resources" icon={<ShieldCheck size={18} />} accent="green" />
    </section>
    <section className="dashboard-grid">
      <div className="panel critical-panel"><PanelHeader title="Priority attack paths" subtitle="Ranked by real-world exploitability" action="View all paths" onAction={() => onOpenPath(paths[0].id)} /><div className="path-list">{paths.map((path, index) => <PathListItem key={path.id} path={path} rank={index + 1} onClick={() => onOpenPath(path.id)} />)}</div><button className="panel-footer-link" onClick={() => onOpenPath(paths[0].id)}>Explore attack path graph <ArrowRight size={14} /></button></div>
      <div className="panel score-panel"><PanelHeader title="Risk momentum" subtitle="Aggregate risk score over 30 days" action="Last 30 days" /><div className="chart-legend"><span><i className="legend-dot purple" />Risk score</span><span><i className="legend-dot green" />Baseline</span></div><RiskChart /><div className="chart-footer"><div><strong>74.2</strong><span>Current score</span></div><div className="chart-change"><ArrowDownRight size={15} /> 6.8% <span>since last review</span></div></div></div>
    </section>
    <section className="dashboard-grid bottom-grid"><div className="panel asset-panel"><PanelHeader title="Assets at risk" subtitle="High-value resources reachable from exposed entries" action="View inventory" /><div className="asset-table"><div className="table-row table-head"><span>Asset</span><span>Risk</span><span>Owner</span></div><AssetRow icon={<KeyRound size={16} />} name="prod/stripe-signing-key" type="Secret · AWS us-east-1" risk="Critical" owner="Platform" /><AssetRow icon={<Database size={16} />} name="customer-exports-prod" type="S3 bucket · AWS us-west-2" risk="High" owner="Data platform" /><AssetRow icon={<Server size={16} />} name="admin-api.internal" type="Private service · EKS" risk="High" owner="Runtime" /></div></div><div className="panel activity-panel"><PanelHeader title="Recent activity" subtitle="What changed in your environment" action="Open log" /><ActivityItem icon={<Sparkles size={15} />} color="purple" text="AI hypothesis confirmed" detail="FND-2047 · GitHub OIDC trust" time="9m ago" /><ActivityItem icon={<Check size={15} />} color="green" text="Remediation validated" detail="S3 encryption on analytics bucket" time="24m ago" /><ActivityItem icon={<GitBranch size={15} />} color="amber" text="New attack path discovered" detail="vendor-support → customer exports" time="1h ago" /><ActivityItem icon={<CloudCog size={15} />} color="blue" text="AWS account connected" detail="Production · 12,842 resources" time="3h ago" /></div></section>
  </div>
}

function MetricCard({ label, value, delta, deltaTone, helper, icon, accent }: { label: string; value: string; delta: string; deltaTone: 'bad' | 'good'; helper: string; icon: ReactNode; accent: string }) {
  return <div className="metric-card"><div className={`metric-icon ${accent}`}>{icon}</div><div className="metric-label">{label}</div><div className="metric-value-row"><strong>{value}</strong><span className={`delta ${deltaTone}`}>{delta}</span></div><div className="metric-helper">{helper}</div></div>
}

function PanelHeader({ title, subtitle, action, onAction }: { title: string; subtitle: string; action?: string; onAction?: () => void }) {
  return <div className="panel-header"><div><h2>{title}</h2><p>{subtitle}</p></div>{action && <button className="panel-action" onClick={onAction}>{action}<ChevronRight size={14} /></button>}</div>
}

function PathListItem({ path, rank, onClick }: { path: Path; rank: number; onClick: () => void }) {
  return <button className="path-list-item" onClick={onClick}><span className="path-rank">0{rank}</span><span className={`severity-marker ${path.severity.toLowerCase()}`} /><span className="path-item-copy"><strong>{path.title}</strong><span>{path.entry} <ArrowRight size={12} /> {path.asset}</span></span><span className="path-score"><strong>{path.score}</strong><span>risk</span></span><ChevronRight size={15} className="path-chevron" /></button>
}

function RiskChart() {
  return <div className="risk-chart"><svg viewBox="0 0 620 205" role="img" aria-label="Risk score decreasing from 82 to 74 over 30 days"><defs><linearGradient id="areaGradient" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#a78bfa" stopOpacity=".28" /><stop offset="100%" stopColor="#a78bfa" stopOpacity="0" /></linearGradient></defs><g className="grid-lines"><line x1="0" y1="31" x2="620" y2="31" /><line x1="0" y1="86" x2="620" y2="86" /><line x1="0" y1="141" x2="620" y2="141" /></g><path d="M0,62 C45,56 56,82 96,74 S144,95 183,78 S231,73 266,108 S321,95 347,112 S401,103 433,130 S478,119 509,144 S564,128 620,152 L620,196 L0,196 Z" fill="url(#areaGradient)" /><path d="M0,62 C45,56 56,82 96,74 S144,95 183,78 S231,73 266,108 S321,95 347,112 S401,103 433,130 S478,119 509,144 S564,128 620,152" fill="none" stroke="#a78bfa" strokeWidth="3" strokeLinecap="round" /><path d="M0,151 C90,151 110,150 180,151 S300,150 390,151 S530,150 620,150" fill="none" stroke="#39d98a" strokeWidth="2" strokeDasharray="6 7" opacity=".8" /><circle cx="620" cy="152" r="5" fill="#a78bfa" stroke="#151e31" strokeWidth="3" /></svg><div className="chart-axis"><span>Sep 25</span><span>Oct 02</span><span>Oct 09</span><span>Oct 16</span><span>Oct 24</span></div></div>
}

function AssetRow({ icon, name, type, risk, owner }: { icon: ReactNode; name: string; type: string; risk: Severity; owner: string }) {
  return <div className="table-row"><div className="asset-name"><span className="asset-icon">{icon}</span><div><strong>{name}</strong><span>{type}</span></div></div><span className={`risk-pill ${risk.toLowerCase()}`}>{risk}</span><span className="owner-name">{owner}</span></div>
}

function ActivityItem({ icon, color, text, detail, time }: { icon: ReactNode; color: string; text: string; detail: string; time: string }) {
  return <div className="activity-item"><span className={`activity-icon ${color}`}>{icon}</span><div><strong>{text}</strong><span>{detail}</span></div><time>{time}</time></div>
}

function AttackPaths({ onOpenPath, onRunAnalysis, isAnalyzing }: { onOpenPath: (id: string) => void; onRunAnalysis: () => void; isAnalyzing: boolean }) {
  return <div className="page-stack"><section className="page-heading heading-with-actions"><div><div className="eyebrow"><GitBranch size={14} />Graph explorer</div><h1>Attack paths</h1><p>Understand the shortest route from an exposed entry point to a sensitive asset.</p></div><div className="heading-actions"><button className="button button-secondary"><Filter size={15} /> Filter</button><button className="button button-primary" onClick={onRunAnalysis} disabled={isAnalyzing}><Sparkles size={15} /> {isAnalyzing ? 'Analyzing…' : 'Run analysis'}</button></div></section><div className="filter-bar"><div className="filter-chip active">All paths <span>12</span></div><div className="filter-chip">Critical <span>3</span></div><div className="filter-chip">High <span>9</span></div><div className="filter-spacer" /><span className="updated-label"><CircleDot size={12} /> Updated 9 min ago</span></div><section className="panel paths-table-panel"><div className="paths-table-head"><span>Path</span><span>Risk score</span><span>Entry point</span><span>High-value asset</span><span>Owner</span><span /></div>{paths.map((path) => <button className="paths-table-row" key={path.id} onClick={() => onOpenPath(path.id)}><div className="path-table-title"><span className={`severity-marker ${path.severity.toLowerCase()}`} /><div><strong>{path.title}</strong><span>{path.tags.join(' · ')}</span></div></div><div className="score-cell"><strong>{path.score}</strong><span>/ 100</span></div><span>{path.entry}</span><span className="table-asset">{path.asset}</span><span>{path.owner}</span><ChevronRight size={16} /></button>)}<div className="table-pagination"><span>Showing <strong>1–3</strong> of 12 paths</span><div><button><ArrowLeft size={14} /></button><button className="current">1</button><button>2</button><button>3</button><button><ArrowRight size={14} /></button></div></div></section></div>
}

function PathDetail({ path, onBack, onRunValidation }: { path: Path; onBack: () => void; onRunValidation: () => void }) {
  return <div className="page-stack"><button className="back-button" onClick={onBack}><ArrowLeft size={15} /> All attack paths</button><section className="detail-heading"><div><div className="eyebrow"><span className={`severity-dot ${path.severity.toLowerCase()}`} />{path.severity} path · {path.id.toUpperCase()}</div><h1>{path.title}</h1><p>{path.description}</p><div className="tag-row">{path.tags.map((tag) => <span className="tag" key={tag}>{tag}</span>)}<span className="tag muted">Detected {path.updated}</span></div></div><div className="detail-actions"><button className="button button-secondary"><Download size={15} /> Export evidence</button><button className="button button-primary" onClick={onRunValidation}><Play size={15} /> Validate fix</button></div></section><section className="detail-summary-grid"><div className="detail-score-card"><span className="score-label">Path risk score</span><div className="big-score"><strong>{path.score}</strong><span>/ 100</span></div><div className="score-bar"><span style={{ width: `${path.score}%` }} /></div><div className="score-foot"><span>Critical exposure</span><span><ArrowUpRight size={13} /> 18 pts this week</span></div></div><div className="detail-stat-card"><span>Reachability confidence</span><strong>98%</strong><span className="green-copy"><CheckCircle2 size={14} /> Verified by graph rules</span></div><div className="detail-stat-card"><span>Blast radius</span><strong>14 assets</strong><span>3 accounts · 2 regions</span></div><div className="detail-stat-card"><span>Last validated</span><strong>9 min ago</strong><span>Analysis #{24}</span></div></section><section className="detail-main-grid"><div className="panel graph-panel"><PanelHeader title="Exploit chain" subtitle="Explicit evidence connecting entry point to high-value asset" action="Graph settings" /><AttackGraph path={path} /></div><div className="panel evidence-panel"><PanelHeader title="Why this is risky" subtitle="Evidence collected from your environment" /><EvidenceList path={path} /></div></section><section className="detail-bottom-grid"><div className="panel remediation-panel"><PanelHeader title="Smallest change to break the path" subtitle="Recommended remediation plan" action="Open ticket" /><div className="remediation-callout"><div className="remediation-icon"><Sparkles size={17} /></div><div><strong>Scope the build role to one repository</strong><p>Replace the wildcard OIDC trust with the exact repository and branch claims. This removes the untrusted entry point without changing the role's runtime permissions.</p></div><span className="effort-chip">Low effort</span></div><div className="remediation-steps"><RemediationStep number="01" title="Update trust condition" detail="repo:acme/payments:ref:refs/heads/main" /><RemediationStep number="02" title="Remove wildcard secret access" detail="secretsmanager:GetSecretValue on 1 resource" /><RemediationStep number="03" title="Re-run path validation" detail="Confirm reachability is gone and no controls regressed" /></div></div><div className="panel assumptions-panel"><PanelHeader title="Assumptions & gaps" subtitle="What the model could not prove" /><div className="assumption"><Info size={15} /><span>Runner compromise is modeled as an initial access event.</span></div><div className="assumption"><Info size={15} /><span>Secret rotation status is not visible in the read-only export.</span></div><div className="assumption warning"><AlertCircle size={15} /><span>CloudTrail data source is 2 hours behind.</span></div></div></section></div>
}

function AttackGraph({ path }: { path: Path }) {
  return <div className="attack-graph"><div className="graph-legend"><span><i className="graph-node-dot red" />Entry point</span><span><i className="graph-node-dot purple" />Identity hop</span><span><i className="graph-node-dot amber" />Permission</span><span><i className="graph-node-dot green" />High-value asset</span></div><div className="graph-canvas"><div className="graph-line line-one" /><div className="graph-line line-two" /><div className="graph-line line-three" /><GraphNode x="entry" type="red" icon={<Globe2 size={18} />} label={path.entry} meta="Public · GitHub OIDC" /><GraphNode x="hop" type="purple" icon={<KeyRound size={18} />} label="build-role-prod" meta="AssumeRole · trust policy" /><GraphNode x="permission" type="amber" icon={<LockKeyhole size={18} />} label="secretsmanager:*" meta="Wildcard permission" /><GraphNode x="asset" type="green" icon={<Database size={18} />} label={path.asset} meta={path.assetType} /></div><div className="graph-footnote"><CheckCircle2 size={14} /> 4-hop route confirmed by deterministic reachability rules <span>·</span> Evidence freshness: 9 min</div></div>
}

function GraphNode({ x, type, icon, label, meta }: { x: string; type: string; icon: ReactNode; label: string; meta: string }) {
  return <div className={`graph-node node-${x}`}><div className={`node-icon ${type}`}>{icon}</div><strong>{label}</strong><span>{meta}</span></div>
}

function EvidenceList({ path }: { path: Path }) {
  return <div className="evidence-list"><EvidenceItem type="entry" title="Internet-facing identity provider" detail={`${path.entry} accepts tokens from any repository in the organization.`} /><EvidenceItem type="identity" title="Trust relationship is too broad" detail="Condition does not constrain repository, branch, or environment claims." /><EvidenceItem type="permission" title="Wildcard permission reaches secrets" detail="build-role-prod has secretsmanager:GetSecretValue on arn:aws:secretsmanager:*:*:secret:*" /><EvidenceItem type="asset" title="Asset is business critical" detail={`${path.asset} is tagged critical=true and owned by ${path.owner}.`} /></div>
}

function EvidenceItem({ type, title, detail }: { type: string; title: string; detail: string }) {
  return <div className="evidence-item"><span className={`evidence-marker ${type}`}><Check size={13} /></span><div><strong>{title}</strong><p>{detail}</p><button className="evidence-link">View source <ExternalLink size={12} /></button></div></div>
}

function RemediationStep({ number, title, detail }: { number: string; title: string; detail: string }) {
  return <div className="remediation-step"><span>{number}</span><div><strong>{title}</strong><p>{detail}</p></div><CheckCircle2 size={17} /></div>
}

function Findings({ onOpenPath }: { onOpenPath: (id: string) => void }) {
  return <div className="page-stack"><section className="page-heading heading-with-actions"><div><div className="eyebrow"><ShieldAlert size={14} />Signal review</div><h1>Findings</h1><p>Every signal is connected to an asset, a path, and a confidence score.</p></div><div className="heading-actions"><button className="button button-secondary"><Download size={15} /> Export CSV</button><button className="button button-primary"><Plus size={16} /> Create rule</button></div></section><div className="filter-bar"><div className="filter-chip active">All findings <span>38</span></div><div className="filter-chip">Critical <span>6</span></div><div className="filter-chip">Open <span>31</span></div><div className="filter-chip">AI hypotheses <span>12</span></div><div className="filter-spacer" /><div className="compact-search"><Search size={14} /><input placeholder="Filter findings" /></div></div><section className="panel findings-panel"><div className="findings-table-head"><span>Finding</span><span>Severity</span><span>Confidence</span><span>Linked path</span><span>Status</span><span /></div>{findings.map((finding) => <button key={finding.id} className="findings-table-row" onClick={() => onOpenPath(finding.path.includes('Vendor') ? 'path-s3-014' : finding.path.includes('web pod') ? 'path-net-007' : 'path-iam-001')}><div className="finding-title"><span className="finding-id">{finding.id}</span><div><strong>{finding.title}</strong><span>{finding.source} · {finding.asset}</span></div></div><span className={`risk-pill ${finding.severity.toLowerCase()}`}>{finding.severity}</span><div className="confidence-cell"><div className="confidence-track"><span style={{ width: `${finding.confidence}%` }} /></div><strong>{finding.confidence}%</strong></div><span className="linked-path">{finding.path}</span><span className={`status-pill ${finding.status === 'Open' ? 'open' : 'review'}`}>{finding.status}</span><ChevronRight size={15} /></button>)}<div className="table-pagination"><span>Showing <strong>1–5</strong> of 38 findings</span><div><button><ArrowLeft size={14} /></button><button className="current">1</button><button>2</button><button>3</button><button><ArrowRight size={14} /></button></div></div></section></div>
}

function Validation({ onRunAnalysis, isAnalyzing }: { onRunAnalysis: () => void; isAnalyzing: boolean }) {
  return <div className="page-stack"><section className="page-heading heading-with-actions"><div><div className="eyebrow"><FileCheck2 size={14} />Change assurance</div><h1>Validation</h1><p>Prove a proposed fix actually reduces risk — and did not create a new path.</p></div><div className="heading-actions"><button className="button button-secondary"><Download size={15} /> Export report</button><button className="button button-primary" onClick={onRunAnalysis} disabled={isAnalyzing}><RefreshCw size={15} className={isAnalyzing ? 'spin' : ''} /> {isAnalyzing ? 'Running…' : 'Run validation'}</button></div></section><section className="validation-hero"><div className="validation-hero-icon"><CheckCircle2 size={25} /></div><div><span className="eyebrow">Latest validation run · 9 minutes ago</span><h2>Risk reduced by 18.6%</h2><p>2 paths broken · 0 regressions detected · 41 controls re-evaluated</p></div><div className="validation-score"><span>Post-change score</span><strong>74.2</strong><small>from 91.2</small></div></section><section className="validation-grid"><div className="panel validation-timeline"><PanelHeader title="Validation history" subtitle="Before-and-after evidence for every change" /><TimelineItem state="success" title="S3 bucket encryption enabled" detail="customer-exports-prod · 3 controls passed" time="Today, 10:18 AM" score="−7.4" /><TimelineItem state="success" title="Vendor trust narrowed" detail="vendor-support role · path broken" time="Today, 09:42 AM" score="−11.2" /><TimelineItem state="warning" title="Security group rule updated" detail="admin-api.internal · 1 follow-up recommended" time="Yesterday, 4:26 PM" score="−2.1" /><TimelineItem state="neutral" title="Baseline environment scan" detail="AWS production · 12,842 resources" time="Oct 22, 2026" score="—" /></div><div className="panel validation-side"><PanelHeader title="Control health" subtitle="Regression signals from latest run" /><ControlHealth label="Identity controls" value="98%" status="healthy" /><ControlHealth label="Network controls" value="91%" status="healthy" /><ControlHealth label="Data protection" value="88%" status="watch" /><ControlHealth label="Logging & detection" value="96%" status="healthy" /><div className="validation-note"><Info size={14} /><span>Validation is read-only. CloudSentinel never applies changes to your cloud accounts.</span></div></div></section></div>
}

function TimelineItem({ state, title, detail, time, score }: { state: string; title: string; detail: string; time: string; score: string }) {
  return <div className="timeline-item"><span className={`timeline-marker ${state}`}>{state === 'success' ? <Check size={13} /> : state === 'warning' ? <AlertCircle size={13} /> : <CircleDot size={13} />}</span><div><strong>{title}</strong><span>{detail}</span><time>{time}</time></div><b className={score.startsWith('−') ? 'score-good' : ''}>{score}</b></div>
}

function ControlHealth({ label, value, status }: { label: string; value: string; status: string }) {
  return <div className="control-health"><div><span>{label}</span><strong>{value}</strong></div><div className="health-track"><span className={status} style={{ width: value }} /></div><em className={status}>{status === 'watch' ? 'Watch' : 'Healthy'}</em></div>
}

function Regressions({ onToast }: { onToast: (message: string) => void }) {
  return <div className="page-stack"><section className="page-heading heading-with-actions"><div><div className="eyebrow"><RefreshCw size={14} />Guardrails</div><h1>Regression tests</h1><p>Turn confirmed paths into reusable checks for every infrastructure change.</p></div><div className="heading-actions"><button className="button button-secondary"><Code2 size={15} /> View API</button><button className="button button-primary" onClick={() => onToast('New regression test template created')}><Plus size={16} /> New test</button></div></section><section className="regression-summary"><SummaryStat label="Active tests" value="24" helper="across 3 environments" /><SummaryStat label="Pass rate" value="98.4%" helper="last 30 days" /><SummaryStat label="Blocked deploys" value="7" helper="saved an estimated 42h" /><SummaryStat label="Coverage" value="81%" helper="of confirmed paths" /></section><section className="panel regression-panel"><div className="regression-table-head"><span>Test</span><span>Scope</span><span>Last run</span><span>Pass rate</span><span>Status</span><span /></div><RegressionRow name="No public CI role can read prod secrets" id="REG-0024" scope="AWS production · IAM" last="9 min ago" rate="100%" status="Passing" /><RegressionRow name="Vendor roles require external IDs" id="REG-0023" scope="AWS analytics · Trust" last="24 min ago" rate="100%" status="Passing" /><RegressionRow name="Public workloads cannot reach admin plane" id="REG-0022" scope="EKS production · Network" last="1 hr ago" rate="96%" status="Review" /><RegressionRow name="Critical buckets must be encrypted" id="REG-0021" scope="AWS production · S3" last="3 hrs ago" rate="100%" status="Passing" /><RegressionRow name="OIDC trust claims stay repository-scoped" id="REG-0020" scope="GitHub · Identity" last="Yesterday" rate="98%" status="Passing" /></section></div>
}

function SummaryStat({ label, value, helper }: { label: string; value: string; helper: string }) {
  return <div className="summary-stat"><span>{label}</span><strong>{value}</strong><small>{helper}</small></div>
}

function RegressionRow({ name, id, scope, last, rate, status }: { name: string; id: string; scope: string; last: string; rate: string; status: string }) {
  return <button className="regression-row"><div className="regression-title"><span className="test-icon"><Check size={14} /></span><div><strong>{name}</strong><span>{id}</span></div></div><span>{scope}</span><span>{last}</span><span className="pass-rate">{rate}</span><span className={`status-pill ${status === 'Passing' ? 'passing' : 'review'}`}>{status}</span><ChevronRight size={15} /></button>
}

function Assets({ onToast }: { onToast: (message: string) => void }) {
  return <div className="page-stack"><section className="page-heading heading-with-actions"><div><div className="eyebrow"><Network size={14} />Environment graph</div><h1>Assets & graph</h1><p>A living inventory of identities, resources, and the relationships between them.</p></div><div className="heading-actions"><button className="button button-secondary" onClick={() => onToast('Graph export prepared')}><Download size={15} /> Export graph</button><button className="button button-primary" onClick={() => onToast('Read-only connection wizard opened')}><Plus size={16} /> Connect source</button></div></section><section className="asset-overview-grid"><div className="panel asset-count-panel"><PanelHeader title="Inventory" subtitle="Across connected environments" /><div className="inventory-grid"><InventoryCard icon={<Users size={17} />} value="2,418" label="Identities" color="purple" /><InventoryCard icon={<Cloud size={17} />} value="6,903" label="Resources" color="blue" /><InventoryCard icon={<Network size={17} />} value="1,884" label="Relationships" color="green" /><InventoryCard icon={<LockKeyhole size={17} />} value="137" label="High-value assets" color="amber" /></div></div><div className="panel source-panel"><PanelHeader title="Connected sources" subtitle="Read-only collection status" /><SourceRow icon={<Cloud size={16} />} name="AWS production" detail="12,842 resources · 9 min ago" status="Healthy" /><SourceRow icon={<GitBranch size={16} />} name="GitHub organization" detail="42 repos · 12 min ago" status="Healthy" /><SourceRow icon={<Network size={16} />} name="Kubernetes clusters" detail="3 clusters · 18 min ago" status="Watch" /></div></section><section className="panel graph-overview-panel"><PanelHeader title="Relationship graph" subtitle="Click a cluster to inspect its reachable assets" action="Open full graph" /><div className="mini-graph"><div className="cluster cluster-left"><span className="cluster-icon purple"><Users size={21} /></span><strong>Identities</strong><small>2,418 nodes</small></div><div className="mini-connector one" /><div className="cluster cluster-center"><span className="cluster-icon amber"><KeyRound size={21} /></span><strong>Permissions</strong><small>4,902 edges</small></div><div className="mini-connector two" /><div className="cluster cluster-right"><span className="cluster-icon green"><Database size={21} /></span><strong>Resources</strong><small>6,903 nodes</small></div><div className="mini-graph-note"><Sparkles size={14} /> AI layer has evaluated 18,420 possible reachability chains</div></div></section></div>
}

function InventoryCard({ icon, value, label, color }: { icon: ReactNode; value: string; label: string; color: string }) {
  return <div className="inventory-card"><span className={`inventory-icon ${color}`}>{icon}</span><strong>{value}</strong><span>{label}</span></div>
}

function SourceRow({ icon, name, detail, status }: { icon: ReactNode; name: string; detail: string; status: string }) {
  return <div className="source-row"><span className="source-icon">{icon}</span><div><strong>{name}</strong><span>{detail}</span></div><span className={`source-status ${status === 'Healthy' ? 'healthy' : 'watch'}`}><i />{status}</span></div>
}

function ActivityView() {
  const activities = [
    ['Analysis completed', '3 attack paths confirmed across AWS production', '9 min ago', 'purple'],
    ['Finding status changed', 'FND-2045 moved from Open to In review', '24 min ago', 'amber'],
    ['Remediation validated', 'customer-exports-prod encryption control passed', '24 min ago', 'green'],
    ['Source connected', 'AWS production read-only integration refreshed', '3 hrs ago', 'blue'],
    ['Regression test created', 'REG-0024 created from FND-2048', 'Yesterday', 'purple'],
    ['Team member added', 'Priya Shah joined the Acme Cloud workspace', 'Oct 22, 2026', 'blue'],
  ]
  return <div className="page-stack"><section className="page-heading"><div><div className="eyebrow"><Activity size={14} />Audit trail</div><h1>Activity log</h1><p>A complete, tenant-scoped record of decisions, changes, and analysis runs.</p></div></section><section className="panel activity-log-panel"><div className="activity-log-toolbar"><div className="filter-chip active">All activity</div><div className="filter-chip">Analysis runs</div><div className="filter-chip">Remediation</div><div className="filter-chip">Access changes</div><div className="filter-spacer" /><div className="compact-search"><Search size={14} /><input placeholder="Search log" /></div></div><div className="activity-log-list">{activities.map(([title, detail, time, color]) => <div className="log-row" key={`${title}-${time}`}><span className={`log-icon ${color}`}>{title === 'Analysis completed' ? <Sparkles size={15} /> : title === 'Remediation validated' ? <Check size={15} /> : title === 'Source connected' ? <CloudCog size={15} /> : <Activity size={15} />}</span><div><strong>{title}</strong><span>{detail}</span></div><time>{time}</time><button className="icon-button small" aria-label="Open activity"><ExternalLink size={14} /></button></div>)}</div></section></div>
}

function Settings({ onToast }: { onToast: (message: string) => void }) {
  return <div className="page-stack"><section className="page-heading"><div><div className="eyebrow"><Settings2 size={14} />Workspace controls</div><h1>Settings</h1><p>Configure how CloudSentinel connects, reasons, and keeps your security data safe.</p></div></section><div className="settings-layout"><div className="settings-nav"><button className="settings-nav-item active"><Cloud size={15} /> Connections</button><button className="settings-nav-item"><Users size={15} /> Team & access</button><button className="settings-nav-item"><Shield size={15} /> Security policy</button><button className="settings-nav-item"><SlidersHorizontal size={15} /> Analysis preferences</button><button className="settings-nav-item"><FileCheck2 size={15} /> Audit & retention</button></div><div className="settings-content"><SettingsSection title="Connected cloud sources" description="CloudSentinel only reads configuration metadata. No write permissions are required."><SettingRow icon={<Cloud size={17} />} title="AWS production" detail="Read-only role · 12,842 resources · synced 9 min ago" action="Manage" onClick={() => onToast('AWS connection settings opened')} status="Connected" /><SettingRow icon={<GitBranch size={17} />} title="GitHub organization" detail="OIDC and repository metadata · synced 12 min ago" action="Manage" onClick={() => onToast('GitHub connection settings opened')} status="Connected" /><button className="add-connection" onClick={() => onToast('Connection wizard opened')}><Plus size={15} /> Connect another source</button></SettingsSection><SettingsSection title="AI-assisted threat modeling" description="Use AI to generate hypotheses, then validate every claim with deterministic graph rules."><ToggleRow title="Generate attack hypotheses" detail="Suggest new paths from observed configuration combinations" checked /><ToggleRow title="Include evidence explanations" detail="Show the source configuration behind each claim" checked /><ToggleRow title="Safe simulation drafts" detail="Create bounded test cases without executing them" checked /></SettingsSection><SettingsSection title="Workspace security" description="Tenant isolation and access controls are enforced for every analysis run."><SettingRow icon={<LockKeyhole size={17} />} title="SSO enforcement" detail="Optional · 2 identity providers configured" action="Configure" onClick={() => onToast('SSO configuration opened')} status="Optional" /><SettingRow icon={<KeyRound size={17} />} title="Credential handling" detail="Secrets are never stored in the relationship graph" action="View policy" onClick={() => onToast('Credential handling policy opened')} status="Protected" /></SettingsSection></div></div></div>
}

function SettingsSection({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return <section className="panel settings-section"><div className="settings-section-heading"><div><h2>{title}</h2><p>{description}</p></div></div><div className="settings-rows">{children}</div></section>
}

function SettingRow({ icon, title, detail, action, onClick, status }: { icon: ReactNode; title: string; detail: string; action: string; onClick: () => void; status: string }) {
  return <div className="setting-row"><span className="setting-icon">{icon}</span><div><strong>{title}</strong><span>{detail}</span></div><span className={`setting-status ${status === 'Connected' || status === 'Protected' ? 'good' : ''}`}><i />{status}</span><button className="text-button" onClick={onClick}>{action}<ChevronRight size={14} /></button></div>
}

function ToggleRow({ title, detail, checked }: { title: string; detail: string; checked: boolean }) {
  return <div className="setting-row toggle-row"><div><strong>{title}</strong><span>{detail}</span></div><button className={`toggle ${checked ? 'checked' : ''}`} aria-label={`${title} ${checked ? 'enabled' : 'disabled'}`}><span /></button></div>
}

export default App
