import type {
  Client, CVEAge, Distribution, Finding, FindingFilter, Host, Overview, Page, ScanConfig, Session,
  TrendPoint, TriageStatus,
} from '@/domain/models'

// Ports implemented by infrastructure (HTTP) and by fakes in tests.

export interface AuthRepository {
  login(username: string, password: string): Promise<Session>
  logout(): Promise<void>
  me(): Promise<Session>
}

export interface StatsRepository {
  overview(client?: string): Promise<Overview>
  trend(client: string | undefined, days: number): Promise<TrendPoint[]>
  oldestCVEs(client: string | undefined, limit: number): Promise<CVEAge[]>
  distribution(): Promise<Distribution>
}

export interface FindingsRepository {
  list(filter: FindingFilter): Promise<Page<Finding>>
  triage(id: number, status: TriageStatus, note: string): Promise<void>
}

export interface HostsRepository {
  list(client?: string): Promise<Host[]>
  revoke(id: number): Promise<void>
}

export interface ClientsRepository {
  list(): Promise<Client[]>
  /** Returns the enroll token; it is shown exactly once. */
  create(name: string): Promise<string>
  setScanConfig(name: string, cfg: ScanConfig): Promise<ScanConfig>
  clearScanConfig(name: string): Promise<void>
}

export interface Repositories {
  auth: AuthRepository
  stats: StatsRepository
  findings: FindingsRepository
  hosts: HostsRepository
  clients: ClientsRepository
}
