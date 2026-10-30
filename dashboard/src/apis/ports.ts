import type {
  AdminSession, Client, Component, ComponentFilter, Finding, FindingFilter, Host, Page, ScanConfig, Session, TrendFilter,
  TrendPoint, TriageStatus,
} from '@/types/models'

// Ports implemented by infrastructure (HTTP) and by fakes in tests.

export interface AuthRepository {
  login(username: string, password: string): Promise<Session>
  logout(): Promise<void>
  me(): Promise<Session>
  /** Returns how many other sessions were signed out. */
  changePassword(current: string, next: string): Promise<number>
  sessions(): Promise<AdminSession[]>
  revokeSession(id: number): Promise<void>
  /** Returns how many sessions were signed out. */
  revokeOtherSessions(): Promise<number>
}

export interface FindingsRepository {
  list(filter: FindingFilter): Promise<Page<Finding>>
  components(filter: ComponentFilter): Promise<Component[]>
  triage(id: number, status: TriageStatus, note: string): Promise<void>
  /** Triages every unresolved finding of a component; returns how many changed. */
  triageComponent(c: Pick<Component, 'hostId' | 'kind' | 'key'>, status: TriageStatus, note: string): Promise<number>
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
  /** Revokes the client's enroll tokens and returns a new one (shown once). */
  rotateEnrollToken(name: string): Promise<string>
  installInfo(): Promise<{ enabled: boolean, publicUrl: string, agentVersion: string }>
}

export interface TrendRepository {
  trend(filter: TrendFilter): Promise<TrendPoint[]>
}

export interface Repositories {
  auth: AuthRepository
  trend: TrendRepository
  findings: FindingsRepository
  hosts: HostsRepository
  clients: ClientsRepository
}
