import type {
  Client, Component, ComponentFilter, Finding, FindingFilter, Host, Page, ScanConfig, Session, TriageStatus,
} from '@/domain/models'

// Ports implemented by infrastructure (HTTP) and by fakes in tests.

export interface AuthRepository {
  login(username: string, password: string): Promise<Session>
  logout(): Promise<void>
  me(): Promise<Session>
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
}

export interface Repositories {
  auth: AuthRepository
  findings: FindingsRepository
  hosts: HostsRepository
  clients: ClientsRepository
}
