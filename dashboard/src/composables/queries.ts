import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, type Ref } from 'vue'
import type { Component, ComponentFilter, FindingFilter, TrendFilter, TriageStatus } from '@/types/models'
import { useUseCases } from './useUseCases'

// vue-query wrappers around the use cases. Keys start with the resource name so
// mutations can invalidate everything derived from it.

export function useHosts(client: Ref<string | undefined>) {
  const uc = useUseCases()
  return useQuery({ queryKey: ['hosts', client], queryFn: () => uc.listHosts(client.value) })
}

export function useHostSoftware(id: Ref<number>) {
  const uc = useUseCases()
  return useQuery({ queryKey: ['hosts', 'software', id], queryFn: () => uc.hostSoftware(id.value) })
}

/** Installer settings; agentVersion is the latest agent central hands out. */
export function useInstallInfo() {
  const uc = useUseCases()
  return useQuery({ queryKey: ['install-info'], queryFn: () => uc.installInfo(), staleTime: 5 * 60_000 })
}

export function useClients() {
  const uc = useUseCases()
  return useQuery({ queryKey: ['clients'], queryFn: () => uc.listClients() })
}

/** Daily open critical/high for sparklines; small and slow-moving, so cached for 5 minutes. */
export function useTrend(filter: Ref<TrendFilter>) {
  const uc = useUseCases()
  return useQuery({
    queryKey: computed(() => ['trend', filter.value]),
    queryFn: () => uc.trend(filter.value),
    staleTime: 5 * 60_000,
  })
}

export function useComponents(filter: Ref<ComponentFilter>) {
  const uc = useUseCases()
  return useQuery({
    queryKey: computed(() => ['components', filter.value]),
    queryFn: () => uc.listComponents(filter.value),
    placeholderData: keepPreviousData,
  })
}

export function useFindings(filter: Ref<FindingFilter>) {
  const uc = useUseCases()
  return useQuery({
    queryKey: computed(() => ['findings', filter.value]),
    queryFn: () => uc.listFindings(filter.value),
    placeholderData: keepPreviousData,
  })
}

function useInvalidate() {
  const qc = useQueryClient()
  return (...keys: string[]) => Promise.all(keys.map((k) => qc.invalidateQueries({ queryKey: [k] })))
}

export function useTriage() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (v: { id: number, status: TriageStatus, note: string }) => uc.triageFinding(v.id, v.status, v.note),
    onSuccess: () => invalidate('findings', 'components', 'hosts', 'clients'),
  })
}

export function useTriageComponent() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (v: { component: Pick<Component, 'hostId' | 'kind' | 'key'>, status: TriageStatus, note: string }) =>
      uc.triageComponent(v.component, v.status, v.note),
    onSuccess: () => invalidate('findings', 'components', 'hosts', 'clients'),
  })
}

export function useRevokeHost() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (id: number) => uc.revokeHost(id),
    onSuccess: () => invalidate('hosts', 'findings', 'components', 'clients'),
  })
}

export function useDeleteHost() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (id: number) => uc.deleteHost(id),
    onSuccess: () => invalidate('hosts', 'install-hosts', 'findings', 'components', 'clients', 'trend'),
  })
}

export function useCreateClient() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (name: string) => uc.createClient(name),
    onSuccess: () => invalidate('clients'),
  })
}

export function useSaveScanConfig() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (v: { name: string, text: string }) => uc.saveScanConfig(v.name, v.text),
    onSuccess: () => invalidate('clients'),
  })
}

export function useAdminSessions() {
  const uc = useUseCases()
  return useQuery({ queryKey: ['sessions'], queryFn: () => uc.listSessions() })
}

export function useChangePassword() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (v: { current: string, next: string, confirm: string }) => uc.changePassword(v.current, v.next, v.confirm),
    onSuccess: () => invalidate('sessions'),
  })
}

export function useRevokeSession() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    /** id undefined = every other session. */
    mutationFn: async (id?: number) => {
      if (id === undefined) await uc.revokeOtherSessions()
      else await uc.revokeSession(id)
    },
    onSuccess: () => invalidate('sessions'),
  })
}

export function useDeleteClient() {
 const uc = useUseCases()
 const invalidate = useInvalidate()
 return useMutation({ mutationFn: (name: string) => uc.deleteClient(name), onSuccess: () => invalidate('clients', 'hosts', 'findings', 'components', 'trend') })
}
