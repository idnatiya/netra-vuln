import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, type Ref } from 'vue'
import type { FindingFilter, TriageStatus } from '@/domain/models'
import { useUseCases } from './useUseCases'

// vue-query wrappers around the use cases. Keys start with the resource name so
// mutations can invalidate everything derived from it.

export function useOverview(client: Ref<string | undefined>) {
  const uc = useUseCases()
  return useQuery({ queryKey: ['overview', client], queryFn: () => uc.overview(client.value) })
}

export function useTrend(client: Ref<string | undefined>, days = 30) {
  const uc = useUseCases()
  return useQuery({ queryKey: ['trend', client, days], queryFn: () => uc.trend(client.value, days) })
}

export function useOldestCVEs(client: Ref<string | undefined>, limit = 10) {
  const uc = useUseCases()
  return useQuery({ queryKey: ['oldest', client, limit], queryFn: () => uc.oldestCVEs(client.value, limit) })
}

export function useDistribution() {
  const uc = useUseCases()
  return useQuery({ queryKey: ['distribution'], queryFn: () => uc.distribution() })
}

export function useHosts(client: Ref<string | undefined>) {
  const uc = useUseCases()
  return useQuery({ queryKey: ['hosts', client], queryFn: () => uc.listHosts(client.value) })
}

export function useClients() {
  const uc = useUseCases()
  return useQuery({ queryKey: ['clients'], queryFn: () => uc.listClients() })
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
    onSuccess: () => invalidate('findings', 'overview', 'hosts', 'oldest'),
  })
}

export function useRevokeHost() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (id: number) => uc.revokeHost(id),
    onSuccess: () => invalidate('hosts', 'overview', 'findings', 'trend', 'oldest', 'distribution', 'clients'),
  })
}

export function useCreateClient() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (name: string) => uc.createClient(name),
    onSuccess: () => invalidate('clients', 'overview'),
  })
}

export function useSaveScanConfig() {
  const uc = useUseCases()
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (v: { name: string, text: string }) => uc.saveScanConfig(v.name, v.text),
    onSuccess: () => invalidate('clients', 'overview'),
  })
}
