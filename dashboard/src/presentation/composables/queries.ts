import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, type Ref } from 'vue'
import type { Component, ComponentFilter, FindingFilter, TriageStatus } from '@/domain/models'
import { useUseCases } from './useUseCases'

// vue-query wrappers around the use cases. Keys start with the resource name so
// mutations can invalidate everything derived from it.

export function useHosts(client: Ref<string | undefined>) {
  const uc = useUseCases()
  return useQuery({ queryKey: ['hosts', client], queryFn: () => uc.listHosts(client.value) })
}

export function useClients() {
  const uc = useUseCases()
  return useQuery({ queryKey: ['clients'], queryFn: () => uc.listClients() })
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
