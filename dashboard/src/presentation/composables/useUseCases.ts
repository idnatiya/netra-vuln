import { inject } from 'vue'
import type { UseCases } from '@/application/usecases'
import { UseCasesKey } from '@/di'

export function useUseCases(): UseCases {
  const uc = inject(UseCasesKey)
  if (!uc) throw new Error('use cases not provided')
  return uc
}
