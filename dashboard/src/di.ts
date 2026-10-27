import type { InjectionKey } from 'vue'
import { createUseCases, type UseCases } from '@/application/usecases'
import { HttpClient } from '@/infrastructure/http'
import { createHttpRepositories } from '@/infrastructure/repositories'

// Composition root: wires infrastructure into the use cases the views consume.

export const UseCasesKey: InjectionKey<UseCases> = Symbol('usecases')

export function buildUseCases(onUnauthorized: () => void): UseCases {
  return createUseCases(createHttpRepositories(new HttpClient('/api/admin/v1', onUnauthorized)))
}
