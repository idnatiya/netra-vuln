import { createUseCases } from './usecases'
import { HttpClient } from './http'
import { createHttpRepositories } from './repositories'

let onUnauthorized = () => {}
export const api = createUseCases(createHttpRepositories(new HttpClient('/api/admin/v1', () => onUnauthorized())))
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler
}
