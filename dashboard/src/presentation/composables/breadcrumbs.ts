import { onUnmounted, ref, watchEffect } from 'vue'
import type { RouteLocationRaw } from 'vue-router'

export interface Crumb {
  label: string
  to?: RouteLocationRaw
}

/** Breadcrumbs shown in the layout header; a view sets them, the route title is the fallback. */
export const crumbs = ref<Crumb[] | null>(null)

/** Sets the header breadcrumbs while the calling view is mounted. */
export function useBreadcrumbs(get: () => Crumb[]) {
  watchEffect(() => (crumbs.value = get()))
  onUnmounted(() => (crumbs.value = null))
}
