import type { components } from '@/api/generated/schema'

export type ProblemDetails = components['schemas']['ProblemDetails']

const NON_JSON_DETAIL = 'The server returned a non-JSON error response.'

export class ApiProblemError extends Error {
  readonly problem: ProblemDetails

  constructor(problem: ProblemDetails) {
    super(problem.detail ?? problem.title)
    this.name = 'ApiProblemError'
    this.problem = problem
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

export async function normalizeApiProblem(
  response: Response,
  requestUrl?: string,
): Promise<ProblemDetails> {
  const fallback: ProblemDetails = {
    type: `/errors/http-${response.status}`,
    title: response.statusText || 'Request failed',
    status: response.status,
    detail: NON_JSON_DETAIL,
    instance: requestUrl,
  }
  const contentType = response.headers.get('Content-Type')?.toLowerCase()
  if (!contentType?.includes('json')) {
    return fallback
  }

  try {
    const body: unknown = await response.json()
    if (!isRecord(body)) {
      return fallback
    }

    return {
      type: optionalString(body.type) ?? fallback.type,
      title: optionalString(body.title) ?? fallback.title,
      status: typeof body.status === 'number' ? body.status : fallback.status,
      detail: optionalString(body.detail),
      instance: optionalString(body.instance) ?? requestUrl,
    }
  } catch {
    return fallback
  }
}
