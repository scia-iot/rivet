import assert from 'node:assert/strict'
import test from 'node:test'

import {
  validateProductionEnvironment,
} from './check_production_env.mjs'

const validEnvironment = {
  VITE_API_BASE_URL: '/api',
  VITE_AUTH_DISABLED: 'false',
  VITE_ENTRA_API_SCOPE:
    'api://22222222-2222-4222-8222-222222222222/access_as_user',
  VITE_ENTRA_CLIENT_ID: '11111111-1111-4111-8111-111111111111',
  VITE_ENTRA_TENANT_ID: '00000000-0000-4000-8000-000000000000',
}

test('accepts an authenticated same-origin production configuration', () => {
  assert.deepEqual(validateProductionEnvironment(validEnvironment), [])
})

test('reports missing field names without echoing values', () => {
  const failures = validateProductionEnvironment({
    ...validEnvironment,
    VITE_ENTRA_API_SCOPE: '',
    VITE_ENTRA_CLIENT_ID: '',
  })

  assert.deepEqual(failures, [
    'VITE_ENTRA_CLIENT_ID must be a UUID',
    'VITE_ENTRA_API_SCOPE must be configured',
  ])
})

test('rejects disabled authentication and external API bases', () => {
  const failures = validateProductionEnvironment({
    ...validEnvironment,
    VITE_API_BASE_URL: 'https://api.example.test',
    VITE_AUTH_DISABLED: 'true',
  })

  assert.deepEqual(failures, [
    'VITE_AUTH_DISABLED must be false',
    'VITE_API_BASE_URL must be /api',
  ])
})

test('rejects placeholders and invalid Entra identifiers', () => {
  const failures = validateProductionEnvironment({
    ...validEnvironment,
    VITE_ENTRA_API_SCOPE: 'api://<api-application-id>/access_as_user',
    VITE_ENTRA_CLIENT_ID: '<client-id>',
    VITE_ENTRA_TENANT_ID: 'common',
  })

  assert.deepEqual(failures, [
    'VITE_ENTRA_TENANT_ID must be a UUID',
    'VITE_ENTRA_CLIENT_ID must be a UUID',
    'VITE_ENTRA_API_SCOPE must be a concrete api:// or https:// scope',
  ])
})

test('does not accept inherited values outside the reviewed vocabulary', () => {
  const failures = validateProductionEnvironment({
    ...validEnvironment,
    AUTH_DISABLED: 'false',
    API_TOKEN: 'sensitive-value',
  })

  assert.deepEqual(failures, [])
  assert.equal(JSON.stringify(failures).includes('sensitive-value'), false)
})

test('rejects unreviewed browser variables without echoing values', () => {
  const sensitiveValue = 'must-not-reach-browser-output'
  const failures = validateProductionEnvironment({
    ...validEnvironment,
    VITE_ENTRA_CLIENT_SECRET: sensitiveValue,
  })

  assert.deepEqual(failures, [
    'VITE_ENTRA_CLIENT_SECRET is not allowed in production',
  ])
  assert.equal(
    JSON.stringify(failures).includes(sensitiveValue),
    false,
  )
})
