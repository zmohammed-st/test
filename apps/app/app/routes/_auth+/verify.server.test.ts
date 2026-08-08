import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.hoisted(() => {
	process.env.SESSION_SECRET = 'test-session-secret'
	process.env.DATABASE_URL = 'file:./data.db'
})

import { prisma } from '@repo/database'
import {
	getCodeValidationStatus,
	isCodeValid,
	validateRequest,
} from './verify.server.tsx'

vi.mock('@repo/database', () => ({
	prisma: {
		verification: {
			findUnique: vi.fn() as any,
		},
	},
}))

const verifyTOTPMock = vi.hoisted(() => vi.fn())
const validateAndConsumeBackupCodeMock = vi.hoisted(() => vi.fn())

vi.mock('@repo/auth', () => ({
	verifySessionStorage: {
		getSession: vi.fn().mockResolvedValue({ get: () => undefined }),
		commitSession: vi.fn().mockResolvedValue(''),
		destroySession: vi.fn().mockResolvedValue(''),
	},
	generateTOTP: vi.fn(),
	verifyTOTP: verifyTOTPMock,
	validateAndConsumeBackupCode: validateAndConsumeBackupCodeMock,
	requireUserId: vi.fn(),
}))

vi.mock('@repo/common', () => ({
	getDomainUrl: vi.fn(() => 'http://localhost:3000'),
}))

vi.mock('@repo/common/toast', () => ({
	redirectWithToast: vi.fn(),
}))

vi.mock('@repo/email', () => ({
	EmailChangeNoticeEmail: vi.fn(() => null),
	sendEmail: vi.fn().mockResolvedValue({ status: 'success' }),
}))

vi.mock('../_app+/security.tsx', () => ({
	newEmailAddressSessionKey: 'newEmailAddress',
	twoFAVerificationType: '2fa',
	twoFAVerifyVerificationType: '2fa-verify',
}))

vi.mock('./login.server.ts', () => ({
	handleVerification: vi.fn(),
	shouldRequestTwoFA: vi.fn().mockResolvedValue(false),
}))

vi.mock('./onboarding.server.ts', () => ({
	handleVerification: vi.fn(),
}))

vi.mock('./reset-password.server.ts', () => ({
	handleVerification: vi.fn(),
}))

function mockVerification(value: any) {
	vi.mocked(prisma.verification.findUnique).mockResolvedValue(value)
}

describe('getCodeValidationStatus', () => {
	beforeEach(() => {
		vi.clearAllMocks()
	})

	it('returns "invalid" when no verification record exists', async () => {
		mockVerification(null)

		const status = await getCodeValidationStatus({
			code: 'ABCDEF',
			type: 'reset-password',
			target: 'user-1',
		})

		expect(status).toBe('invalid')
	})

	it('returns "expired" when expiresAt is in the past', async () => {
		mockVerification({
			algorithm: 'SHA-256',
			secret: 'secret',
			period: 600,
			charSet: 'ABC',
			expiresAt: new Date(Date.now() - 1000),
		})

		const status = await getCodeValidationStatus({
			code: 'ABCDEF',
			type: 'reset-password',
			target: 'user-1',
		})

		expect(status).toBe('expired')
		expect(verifyTOTPMock).not.toHaveBeenCalled()
	})

	it('returns "valid" when the code matches and is not expired', async () => {
		mockVerification({
			algorithm: 'SHA-256',
			secret: 'secret',
			period: 600,
			charSet: 'ABC',
			expiresAt: new Date(Date.now() + 60_000),
		})
		verifyTOTPMock.mockResolvedValue(true)

		const status = await getCodeValidationStatus({
			code: 'ABCDEF',
			type: 'reset-password',
			target: 'user-1',
		})

		expect(status).toBe('valid')
	})

	it('returns "invalid" when the code does not match (not expired)', async () => {
		mockVerification({
			algorithm: 'SHA-256',
			secret: 'secret',
			period: 600,
			charSet: 'ABC',
			expiresAt: new Date(Date.now() + 60_000),
		})
		verifyTOTPMock.mockResolvedValue(false)

		const status = await getCodeValidationStatus({
			code: 'WRONG1',
			type: 'reset-password',
			target: 'user-1',
		})

		expect(status).toBe('invalid')
	})

	it('treats a null expiresAt as non-expiring', async () => {
		mockVerification({
			algorithm: 'SHA-256',
			secret: 'secret',
			period: 600,
			charSet: 'ABC',
			expiresAt: null,
		})
		verifyTOTPMock.mockResolvedValue(true)

		const status = await getCodeValidationStatus({
			code: 'ABCDEF',
			type: 'reset-password',
			target: 'user-1',
		})

		expect(status).toBe('valid')
	})

	it('falls back to backup codes for 2fa verification', async () => {
		mockVerification({
			algorithm: 'SHA-256',
			secret: 'secret',
			period: 600,
			charSet: 'ABC',
			expiresAt: new Date(Date.now() + 60_000),
		})
		verifyTOTPMock.mockResolvedValue(false)
		validateAndConsumeBackupCodeMock.mockResolvedValue(true)

		const status = await getCodeValidationStatus({
			code: 'ABCD-1234',
			type: '2fa',
			target: 'user-1',
		})

		expect(status).toBe('valid')
		expect(validateAndConsumeBackupCodeMock).toHaveBeenCalledWith(
			'user-1',
			'ABCD-1234',
		)
	})
})

describe('isCodeValid', () => {
	beforeEach(() => {
		vi.clearAllMocks()
	})

	it('returns true for a valid code', async () => {
		mockVerification({
			algorithm: 'SHA-256',
			secret: 'secret',
			period: 600,
			charSet: 'ABC',
			expiresAt: new Date(Date.now() + 60_000),
		})
		verifyTOTPMock.mockResolvedValue(true)

		expect(
			await isCodeValid({
				code: 'ABCDEF',
				type: 'reset-password',
				target: 'user-1',
			}),
		).toBe(true)
	})

	it('returns false for an expired code (preserves boolean contract)', async () => {
		mockVerification({
			algorithm: 'SHA-256',
			secret: 'secret',
			period: 600,
			charSet: 'ABC',
			expiresAt: new Date(Date.now() - 1000),
		})

		expect(
			await isCodeValid({
				code: 'ABCDEF',
				type: 'reset-password',
				target: 'user-1',
			}),
		).toBe(false)
	})

	it('returns false for an invalid code', async () => {
		mockVerification(null)

		expect(
			await isCodeValid({
				code: 'ABCDEF',
				type: 'reset-password',
				target: 'user-1',
			}),
		).toBe(false)
	})
})

describe('validateRequest expired vs invalid messaging', () => {
	beforeEach(() => {
		vi.clearAllMocks()
	})

	function buildBody(code: string) {
		const body = new URLSearchParams()
		body.set('code', code)
		body.set('type', 'reset-password')
		body.set('target', 'user-1')
		return body
	}

	it('reports "This code has expired" for an expired reset-password code', async () => {
		mockVerification({
			algorithm: 'SHA-256',
			secret: 'secret',
			period: 600,
			charSet: 'ABC',
			expiresAt: new Date(Date.now() - 1000),
		})

		const result = await validateRequest(
			new Request('http://localhost:3000/verify'),
			buildBody('ABCDEF'),
		)
		const payload = (result as any).data
		const errors = payload?.result?.error?.code ?? []

		expect(errors).toContain('This code has expired. Please request a new one.')
	})

	it('reports "Invalid code" for a wrong reset-password code (not expired)', async () => {
		mockVerification({
			algorithm: 'SHA-256',
			secret: 'secret',
			period: 600,
			charSet: 'ABC',
			expiresAt: new Date(Date.now() + 60_000),
		})
		verifyTOTPMock.mockResolvedValue(false)

		const result = await validateRequest(
			new Request('http://localhost:3000/verify'),
			buildBody('WRONG1'),
		)
		const payload = (result as any).data
		const errors = payload?.result?.error?.code ?? []

		expect(errors).toContain('Invalid code')
		expect(errors).not.toContain(
			'This code has expired. Please request a new one.',
		)
	})

	it('reports "Invalid code" when no verification record exists', async () => {
		mockVerification(null)

		const result = await validateRequest(
			new Request('http://localhost:3000/verify'),
			buildBody('ABCDEF'),
		)
		const payload = (result as any).data
		const errors = payload?.result?.error?.code ?? []

		expect(errors).toContain('Invalid code')
	})
})
