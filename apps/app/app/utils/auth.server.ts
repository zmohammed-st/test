import { type Connection, type User } from '@prisma/client'
import { getUtmParams } from '@repo/analytics'
import {
	canUserLogin,
	getPasswordHash,
	type ProviderUser,
	verifyUserPassword,
	providers,
} from '@repo/auth'

import { downloadFile } from '@repo/common'
import { prisma } from '@repo/database'
import { getClientIp } from '@repo/security'
import { Authenticator } from 'remix-auth'
import { ssoAuthService } from './sso/auth.server.ts'
import { uploadProfileImage } from './storage.server.ts'
import { getUserAgent } from './user-agent.server.ts'

export { canUserLogin }

export const SESSION_EXPIRATION_TIME_SHORT = 1000 * 60 * 60 * 24 // 24 hours (default)
export const SESSION_EXPIRATION_TIME_LONG = 1000 * 60 * 60 * 24 * 30 // 30 days (remember me)
export const getSessionExpirationDate = (remember = false) =>
	new Date(
		Date.now() +
			(remember ? SESSION_EXPIRATION_TIME_LONG : SESSION_EXPIRATION_TIME_SHORT),
	)

/**
 * Extract IP address and user agent from request for session tracking
 */
function getSessionMetadata(request?: Request) {
	if (!request) return { ipAddress: null, userAgent: null }
	return {
		ipAddress: getClientIp(request),
		userAgent: getUserAgent(request),
	}
}

export const authenticator = new Authenticator<ProviderUser>()

// Register existing OAuth providers (GitHub, Google, etc.)
for (const [providerName, provider] of Object.entries(providers)) {
	const strategy = provider.getAuthStrategy()
	if (strategy) {
		authenticator.use(strategy, providerName)
	}
}

/**
 * Get or register an SSO strategy for an organization
 * This creates dynamic strategies based on organization SSO configuration
 */
export async function getSSOStrategy(organizationId: string) {
	const strategyName = `sso-${organizationId}`

	// Check if strategy is already registered
	try {
		// Try to get the existing strategy - this will throw if not found
		const existingStrategy = (authenticator as any)._strategies.get(
			strategyName,
		)
		if (existingStrategy) {
			return strategyName
		}
	} catch {
		// Strategy doesn't exist, we'll create it below
	}

	// Get the SSO strategy from the service
	const strategy = await ssoAuthService.getStrategy(organizationId)
	if (!strategy) {
		return null
	}

	// Register the strategy with the authenticator
	authenticator.use(strategy, strategyName)

	return strategyName
}

export async function login({
	username,
	password,
	request,
	remember = false,
}: {
	username: string
	password: string
	request?: Request
	remember?: boolean
}) {
	// Try to find user by username first, then by email if it looks like an email
	let user = null

	if (username.includes('@')) {
		// Looks like an email, try email first
		user = await verifyUserPassword({ email: username }, password)
		if (!user) {
			// If email fails, try as username (in case someone has @ in their username)
			user = await verifyUserPassword({ username }, password)
		}
	} else {
		// Looks like a username, try username first
		user = await verifyUserPassword({ username }, password)
		if (!user) {
			// If username fails, try as email (in case it's a short email)
			user = await verifyUserPassword({ email: username }, password)
		}
	}

	if (!user) return null

	const canLogin = await canUserLogin(user.id)
	if (!canLogin) return null

	const { ipAddress, userAgent } = getSessionMetadata(request)

	const session = await prisma.session.create({
		select: { id: true, expirationDate: true, userId: true },
		data: {
			expirationDate: getSessionExpirationDate(remember),
			ipAddress,
			userAgent,
			userId: user.id,
		},
	})
	return session
}

export async function resetUserPassword({
	username,
	password,
}: {
	username: User['username']
	password: string
}) {
	const hashedPassword = await getPasswordHash(password)
	return prisma.user.update({
		where: { username },
		data: {
			password: {
				update: {
					hash: hashedPassword,
				},
			},
		},
	})
}

export async function signup({
	email,
	username,
	password,
	name,
	request,
}: {
	email: User['email']
	username: User['username']
	name: User['name']
	password: string
	request?: Request
}) {
	const hashedPassword = await getPasswordHash(password)

	// Get UTM parameters from cookies if request is provided
	const utmParams = request ? await getUtmParams(request) : null

	const { ipAddress, userAgent } = getSessionMetadata(request)

	const session = await prisma.session.create({
		data: {
			expirationDate: getSessionExpirationDate(),
			ipAddress,
			userAgent,
			user: {
				create: {
					email: email.toLowerCase(),
					username: username.toLowerCase(),
					name,
					roles: { connect: { name: 'user' } },
					password: {
						create: {
							hash: hashedPassword,
						},
					},
					// Add UTM source if available
					...(utmParams && {
						utmSource: {
							create: {
								source: utmParams.source,
								medium: utmParams.medium,
								campaign: utmParams.campaign,
								term: utmParams.term,
								content: utmParams.content,
								referrer: utmParams.referrer,
							},
						},
					}),
				},
			},
		},
		select: { id: true, expirationDate: true, userId: true },
	})

	return session
}

export async function signupWithConnection({
	email,
	username,
	name,
	providerId,
	providerName,
	imageUrl,
	request,
}: {
	email: User['email']
	username: User['username']
	name: User['name']
	providerId: Connection['providerId']
	providerName: Connection['providerName']
	imageUrl?: string
	request?: Request
}) {
	const user = await prisma.user.create({
		data: {
			email: email.toLowerCase(),
			username: username.toLowerCase(),
			name,
			roles: { connect: { name: 'user' } },
			connections: { create: { providerId, providerName } },
		},
		select: { id: true },
	})

	if (imageUrl) {
		const imageFile = await downloadFile(imageUrl)
		await prisma.user.update({
			where: { id: user.id },
			data: {
				image: {
					create: {
						objectKey: await uploadProfileImage(user.id, imageFile),
					},
				},
			},
		})
	}

	// Create and return the session
	const { ipAddress, userAgent } = getSessionMetadata(request)

	const session = await prisma.session.create({
		data: {
			expirationDate: getSessionExpirationDate(),
			userId: user.id,
			ipAddress,
			userAgent,
		},
		select: { id: true, expirationDate: true },
	})

	return session
}

/**
 * Create session for SSO authenticated user
 */
export async function loginWithSSO({
	user,
	_organizationId,
	request,
}: {
	user: User
	_organizationId: string
	request?: Request
}) {
	const canLogin = await canUserLogin(user.id)
	if (!canLogin) {
		throw new Error('User is banned and cannot login')
	}

	const { ipAddress, userAgent } = getSessionMetadata(request)

	const session = await prisma.session.create({
		select: { id: true, expirationDate: true, userId: true },
		data: {
			expirationDate: getSessionExpirationDate(),
			ipAddress,
			userAgent,
			userId: user.id,
		},
	})

	return session
}
