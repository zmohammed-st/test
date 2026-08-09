/**
 * Permission-based UI components for conditional rendering
 * Hide/show elements based on user's organization permissions
 */

import { type ReactNode } from 'react'
import { useHasPermission } from '#app/hooks/use-organization-permissions.ts'

interface PermissionGuardProps {
	children: ReactNode
	fallback?: ReactNode
}

interface NotePermissionGuardProps extends PermissionGuardProps {
	noteOwnerId?: string
	currentUserId?: string
}

export function CanEditNote({
	noteOwnerId,
	currentUserId,
	children,
	fallback = null,
}: NotePermissionGuardProps) {
	const hasPermission = useHasPermission()

	// Check if user can edit any note or if they own this specific note
	const canEdit =
		hasPermission('update:note:org') ||
		(hasPermission('update:note:own') && noteOwnerId === currentUserId)

	if (!canEdit) {
		return <>{fallback}</>
	}

	return <>{children}</>
}

export function CanDeleteNote({
	noteOwnerId,
	currentUserId,
	children,
	fallback = null,
}: NotePermissionGuardProps) {
	const hasPermission = useHasPermission()

	// Check if user can delete any note or if they own this specific note
	const canDelete =
		hasPermission('delete:note:org') ||
		(hasPermission('delete:note:own') && noteOwnerId === currentUserId)

	if (!canDelete) {
		return <>{fallback}</>
	}

	return <>{children}</>
}
