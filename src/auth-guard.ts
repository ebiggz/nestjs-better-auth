import type {
	CanActivate,
	ContextType,
	ExecutionContext,
} from "@nestjs/common";
import {
	ForbiddenException,
	Inject,
	Injectable,
	UnauthorizedException,
} from "@nestjs/common";
import { ModuleRef, Reflector } from "@nestjs/core";
import type { getSession } from "better-auth/api";
import { fromNodeHeaders } from "better-auth/node";
import type { AuthModuleOptions } from "./auth-module-definition.ts";
import {
	AUTH_INSTANCE_NAME_KEY,
	DEFAULT_AUTH_INSTANCE_NAME,
	_authInstanceNames,
	getAuthOptionsToken,
} from "./symbols.ts";
import { getRequestFromContext } from "./utils.ts";

/**
 * Type representing a valid user session after authentication
 * Excludes null and undefined values from the session return type
 */
export type BaseUserSession = NonNullable<
	Awaited<ReturnType<ReturnType<typeof getSession>>>
>;

/**
 * Type representing a user session with plugin-aware type inference.
 *
 * Pass your auth instance type to get full type safety for plugin fields:
 *
 * @example
 * ```ts
 * const auth = betterAuth({ plugins: [username(), admin()] });
 *
 * @Get('me')
 * getMe(@Session() session: UserSession<typeof auth>) {
 *   session.user.username; // ✅ typed correctly
 * }
 * ```
 */
export type UserSession<T = unknown> = T extends {
	$Infer: { Session: infer S };
}
	? S
	: BaseUserSession & {
			user: BaseUserSession["user"] & {
				role?: string | string[];
			};
			session: BaseUserSession["session"] & {
				activeOrganizationId?: string;
			};
		};

const AuthErrorType = {
	UNAUTHORIZED: "UNAUTHORIZED",
	FORBIDDEN: "FORBIDDEN",
} as const;

/**
 * Lazy-load WsException to make @nestjs/websockets an optional dependency
 */
// biome-ignore lint/suspicious/noExplicitAny: WsException type comes from optional @nestjs/websockets dependency
let WsException: any;
async function getWsException() {
	if (!WsException) {
		try {
			WsException = (await import("@nestjs/websockets")).WsException;
		} catch (_error) {
			throw new Error(
				"@nestjs/websockets is required for WebSocket support. Please install it: npm install @nestjs/websockets @nestjs/platform-socket.io",
			);
		}
	}
	return WsException;
}

const AuthContextErrorMap: Record<
	ContextType | "graphql",
	Record<keyof typeof AuthErrorType, (args?: unknown) => Promise<Error>>
> = {
	http: {
		UNAUTHORIZED: async (args) =>
			new UnauthorizedException(
				args ?? {
					code: "UNAUTHORIZED",
					message: "Unauthorized",
				},
			),
		FORBIDDEN: async (args) =>
			new ForbiddenException(
				args ?? {
					code: "FORBIDDEN",
					message: "Insufficient permissions",
				},
			),
	},
	graphql: {
		UNAUTHORIZED: async (args) => {
			if (args) return new UnauthorizedException(args);
			return new UnauthorizedException();
		},
		FORBIDDEN: async (args) => {
			if (args) return new ForbiddenException(args);
			return new ForbiddenException("Insufficient permissions");
		},
	},
	ws: {
		UNAUTHORIZED: async (args) => {
			const WsExceptionClass = await getWsException();
			return new WsExceptionClass(args ?? "UNAUTHORIZED");
		},
		FORBIDDEN: async (args) => {
			const WsExceptionClass = await getWsException();
			return new WsExceptionClass(args ?? "FORBIDDEN");
		},
	},
	rpc: {
		UNAUTHORIZED: async () => new Error("UNAUTHORIZED"),
		FORBIDDEN: async () => new Error("FORBIDDEN"),
	},
};

/**
 * NestJS guard that handles authentication for protected routes
 * Can be configured with @AllowAnonymous() or @OptionalAuth() decorators to modify authentication behavior
 * Supports multiple named auth instances via @UseAuth() decorator
 */
@Injectable()
export class AuthGuard implements CanActivate {
	constructor(
		@Inject(Reflector)
		private readonly reflector: Reflector,
		private readonly moduleRef: ModuleRef,
	) {}

	/**
	 * Resolves the auth options for the current execution context.
	 * Uses @UseAuth('name') metadata if present, otherwise falls back
	 * to the default instance or the only registered instance.
	 */
	private getAuthOptions(context: ExecutionContext): AuthModuleOptions {
		const instanceName = this.reflector.getAllAndOverride<string>(
			AUTH_INSTANCE_NAME_KEY,
			[context.getHandler(), context.getClass()],
		);

		const name = instanceName || DEFAULT_AUTH_INSTANCE_NAME;
		const token = getAuthOptionsToken(name);

		try {
			return this.moduleRef.get(token, { strict: false });
		} catch {
			// If explicitly named but not found, throw a clear error
			if (instanceName) {
				throw new Error(
					`Auth instance '${instanceName}' not found. Did you register it with AuthModule.forRoot({ name: '${instanceName}', ... })?`,
				);
			}

			// No explicit name and no default instance — try to find any single registered instance
			if (_authInstanceNames.size === 1) {
				const onlyName = _authInstanceNames.values().next().value as string;
				try {
					return this.moduleRef.get(getAuthOptionsToken(onlyName), {
						strict: false,
					});
				} catch {
					// fall through to error
				}
			}

			throw new Error(
				"No auth instance found. Register one with AuthModule.forRoot(...) or specify the instance with @UseAuth('name').",
			);
		}
	}

	/**
	 * Validates if the current request is authenticated
	 * Attaches session and user information to the request object
	 * Supports HTTP, GraphQL and WebSocket execution contexts
	 * @param context - The execution context of the current request
	 * @returns True if the request is authorized to proceed, throws an error otherwise
	 */
	async canActivate(context: ExecutionContext): Promise<boolean> {
		const options = this.getAuthOptions(context);
		const request = await getRequestFromContext(context);
		const session: UserSession | null = await options.auth.api.getSession({
			headers: fromNodeHeaders(
				request.headers || request?.handshake?.headers || [],
			),
		});

		request.session = session;
		request.user = session?.user ?? null; // useful for observability tools like Sentry

		const isPublic = this.reflector.getAllAndOverride<boolean>("PUBLIC", [
			context.getHandler(),
			context.getClass(),
		]);

		if (isPublic) return true;

		const isOptional = this.reflector.getAllAndOverride<boolean>("OPTIONAL", [
			context.getHandler(),
			context.getClass(),
		]);

		if (!session && isOptional) return true;

		const ctxType = context.getType();
		if (!session) throw await AuthContextErrorMap[ctxType].UNAUTHORIZED();

		const headers = fromNodeHeaders(
			request.headers || request?.handshake?.headers || [],
		);

		// Check @Roles() - user.role only (admin plugin)
		const requiredRoles = this.reflector.getAllAndOverride<string[]>("ROLES", [
			context.getHandler(),
			context.getClass(),
		]);

		if (requiredRoles && requiredRoles.length > 0) {
			const hasRole = this.checkUserRole(session, requiredRoles);
			if (!hasRole) throw await AuthContextErrorMap[ctxType].FORBIDDEN();
		}

		// Check @OrgRoles() - organization member role only
		const requiredOrgRoles = this.reflector.getAllAndOverride<string[]>(
			"ORG_ROLES",
			[context.getHandler(), context.getClass()],
		);

		if (requiredOrgRoles && requiredOrgRoles.length > 0) {
			const hasOrgRole = await this.checkOrgRole(
				options,
				session,
				headers,
				requiredOrgRoles,
			);
			if (!hasOrgRole) throw await AuthContextErrorMap[ctxType].FORBIDDEN();
		}

		// Check @UserHasPermission() - permission-based access control
		const permissionCheck = this.reflector.getAllAndOverride<
			| {
					userId?: string;
					role?: string;
					permission?: Record<string, string[]>;
					permissions?: Record<string, string[]>;
			  }
			| undefined
		>("USER_HAS_PERMISSION", [context.getHandler(), context.getClass()]);

		if (permissionCheck) {
			const hasPermission = await this.checkUserPermission(
				options,
				session,
				headers,
				permissionCheck,
			);
			if (!hasPermission) throw await AuthContextErrorMap[ctxType].FORBIDDEN();
		}

		// Check @MemberHasPermission() - organization member permission-based access control
		const memberPermissionCheck = this.reflector.getAllAndOverride<
			| {
					permissions: Record<string, string[]>;
			  }
			| undefined
		>("MEMBER_HAS_PERMISSION", [context.getHandler(), context.getClass()]);

		if (memberPermissionCheck) {
			const hasMemberPermission = await this.checkMemberPermission(
				options,
				session,
				headers,
				memberPermissionCheck,
			);
			if (!hasMemberPermission)
				throw await AuthContextErrorMap[ctxType].FORBIDDEN();
		}

		return true;
	}

	/**
	 * Checks if a role value matches any of the required roles
	 * Handles both array and comma-separated string role formats
	 * @param role - The role value to check (string, array, or undefined)
	 * @param requiredRoles - Array of roles that grant access
	 * @returns True if the role matches any required role
	 */
	private matchesRequiredRole(
		role: string | string[] | undefined,
		requiredRoles: string[],
	): boolean {
		if (!role) return false;

		if (Array.isArray(role)) {
			return role.some((r) => requiredRoles.includes(r));
		}

		if (typeof role === "string") {
			return role.split(",").some((r) => requiredRoles.includes(r.trim()));
		}

		return false;
	}

	/**
	 * Fetches the user's role within an organization from the member table
	 * Uses Better Auth's organization plugin API if available
	 * @param headers - The request headers containing session cookies
	 * @returns The member's role in the organization, or undefined if not found
	 */
	private async getMemberRoleInOrganization(
		options: AuthModuleOptions,
		headers: Headers,
	): Promise<string | undefined> {
		// Better Auth organization plugin exposes getActiveMemberRole or getActiveMember API
		// biome-ignore lint/suspicious/noExplicitAny: Better Auth API types vary by plugin configuration
		const authApi = options.auth.api as any;

		// Try getActiveMemberRole first (most direct for our use case)
		if (typeof authApi.getActiveMemberRole === "function") {
			const result = await authApi.getActiveMemberRole({ headers });
			return result?.role;
		}

		// Fallback: try getActiveMember
		if (typeof authApi.getActiveMember === "function") {
			const member = await authApi.getActiveMember({ headers });
			return member?.role;
		}

		return undefined;
	}

	/**
	 * Checks if the user has any of the required roles in user.role only.
	 * Used by @Roles() decorator for system-level role checks (admin plugin).
	 * @param session - The user's session
	 * @param requiredRoles - Array of roles that grant access
	 * @returns True if user.role matches any required role
	 */
	private checkUserRole(
		session: UserSession,
		requiredRoles: string[],
	): boolean {
		return this.matchesRequiredRole(session.user.role, requiredRoles);
	}

	/**
	 * Checks if the user has any of the required roles in their organization.
	 * Used by @OrgRoles() decorator for organization-level role checks.
	 * Requires an active organization in the session.
	 * @param session - The user's session
	 * @param headers - The request headers for API calls
	 * @param requiredRoles - Array of roles that grant access
	 * @returns True if org member role matches any required role
	 */
	private async checkOrgRole(
		options: AuthModuleOptions,
		session: UserSession,
		headers: Headers,
		requiredRoles: string[],
	): Promise<boolean> {
		const activeOrgId = session.session?.activeOrganizationId;
		if (!activeOrgId) {
			return false;
		}

		try {
			const memberRole = await this.getMemberRoleInOrganization(options, headers);
			return this.matchesRequiredRole(memberRole, requiredRoles);
		} catch (error) {
			// Log error for debugging but return false to trigger 403 Forbidden
			// instead of letting the error propagate as a 500
			console.error("Organization plugin error:", error);
			return false;
		}
	}

	/**
	 * Checks if the user has the required permissions.
	 * Used by @UserHasPermission() decorator for permission-based access control.
	 * Calls Better Auth's userHasPermission API to verify permissions.
	 * @param session - The user's session
	 * @param headers - The request headers for API calls
	 * @param permissionCheck - The permission check options
	 * @returns True if user has the required permissions
	 */
	private async checkUserPermission(
		options: AuthModuleOptions,
		session: UserSession,
		headers: Headers,
		permissionCheck: {
			userId?: string;
			role?: string;
			permission?: Record<string, string[]>;
			permissions?: Record<string, string[]>;
		},
	): Promise<boolean> {
		try {
			// biome-ignore lint/suspicious/noExplicitAny: Better Auth API types vary by plugin configuration
			const authApi = options.auth.api as any;

			// Check if userHasPermission API is available
			if (typeof authApi.userHasPermission !== "function") {
				console.error(
					"userHasPermission API not available. Make sure access control is configured in Better Auth.",
				);
				return false;
			}

			// Build the request body
			const body: {
				userId?: string;
				role?: string;
				permissions?: Record<string, string[]>;
			} = {};

			// Use provided userId or default to current user's ID
			if (permissionCheck.userId) {
				body.userId = permissionCheck.userId;
			} else if (session.user.id) {
				body.userId = session.user.id;
			}

			// Add role if provided (server-only)
			if (permissionCheck.role) {
				body.role = permissionCheck.role;
			}

			// Better Auth expects the pluralized payload shape.
			if (permissionCheck.permission) {
				body.permissions = permissionCheck.permission;
			} else if (permissionCheck.permissions) {
				body.permissions = permissionCheck.permissions;
			}

			// Call the Better Auth userHasPermission API
			const result = await authApi.userHasPermission({
				body,
				headers,
			});
			if (result?.success) {
				return true;
			}

			return false;
		} catch (error) {
			// Log error for debugging but return false to trigger 403 Forbidden
			// instead of letting the error propagate as a 500
			console.error("Permission check error:", error);
			console.error(
				"Permission check body:",
				JSON.stringify(permissionCheck, null, 2),
			);
			return false;
		}
	}

	/**
	 * Checks if the organization member has the required permissions.
	 * Used by @MemberHasPermission() decorator for organization member permission-based access control.
	 * Calls Better Auth's organization plugin hasPermission API to verify permissions.
	 * Requires an active organization in the session.
	 * @param session - The user's session
	 * @param headers - The request headers for API calls
	 * @param permissionCheck - The permission check options
	 * @returns True if member has the required permissions
	 */
	private async checkMemberPermission(
		options: AuthModuleOptions,
		session: UserSession,
		headers: Headers,
		permissionCheck: {
			permissions: Record<string, string[]>;
		},
	): Promise<boolean> {
		// Require an active organization (like @OrgRoles)
		const activeOrgId = session.session?.activeOrganizationId;
		if (!activeOrgId) {
			return false;
		}

		try {
			// biome-ignore lint/suspicious/noExplicitAny: Better Auth API types vary by plugin configuration
			const authApi = options.auth.api as any;

			// Check if hasPermission API is available (organization plugin)
			if (typeof authApi.hasPermission !== "function") {
				console.error(
					"hasPermission API not available. Make sure organization plugin with access control is configured in Better Auth.",
				);
				return false;
			}

			// Build the request body - organization plugin only uses permissions
			const body: {
				permissions: Record<string, string[]>;
			} = {
				permissions: permissionCheck.permissions,
			};

			// Call the Better Auth organization plugin hasPermission API
			const result = await authApi.hasPermission({
				body,
				headers,
			});

			if (result?.success) {
				return true;
			}

			return false;
		} catch (error) {
			// Log error for debugging but return false to trigger 403 Forbidden
			// instead of letting the error propagate as a 500
			console.error("Member permission check error:", error);
			console.error(
				"Member permission check body:",
				JSON.stringify(permissionCheck, null, 2),
			);
			return false;
		}
	}
}
