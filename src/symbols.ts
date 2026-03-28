export const BEFORE_HOOK_KEY = Symbol("BEFORE_HOOK") as symbol;
export const AFTER_HOOK_KEY = Symbol("AFTER_HOOK") as symbol;
export const HOOK_KEY = Symbol("HOOK") as symbol;
export const AUTH_MODULE_OPTIONS_KEY = Symbol("AUTH_MODULE_OPTIONS") as symbol;

/**
 * Metadata key for the @UseAuth() decorator, specifying which auth instance
 * a controller or route handler should use.
 */
export const AUTH_INSTANCE_NAME_KEY = Symbol("AUTH_INSTANCE_NAME");

/**
 * The default auth instance name used when no explicit name is provided.
 */
export const DEFAULT_AUTH_INSTANCE_NAME = "default";

/**
 * Internal registry of registered auth instance names.
 * Used by AuthModule and AuthGuard to discover available instances.
 * @internal
 */
export const _authInstanceNames = new Set<string>();

/**
 * Returns the injection token for a named auth instance's options.
 * @param name - The instance name (defaults to the default instance)
 */
export function getAuthOptionsToken(
	name = DEFAULT_AUTH_INSTANCE_NAME,
): string {
	return `AUTH_MODULE_OPTIONS_${name}`;
}

/**
 * Returns the injection token for a named auth instance's AuthService.
 * @param name - The instance name (defaults to the default instance)
 */
export function getAuthServiceToken(
	name = DEFAULT_AUTH_INSTANCE_NAME,
): string {
	return `AUTH_SERVICE_${name}`;
}
