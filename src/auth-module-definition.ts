import type { ModuleMetadata } from "@nestjs/common";
import type { Auth } from "./auth-module.ts";
import type {
	JsonBodyParserOptions,
	UrlencodedBodyParserOptions,
} from "./body-parser-options.ts";

export type AuthModuleJsonBodyParserOptions = JsonBodyParserOptions & {
	enabled?: boolean;
};

export type AuthModuleUrlencodedBodyParserOptions =
	UrlencodedBodyParserOptions & {
		enabled?: boolean;
	};

export type AuthModuleBodyParserOptions = {
	json?: AuthModuleJsonBodyParserOptions;
	urlencoded?: AuthModuleUrlencodedBodyParserOptions;
	/**
	 * When set to `true`, attaches the raw request buffer to `req.rawBody`.
	 *
	 * This is useful for webhook signature verification that requires the raw,
	 * unparsed request body.
	 *
	 * **Important:** Since this library disables NestJS's built-in body parser,
	 * NestJS's `rawBody: true` option in `NestFactory.create()` has no effect.
	 * Use this option instead.
	 *
	 * @default false
	 */
	rawBody?: boolean;
};

export type AuthModuleMiddleware = (
	// biome-ignore lint/suspicious/noExplicitAny: public middleware should not force an adapter-specific request type
	req: any,
	// biome-ignore lint/suspicious/noExplicitAny: public middleware should not force an adapter-specific response type
	res: any,
	next: (error?: unknown) => void,
) => void | Promise<void>;

export type AuthModuleOptions<A = Auth> = {
	auth: A;
	/**
	 * Optional name for this auth instance. Used for multi-instance setups
	 * where you need separate Better Auth instances (e.g., customer vs employee auth).
	 * When omitted, the instance is registered as the default.
	 */
	name?: string;
	disableTrustedOriginsCors?: boolean;
	/**
	 * @deprecated Use `bodyParser.json.enabled` and `bodyParser.urlencoded.enabled` instead.
	 */
	disableBodyParser?: boolean;
	/**
	 * @deprecated Use `bodyParser.rawBody` instead.
	 */
	enableRawBodyParser?: boolean;
	bodyParser?: AuthModuleBodyParserOptions;
	middleware?: AuthModuleMiddleware;
};

/**
 * Extra options that control module-level behavior (global registration, guards, controllers).
 */
export type AuthModuleExtras = {
	isGlobal?: boolean;
	disableGlobalAuthGuard?: boolean;
	disableControllers?: boolean;
};

/**
 * Combined options for AuthModule.forRoot() — includes both auth instance
 * options and module-level extras.
 */
export type AuthModuleForRootOptions<A = Auth> = AuthModuleOptions<A> &
	AuthModuleExtras;

/**
 * Options for AuthModule.forRootAsync() — supports async factory-based configuration.
 */
export type AuthModuleAsyncOptions = AuthModuleExtras & {
	/**
	 * Optional name for this auth instance. Used for multi-instance setups.
	 * When omitted, the instance is registered as the default.
	 */
	name?: string;
	imports?: ModuleMetadata["imports"];
	// biome-ignore lint/suspicious/noExplicitAny: factory args are injection-dependent
	useFactory: (
		// biome-ignore lint/suspicious/noExplicitAny: factory args are injection-dependent
		...args: any[]
	) => AuthModuleOptions | Promise<AuthModuleOptions>;
	// biome-ignore lint/suspicious/noExplicitAny: inject tokens can be any type
	inject?: any[];
};

/**
 * Injection token for the default auth instance options.
 * For named instances, use getAuthOptionsToken(name) from symbols.ts.
 */
export const MODULE_OPTIONS_TOKEN = Symbol("AUTH_MODULE_OPTIONS");

/**
 * @deprecated For backward compatibility — use AuthModuleForRootOptions type directly.
 */
export declare const OPTIONS_TYPE: AuthModuleForRootOptions;
/**
 * @deprecated For backward compatibility — use AuthModuleAsyncOptions type directly.
 */
export declare const ASYNC_OPTIONS_TYPE: AuthModuleAsyncOptions;
