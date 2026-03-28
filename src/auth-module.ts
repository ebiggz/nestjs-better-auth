import { Inject, Logger, Module } from "@nestjs/common";
import type {
	DynamicModule,
	MiddlewareConsumer,
	NestModule,
	OnModuleDestroy,
	OnModuleInit,
} from "@nestjs/common";
import {
	ApplicationConfig,
	DiscoveryModule,
	DiscoveryService,
	HttpAdapterHost,
	MetadataScanner,
	ModuleRef,
} from "@nestjs/core";
import { toNodeHandler } from "better-auth/node";
import { createAuthMiddleware } from "better-auth/api";
import type {
	Request as ExpressRequest,
	Response as ExpressResponse,
} from "express";
import {
	type AuthModuleAsyncOptions,
	type AuthModuleForRootOptions,
	type AuthModuleOptions,
	MODULE_OPTIONS_TOKEN,
} from "./auth-module-definition.ts";
import { AuthService } from "./auth-service.ts";
import { configureFastifyBodyParser } from "./fastify-body-parser.ts";
import {
	SkipBodyParsingMiddleware,
	getNodeRequest,
	getNodeResponse,
	handleFastifyTrustedOriginsCors,
	matchesBasePath,
	resolveBodyParserOptions,
} from "./middlewares.ts";
import {
	AFTER_HOOK_KEY,
	BEFORE_HOOK_KEY,
	DEFAULT_AUTH_INSTANCE_NAME,
	HOOK_KEY,
	_authInstanceNames,
	getAuthOptionsToken,
	getAuthServiceToken,
} from "./symbols.ts";
import { AuthGuard } from "./auth-guard.ts";
import { APP_GUARD } from "@nestjs/core";
import { normalizePath } from "@nestjs/common/utils/shared.utils.js";
import { mapToExcludeRoute } from "@nestjs/core/middleware/utils.js";

const HOOKS = [
	{ metadataKey: BEFORE_HOOK_KEY, hookType: "before" as const },
	{ metadataKey: AFTER_HOOK_KEY, hookType: "after" as const },
];

type AdapterRequest = ExpressRequest & {
	raw?: ExpressRequest;
	originalUrl?: string;
	url?: string;
	baseUrl?: string;
};

type AdapterResponse = ExpressResponse & {
	raw?: ExpressResponse;
};

// biome-ignore lint/suspicious/noExplicitAny: i don't want to cause issues/breaking changes between different ways of setting up better-auth and even versions
export type Auth = any;

interface ResolvedAuthInstance {
	name: string;
	options: AuthModuleOptions;
	basePath: string;
	disableControllers: boolean;
}

/**
 * NestJS module that integrates the Auth library with NestJS applications.
 * Provides authentication middleware, hooks, and exception handling.
 *
 * Supports multiple named Better Auth instances for multi-app auth scenarios.
 *
 * @example Single instance:
 * ```ts
 * AuthModule.forRoot({ auth })
 * ```
 *
 * @example Multiple instances:
 * ```ts
 * AuthModule.forRoot({ auth: customerAuth, name: 'customer' })
 * AuthModule.forRoot({ auth: employeeAuth, name: 'employee' })
 * ```
 */
@Module({
	imports: [DiscoveryModule],
})
export class AuthModule implements NestModule, OnModuleInit, OnModuleDestroy {
	/**
	 * Per-instance extras that can't be stored in the options token
	 * (because they're module-level concerns, not runtime options).
	 */
	private static readonly instanceExtras = new Map<
		string,
		{ disableControllers: boolean }
	>();

	private readonly logger = new Logger(AuthModule.name);
	private readonly instances = new Map<string, ResolvedAuthInstance>();
	private instancesResolved = false;

	constructor(
		@Inject(ApplicationConfig)
		private readonly applicationConfig: ApplicationConfig,
		@Inject(DiscoveryService)
		private readonly discoveryService: DiscoveryService,
		@Inject(MetadataScanner)
		private readonly metadataScanner: MetadataScanner,
		@Inject(HttpAdapterHost)
		private readonly adapter: HttpAdapterHost,
		@Inject(ModuleRef)
		private readonly moduleRef: ModuleRef,
	) {}

	/**
	 * Resolves all registered auth instances from the DI container.
	 * Called lazily (not in the constructor) because async providers
	 * (e.g. from forRootAsync) may not be instantiated yet at
	 * constructor time — ModuleRef.get() would throw silently.
	 * By the time configure() runs, all providers are guaranteed
	 * to be resolved.
	 */
	private resolveInstances(): void {
		if (this.instancesResolved) return;
		this.instancesResolved = true;

		for (const name of Array.from(_authInstanceNames)) {
			const isDefault = name === DEFAULT_AUTH_INSTANCE_NAME;
			let options: AuthModuleOptions | undefined;

			// For the default instance, try MODULE_OPTIONS_TOKEN (Symbol) first.
			// This is the same token the original ConfigurableModuleBuilder used,
			// and we register the factory directly under it for backward compat.
			if (isDefault) {
				try {
					options = this.moduleRef.get(MODULE_OPTIONS_TOKEN, { strict: false });
				} catch {
					// Symbol token not found, fall through to string token
				}
			}

			// Fall back to the string-based token (used for named instances,
			// or as a fallback for the default instance)
			if (!options) {
				const token = getAuthOptionsToken(name);
				try {
					options = this.moduleRef.get(token, { strict: false });
				} catch {
					continue; // Registered by a different application context
				}
			}

			const basePath = normalizePath(
				options!.auth.options.basePath ?? "/api/auth",
			);
			const extras = AuthModule.instanceExtras.get(name);

			this.instances.set(name, {
				name,
				options: options!,
				basePath,
				disableControllers: extras?.disableControllers ?? false,
			});

			// Add exclusion to global prefix for this instance's auth routes
			const globalPrefixOptions =
				this.applicationConfig.getGlobalPrefixOptions();
			this.applicationConfig.setGlobalPrefixOptions({
				exclude: [
					...(globalPrefixOptions.exclude ?? []),
					...mapToExcludeRoute([basePath, `${basePath}/*path`]),
				],
			});
		}
	}

	onModuleDestroy(): void {
		for (const name of Array.from(this.instances.keys())) {
			_authInstanceNames.delete(name);
			AuthModule.instanceExtras.delete(name);
		}
	}

	onModuleInit(): void {
		this.resolveInstances();

		const providers = this.discoveryService
			.getProviders()
			.filter(
				({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype),
			);

		if (providers.length === 0) return;

		for (const instance of Array.from(this.instances.values())) {
			if (instance.disableControllers) continue;

			// Prevent double hook initialization (can happen when multiple forRoot
			// calls for the same module class cause onModuleInit to fire more than once)
			const auth = instance.options.auth;
			if (auth._nestjsHooksInitialized) continue;
			auth._nestjsHooksInitialized = true;

			const hooksConfigured =
				typeof auth?.options?.hooks === "object";

			for (const provider of providers) {
				// Check if this hook targets this specific instance
				const hookTarget = Reflect.getMetadata(HOOK_KEY, provider.metatype!);
				// hookTarget is true (all instances) or a string (specific instance name)
				if (hookTarget !== true && hookTarget !== instance.name) continue;

				if (!hooksConfigured) {
					throw new Error(
						`Detected @Hook providers but Better Auth 'hooks' are not configured${this.instances.size > 1 ? ` for instance '${instance.name}'` : ""}. Add 'hooks: {}' to your betterAuth(...) options.`,
					);
				}

				const providerPrototype = Object.getPrototypeOf(provider.instance);
				const methods =
					this.metadataScanner.getAllMethodNames(providerPrototype);

				for (const method of methods) {
					const providerMethod = providerPrototype[method];
					this.setupHooks(
						providerMethod,
						provider.instance,
						instance.options,
					);
				}
			}
		}
	}

	configure(consumer: MiddlewareConsumer): void {
		this.resolveInstances();

		// Filter to instances that have controllers/middleware enabled
		// and haven't been configured yet (prevents double middleware setup
		// when multiple forRoot calls create separate module contexts)
		const activeInstances = Array.from(this.instances.values()).filter(
			(i) => !i.disableControllers && !i.options.auth._nestjsConfigured,
		);

		// Mark all active instances as configured
		for (const instance of activeInstances) {
			instance.options.auth._nestjsConfigured = true;
		}

		if (activeInstances.length === 0) return;

		const adapterType = this.adapter.httpAdapter.getType();

		// Collect all base paths for body parser skipping
		const allBasePaths = activeInstances.map((i) => i.basePath);

		// Use body parser options from the first active instance
		const firstInstance = activeInstances[0];
		const bodyParserOptions = resolveBodyParserOptions(firstInstance.options);

		// Handle deprecation warnings (once per deprecation type)
		if (
			activeInstances.some((i) => "disableBodyParser" in i.options)
		) {
			this.logger.warn(
				"`disableBodyParser` is deprecated. Use `bodyParser.json.enabled` and `bodyParser.urlencoded.enabled` instead.",
			);
		}

		if (
			activeInstances.some((i) => "enableRawBodyParser" in i.options)
		) {
			this.logger.warn(
				"`enableRawBodyParser` is deprecated. Use `bodyParser.rawBody` instead.",
			);
		}

		// Set up body parser skip middleware (Express only)
		if (adapterType !== "fastify") {
			consumer
				.apply(
					SkipBodyParsingMiddleware({
						basePaths: allBasePaths,
						bodyParser: bodyParserOptions,
					}),
				)
				.forRoutes("*path");
		}

		if (adapterType === "fastify") {
			configureFastifyBodyParser(this.adapter.httpAdapter, bodyParserOptions);
		}

		// Set up CORS and auth handler for each active instance
		for (const instance of activeInstances) {
			const { options, basePath } = instance;
			const trustedOrigins = options.auth.options.trustedOrigins;
			const isNotFunctionBased =
				trustedOrigins && Array.isArray(trustedOrigins);

			if (!options.disableTrustedOriginsCors && isNotFunctionBased) {
				if (adapterType === "fastify") {
					const fastifyInstance = this.adapter.httpAdapter.getInstance<{
						hasRequestDecorator?: (name: string) => boolean;
					}>();
					const hasFastifyCorsRegistered =
						fastifyInstance?.hasRequestDecorator?.("corsPreflightEnabled") ??
						false;

					if (hasFastifyCorsRegistered) {
						this.logger.warn(
							"Detected an existing @fastify/cors registration. Skipping automatic Fastify CORS registration for Better Auth trustedOrigins to avoid duplicate plugin registration. Better Auth routes will still apply CORS from trustedOrigins. Set disableTrustedOriginsCors: true if you want to fully manage Better Auth CORS yourself.",
						);
					} else {
						this.adapter.httpAdapter.enableCors({
							origin: trustedOrigins,
							methods: ["GET", "POST", "PUT", "DELETE"],
							credentials: true,
						});
					}
				} else {
					this.adapter.httpAdapter.enableCors({
						origin: trustedOrigins,
						methods: ["GET", "POST", "PUT", "DELETE"],
						credentials: true,
					});
				}
			} else if (
				trustedOrigins &&
				!options.disableTrustedOriginsCors &&
				!isNotFunctionBased
			)
				throw new Error(
					"Function-based trustedOrigins not supported in NestJS. Use string array or disable CORS with disableTrustedOriginsCors: true.",
				);

			const handler = toNodeHandler(options.auth);
			const authHandler = (
				req: AdapterRequest,
				res: AdapterResponse,
				next: () => void,
			) => {
				if (!matchesBasePath(req, basePath)) {
					next();
					return;
				}

				if (
					adapterType === "fastify" &&
					!options.disableTrustedOriginsCors &&
					isNotFunctionBased &&
					handleFastifyTrustedOriginsCors(req, res, {
						trustedOrigins,
					})
				) {
					return;
				}

				const nodeReq = getNodeRequest(req);
				const nodeRes = getNodeResponse(res);

				if (options.middleware) {
					return options.middleware(req, res, () =>
						handler(nodeReq, nodeRes),
					);
				}
				return handler(nodeReq, nodeRes);
			};

			this.adapter.httpAdapter.use(
				(
					// biome-ignore lint/suspicious/noExplicitAny: adapter request type should not leak into the public declaration
					req: any,
					// biome-ignore lint/suspicious/noExplicitAny: adapter response type should not leak into the public declaration
					res: any,
					next: () => void,
				) =>
					authHandler(
						req as AdapterRequest,
						res as AdapterResponse,
						next,
					),
			);
			this.logger.log(
				`AuthModule initialized BetterAuth${this.instances.size > 1 ? ` instance '${instance.name}'` : ""} on '${basePath}'`,
			);
		}
	}

	private setupHooks(
		providerMethod: (...args: unknown[]) => unknown,
		providerClass: { new (...args: unknown[]): unknown },
		options: AuthModuleOptions,
	) {
		if (!options.auth.options.hooks) return;

		for (const { metadataKey, hookType } of HOOKS) {
			const hasHook = Reflect.hasMetadata(metadataKey, providerMethod);
			if (!hasHook) continue;

			const hookPath = Reflect.getMetadata(metadataKey, providerMethod);

			const originalHook = options.auth.options.hooks[hookType];
			options.auth.options.hooks[hookType] = createAuthMiddleware(
				async (ctx) => {
					if (originalHook) {
						await originalHook(ctx);
					}

					if (hookPath && hookPath !== ctx.path) return;

					await providerMethod.apply(providerClass, [ctx]);
				},
			);
		}
	}

	static forRoot(options: AuthModuleForRootOptions): DynamicModule;
	/**
	 * @deprecated Use the object-based signature: AuthModule.forRoot({ auth, ...options })
	 */
	static forRoot(
		auth: Auth,
		options?: Omit<AuthModuleForRootOptions, "auth">,
	): DynamicModule;
	static forRoot(
		arg1: Auth | AuthModuleForRootOptions,
		arg2?: Omit<AuthModuleForRootOptions, "auth">,
	): DynamicModule {
		const normalizedOptions: AuthModuleForRootOptions =
			typeof arg1 === "object" && arg1 !== null && "auth" in (arg1 as object)
				? (arg1 as AuthModuleForRootOptions)
				: ({
						...(arg2 ?? {}),
						auth: arg1 as Auth,
					} as AuthModuleForRootOptions);

		const name = normalizedOptions.name || DEFAULT_AUTH_INSTANCE_NAME;
		const optionsToken = getAuthOptionsToken(name);
		const serviceToken = getAuthServiceToken(name);
		const isDefault = name === DEFAULT_AUTH_INSTANCE_NAME;

		_authInstanceNames.add(name);
		AuthModule.instanceExtras.set(name, {
			disableControllers: !!normalizedOptions.disableControllers,
		});

		return {
			module: AuthModule,
			imports: [DiscoveryModule],
			global: normalizedOptions.isGlobal ?? true,
			providers: [
				{ provide: optionsToken, useValue: normalizedOptions },
				{
					provide: serviceToken,
					useFactory: (opts: AuthModuleOptions) => new AuthService(opts),
					inject: [optionsToken],
				},
				// Backward compat: default instance also provides MODULE_OPTIONS_TOKEN and AuthService
				...(isDefault
					? [
							{
								provide: MODULE_OPTIONS_TOKEN,
								useExisting: optionsToken,
							},
							{ provide: AuthService, useExisting: serviceToken },
						]
					: []),
				...(!normalizedOptions.disableGlobalAuthGuard
					? [{ provide: APP_GUARD, useClass: AuthGuard }]
					: []),
			],
			exports: [
				optionsToken,
				serviceToken,
				...(isDefault ? [MODULE_OPTIONS_TOKEN, AuthService] : []),
			],
		};
	}

	static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
		const name = options.name || DEFAULT_AUTH_INSTANCE_NAME;
		const optionsToken = getAuthOptionsToken(name);
		const serviceToken = getAuthServiceToken(name);
		const isDefault = name === DEFAULT_AUTH_INSTANCE_NAME;

		_authInstanceNames.add(name);
		AuthModule.instanceExtras.set(name, {
			disableControllers: !!options.disableControllers,
		});

		// For the default instance, register the factory directly under
		// MODULE_OPTIONS_TOKEN (the Symbol) — matching what the original
		// ConfigurableModuleBuilder did. The string token aliases to it.
		// For named instances, the string token is the primary provider.
		const optionsProviders = isDefault
			? [
					{
						provide: MODULE_OPTIONS_TOKEN,
						useFactory: options.useFactory,
						inject: options.inject || [],
					},
					{
						provide: optionsToken,
						useExisting: MODULE_OPTIONS_TOKEN,
					},
				]
			: [
					{
						provide: optionsToken,
						useFactory: options.useFactory,
						inject: options.inject || [],
					},
				];

		return {
			module: AuthModule,
			imports: [DiscoveryModule, ...(options.imports || [])],
			global: options.isGlobal ?? true,
			providers: [
				...optionsProviders,
				{
					provide: serviceToken,
					useFactory: (opts: AuthModuleOptions) => new AuthService(opts),
					inject: [isDefault ? MODULE_OPTIONS_TOKEN : optionsToken],
				},
				// Backward compat: default instance also provides AuthService class token
				...(isDefault
					? [{ provide: AuthService, useExisting: serviceToken }]
					: []),
				...(!options.disableGlobalAuthGuard
					? [{ provide: APP_GUARD, useClass: AuthGuard }]
					: []),
			],
			exports: [
				optionsToken,
				serviceToken,
				...(isDefault ? [MODULE_OPTIONS_TOKEN, AuthService] : []),
			],
		};
	}
}
