import "reflect-metadata";
import request from "supertest";
import { faker } from "@faker-js/faker";
import {
	Controller,
	Get,
	Injectable,
	Module,
	type INestApplication,
} from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { betterAuth } from "better-auth";
import { bearer } from "better-auth/plugins/bearer";
import {
	AuthModule,
	AuthService,
	UseAuth,
	InjectAuth,
	AllowAnonymous,
	Session,
	Hook,
	BeforeHook,
	type AuthHookContext,
} from "../../src/index.ts";
import { createTestNestApplication } from "../shared/test-utils.ts";

// Create two separate auth instances with different base paths and cookie prefixes
function createCustomerAuth(withHooks = false) {
	return betterAuth({
		basePath: "/api/customer-auth",
		emailAndPassword: { enabled: true },
		plugins: [bearer()],
		advanced: {
			cookiePrefix: "customer",
		},
		...(withHooks ? { hooks: {} } : {}),
	});
}

function createEmployeeAuth(withHooks = false) {
	return betterAuth({
		basePath: "/api/employee-auth",
		emailAndPassword: { enabled: true },
		plugins: [bearer()],
		advanced: {
			cookiePrefix: "employee",
		},
		...(withHooks ? { hooks: {} } : {}),
	});
}

// Customer controller - uses the 'customer' auth instance
@UseAuth("customer")
@Controller("customer")
class CustomerController {
	constructor(
		@InjectAuth("customer") private readonly authService: AuthService,
	) {}

	@Get("profile")
	profile(@Session() session: unknown) {
		return { session, source: "customer" };
	}

	@AllowAnonymous()
	@Get("public")
	publicRoute() {
		return { ok: true, source: "customer" };
	}

	@AllowAnonymous()
	@Get("instance-check")
	instanceCheck() {
		return {
			hasApi: !!this.authService.api,
			hasInstance: !!this.authService.instance,
		};
	}
}

// Employee controller - uses the 'employee' auth instance
@UseAuth("employee")
@Controller("employee")
class EmployeeController {
	constructor(
		@InjectAuth("employee") private readonly authService: AuthService,
	) {}

	@Get("profile")
	profile(@Session() session: unknown) {
		return { session, source: "employee" };
	}

	@AllowAnonymous()
	@Get("public")
	publicRoute() {
		return { ok: true, source: "employee" };
	}

	@AllowAnonymous()
	@Get("instance-check")
	instanceCheck() {
		return {
			hasApi: !!this.authService.api,
			hasInstance: !!this.authService.instance,
		};
	}
}

describe("multi-instance e2e", () => {
	let app: INestApplication;
	let customerAuth: ReturnType<typeof createCustomerAuth>;
	let employeeAuth: ReturnType<typeof createEmployeeAuth>;

	beforeAll(async () => {
		customerAuth = createCustomerAuth();
		employeeAuth = createEmployeeAuth();

		@Module({
			imports: [
				AuthModule.forRoot({ auth: customerAuth, name: "customer" }),
				AuthModule.forRoot({ auth: employeeAuth, name: "employee" }),
			],
			controllers: [CustomerController, EmployeeController],
		})
		class AppModule {}

		const moduleRef = await Test.createTestingModule({
			imports: [AppModule],
		}).compile();

		app = await createTestNestApplication(moduleRef);
	});

	afterAll(async () => {
		await app.close();
	});

	describe("auth route handling", () => {
		it("should handle customer auth sign-up at /api/customer-auth", async () => {
			const response = await request(app.getHttpServer())
				.post("/api/customer-auth/sign-up/email")
				.set("Content-Type", "application/json")
				.send({
					name: faker.person.fullName(),
					email: faker.internet.email(),
					password: faker.internet.password({ length: 10 }),
				})
				.expect(200);

			expect(response.body?.token).toBeDefined();
			expect(response.body?.user?.id).toBeDefined();
		});

		it("should handle employee auth sign-up at /api/employee-auth", async () => {
			const response = await request(app.getHttpServer())
				.post("/api/employee-auth/sign-up/email")
				.set("Content-Type", "application/json")
				.send({
					name: faker.person.fullName(),
					email: faker.internet.email(),
					password: faker.internet.password({ length: 10 }),
				})
				.expect(200);

			expect(response.body?.token).toBeDefined();
			expect(response.body?.user?.id).toBeDefined();
		});
	});

	describe("instance-scoped guards", () => {
		it("should authenticate customer routes with customer auth token", async () => {
			const signUp = await customerAuth.api.signUpEmail({
				body: {
					name: faker.person.fullName(),
					email: faker.internet.email(),
					password: faker.internet.password({ length: 10 }),
				},
			});

			const response = await request(app.getHttpServer())
				.get("/customer/profile")
				.set("Authorization", `Bearer ${signUp.token}`)
				.expect(200);

			expect(response.body).toMatchObject({
				source: "customer",
				session: expect.objectContaining({
					user: expect.objectContaining({
						id: signUp.user.id,
					}),
				}),
			});
		});

		it("should authenticate employee routes with employee auth token", async () => {
			const signUp = await employeeAuth.api.signUpEmail({
				body: {
					name: faker.person.fullName(),
					email: faker.internet.email(),
					password: faker.internet.password({ length: 10 }),
				},
			});

			const response = await request(app.getHttpServer())
				.get("/employee/profile")
				.set("Authorization", `Bearer ${signUp.token}`)
				.expect(200);

			expect(response.body).toMatchObject({
				source: "employee",
				session: expect.objectContaining({
					user: expect.objectContaining({
						id: signUp.user.id,
					}),
				}),
			});
		});

		it("should reject customer token on employee route", async () => {
			const signUp = await customerAuth.api.signUpEmail({
				body: {
					name: faker.person.fullName(),
					email: faker.internet.email(),
					password: faker.internet.password({ length: 10 }),
				},
			});

			await request(app.getHttpServer())
				.get("/employee/profile")
				.set("Authorization", `Bearer ${signUp.token}`)
				.expect(401);
		});

		it("should reject employee token on customer route", async () => {
			const signUp = await employeeAuth.api.signUpEmail({
				body: {
					name: faker.person.fullName(),
					email: faker.internet.email(),
					password: faker.internet.password({ length: 10 }),
				},
			});

			await request(app.getHttpServer())
				.get("/customer/profile")
				.set("Authorization", `Bearer ${signUp.token}`)
				.expect(401);
		});

		it("should reject unauthenticated access to protected routes", async () => {
			await request(app.getHttpServer())
				.get("/customer/profile")
				.expect(401);

			await request(app.getHttpServer())
				.get("/employee/profile")
				.expect(401);
		});

		it("should allow public routes without authentication", async () => {
			const customerRes = await request(app.getHttpServer())
				.get("/customer/public")
				.expect(200);

			expect(customerRes.body).toMatchObject({
				ok: true,
				source: "customer",
			});

			const employeeRes = await request(app.getHttpServer())
				.get("/employee/public")
				.expect(200);

			expect(employeeRes.body).toMatchObject({
				ok: true,
				source: "employee",
			});
		});
	});

	describe("named AuthService injection", () => {
		it("should inject the correct auth service per instance", async () => {
			const customerRes = await request(app.getHttpServer())
				.get("/customer/instance-check")
				.expect(200);

			expect(customerRes.body).toMatchObject({
				hasApi: true,
				hasInstance: true,
			});

			const employeeRes = await request(app.getHttpServer())
				.get("/employee/instance-check")
				.expect(200);

			expect(employeeRes.body).toMatchObject({
				hasApi: true,
				hasInstance: true,
			});
		});
	});
});

describe("multi-instance with hooks", () => {
	let app: INestApplication;
	let customerAuth: ReturnType<typeof createCustomerAuth>;
	let employeeAuth: ReturnType<typeof createEmployeeAuth>;

	@Injectable()
	class HookTracker {
		customerHookCalls = 0;
		employeeHookCalls = 0;
	}

	@Hook("customer")
	@Injectable()
	class CustomerHook {
		constructor(private readonly tracker: HookTracker) {}

		@BeforeHook("/sign-up/email")
		async handle(_ctx: AuthHookContext) {
			this.tracker.customerHookCalls += 1;
		}
	}

	@Hook("employee")
	@Injectable()
	class EmployeeHook {
		constructor(private readonly tracker: HookTracker) {}

		@BeforeHook("/sign-up/email")
		async handle(_ctx: AuthHookContext) {
			this.tracker.employeeHookCalls += 1;
		}
	}

	beforeAll(async () => {
		customerAuth = createCustomerAuth(true);
		employeeAuth = createEmployeeAuth(true);

		@Module({
			imports: [
				AuthModule.forRoot({ auth: customerAuth, name: "customer" }),
				AuthModule.forRoot({ auth: employeeAuth, name: "employee" }),
			],
			providers: [HookTracker, CustomerHook, EmployeeHook],
		})
		class AppModule {}

		const moduleRef = await Test.createTestingModule({
			imports: [AppModule],
		}).compile();

		app = await createTestNestApplication(moduleRef);
	});

	afterAll(async () => {
		await app.close();
	});

	it("should only trigger customer hook on customer auth sign-up", async () => {
		const tracker = app.get(HookTracker);

		await request(app.getHttpServer())
			.post("/api/customer-auth/sign-up/email")
			.set("Content-Type", "application/json")
			.send({
				name: faker.person.fullName(),
				email: faker.internet.email(),
				password: faker.internet.password({ length: 10 }),
			})
			.expect(200);

		expect(tracker.customerHookCalls).toBe(1);
		expect(tracker.employeeHookCalls).toBe(0);
	});

	it("should only trigger employee hook on employee auth sign-up", async () => {
		const tracker = app.get(HookTracker);
		const beforeCustomer = tracker.customerHookCalls;

		await request(app.getHttpServer())
			.post("/api/employee-auth/sign-up/email")
			.set("Content-Type", "application/json")
			.send({
				name: faker.person.fullName(),
				email: faker.internet.email(),
				password: faker.internet.password({ length: 10 }),
			})
			.expect(200);

		expect(tracker.employeeHookCalls).toBe(1);
		expect(tracker.customerHookCalls).toBe(beforeCustomer);
	});
});

describe("multi-instance with forRootAsync", () => {
	let app: INestApplication;
	let customerAuth: ReturnType<typeof createCustomerAuth>;
	let employeeAuth: ReturnType<typeof createEmployeeAuth>;

	beforeAll(async () => {
		customerAuth = createCustomerAuth();
		employeeAuth = createEmployeeAuth();

		@Module({
			imports: [
				AuthModule.forRootAsync({
					name: "customer",
					useFactory: async () => ({ auth: customerAuth }),
				}),
				AuthModule.forRootAsync({
					name: "employee",
					useFactory: async () => ({ auth: employeeAuth }),
				}),
			],
			controllers: [CustomerController, EmployeeController],
		})
		class AppModule {}

		const moduleRef = await Test.createTestingModule({
			imports: [AppModule],
		}).compile();

		app = await createTestNestApplication(moduleRef);
	});

	afterAll(async () => {
		await app.close();
	});

	it("should work with async configuration for both instances", async () => {
		const customerSignUp = await customerAuth.api.signUpEmail({
			body: {
				name: faker.person.fullName(),
				email: faker.internet.email(),
				password: faker.internet.password({ length: 10 }),
			},
		});

		const response = await request(app.getHttpServer())
			.get("/customer/profile")
			.set("Authorization", `Bearer ${customerSignUp.token}`)
			.expect(200);

		expect(response.body).toMatchObject({
			source: "customer",
			session: expect.objectContaining({
				user: expect.objectContaining({
					id: customerSignUp.user.id,
				}),
			}),
		});
	});
});
