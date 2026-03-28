import request from "supertest";
import { faker } from "@faker-js/faker";
import { createTestApp, type TestAppSetup } from "../shared/test-utils.ts";

describe("module e2e", () => {
	it("should be able to configure controllers when configured asynchronously", async () => {
		await expect(createTestApp({}, true)).resolves.toBeDefined();
	});

	it("should register auth routes when using forRootAsync", async () => {
		let testSetup: TestAppSetup | undefined;
		try {
			testSetup = await createTestApp({}, true);

			const signUpResponse = await request(testSetup.app.getHttpServer())
				.post("/api/auth/sign-up/email")
				.set("Content-Type", "application/json")
				.send({
					name: faker.person.fullName(),
					email: faker.internet.email(),
					password: faker.internet.password({ length: 10 }),
				})
				.expect(200);

			const { token, user } = signUpResponse.body ?? {};
			expect(token).toBeDefined();
			expect(user?.id).toBeDefined();

			// Verify the token works for authenticated requests
			const protectedResponse = await request(testSetup.app.getHttpServer())
				.get("/test/protected")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);

			expect(protectedResponse.body).toMatchObject({
				user: expect.objectContaining({ id: user.id }),
			});
		} finally {
			await testSetup?.app.close();
		}
	});
});
