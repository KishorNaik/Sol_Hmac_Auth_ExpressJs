// Debug Mode:All Test Case Run
//node --trace-deprecation --test --require ts-node/register -r tsconfig-paths/register ./src/modules/demo/tests/integration/index.test.ts

// Debug Mode:Specific Test Case Run
//node --trace-deprecation --test --test-name-pattern='test_name' --require ts-node/register -r tsconfig-paths/register ./src/modules/demo/tests/integration/index.test.ts

// If Debug not Worked then use
//node --trace-deprecation --test --test-name-pattern='test_name' --require ts-node/register --inspect=4321 -r tsconfig-paths/register ./src/modules/demo/tests/integration/index.test.ts

import 'reflect-metadata';
import { describe, it } from 'node:test';
import expect from 'expect';
import request from 'supertest';
import { App } from '@/app';
import { ValidateEnv } from '@/shared/utils/validations/env';
import { modulesFederation } from '@/moduleFederation';
import { AES } from '@/shared/utils/helpers/aes';
import { ENCRYPTION_KEY } from '@/config';
import { DemoAesRequestDto } from '../../apps/contracts/v1/demoAes/index.Contract';
import { generateHmac } from '@/shared/utils/helpers/hmac';
import { AesRequestDto } from '@/shared/models/request/aes.RequestDto';

process.env.NODE_ENV = 'development';
process.env.ENCRYPTION_KEY = 'RWw5ejc0Wzjq0i0T2ZTZhcYu44fQI5M6';
ValidateEnv();

const appInstance = new App([...modulesFederation]);
const app = appInstance.getServer();

describe('Demo Aes Integration Test', () => {
	// node --trace-deprecation --test --test-name-pattern='should_return_true_if_all_service_return_ok' --require ts-node/register -r tsconfig-paths/register ./src/modules/demo/tests/integration/index.test.ts
	it('should_return_true_if_all_service_return_ok', async () => {

    const requestBody: DemoAesRequestDto = {
      firstName: 'John',
      lastName: 'Doe',
    }

    const aes = new AES(ENCRYPTION_KEY);
    const encryptRequestBody = await aes.encryptAsync(JSON.stringify(requestBody));

    const secretKey = 'secret_key'; // This should match the key used in your middleware
    const clientId = 'test-client-id';

    const payload:AesRequestDto={
      body:encryptRequestBody
    }

    // Generate a valid signature using the same method as the client
    const signatureResult = generateHmac(JSON.stringify(payload), secretKey);
    if(signatureResult.isErr()){
      throw new Error('Error generating signature');
    }

    const signature = signatureResult.value;


		const response = await request(app)
    .post('/api/v1/demo')
    .set('x-auth-signature', signature)
    .set('x-client-id', clientId)
    .send(payload);

		expect(response.status).toBe(200);
    process.exit(0);
	});
});
