# Hmac Authentication
This is a simple Node.js server that implements HMAC authentication. It provides an API endpoint that requires authentication using HMAC.

## Step 1: Generate and Compare HMAC
https://github.com/KishorNaik/Sol_Hmac_Auth_ExpressJs/blob/main/src/shared/utils/helpers/hmac/index.ts
```typescript
// Generate Hashed Message Authentication Code (HMAC)
import { createHmac } from 'crypto';
import { Ok, Result } from 'neverthrow';
import { ResultError, ResultExceptionFactory } from '../../exceptions/results';
import { StatusCodes } from 'http-status-codes';

export const generateHmac = (payload: string, secret: string): Result<string,ResultError> => {
  try
  {
    if(!payload)
      return ResultExceptionFactory.error(StatusCodes.BAD_REQUEST, 'Payload is required');

    if(!secret)
      return ResultExceptionFactory.error(StatusCodes.BAD_REQUEST, 'Secret is required');

    const hmac = createHmac('sha256', secret);
    hmac.update(payload);
    const signature:string = hmac.digest('hex');

    if(!signature)
      return ResultExceptionFactory.error(StatusCodes.INTERNAL_SERVER_ERROR, 'Failed to generate HMAC');
    return new Ok(signature);

  }
  catch(ex){
    const error = ex as Error;
    return ResultExceptionFactory.error(StatusCodes.INTERNAL_SERVER_ERROR, `An error occurred while generating HMAC: ${error.message}`);
  }

};

// Compare HMAC Signature
export const compareHmac = (payload: string, secret: string, receivedSignature: string): Result<boolean,ResultError> => {
  try
  {
    if(!payload)
      return ResultExceptionFactory.error(StatusCodes.BAD_REQUEST, 'Payload is required');

    if(!secret)
      return ResultExceptionFactory.error(StatusCodes.BAD_REQUEST, 'Secret is required');

    if(!receivedSignature)
      return ResultExceptionFactory.error(StatusCodes.BAD_REQUEST, 'Signature is required');

    const createHmacResult=generateHmac(payload, secret);
    if(createHmacResult.isErr())
      return ResultExceptionFactory.error(createHmacResult.error.status, createHmacResult.error.message);

    const signature = createHmacResult.value;
    if(signature !== receivedSignature)
      return ResultExceptionFactory.error(StatusCodes.UNAUTHORIZED, 'Invalid signature');

    return new Ok(true);
  }
  catch(ex){
    const error = ex as Error;
    return ResultExceptionFactory.error(StatusCodes.INTERNAL_SERVER_ERROR, `An error occurred while comparing HMAC: ${error.message}`);
  }
}

```

## Step 2: Hmac Authentication Middleware
https://github.com/KishorNaik/Sol_Hmac_Auth_ExpressJs/blob/main/src/middlewares/hmac.middlware.ts
```typescript
import { DataResponseFactory } from '@/shared/models/response/data.Response';
import { ResultError } from '@/shared/utils/exceptions/results';
import { compareHmac } from '@/shared/utils/helpers/hmac';
import express, { Request, Response, NextFunction } from 'express';
import { Ok, Result } from 'neverthrow';

export async function authenticateHmac(req: Request, res: Response, next: NextFunction) {
  const payload = JSON.stringify(req.body);
  const receivedSignature = req.headers['x-auth-signature'] as string;
  const clientId=req.headers['x-client-id'] as string;

  if(!clientId){
    const response = DataResponseFactory.Response<undefined>(
      false,
      403,
      undefined,
      'Forbidden - You do not have permission to access this resource: Client Id is required'
    );
    return res.status(403).json(response);
  }

  if (!receivedSignature) {
    const response = DataResponseFactory.Response<undefined>(
            false,
            403,
            undefined,
            'Forbidden - You do not have permission to access this resource: Signature is required'
          );
    return res.status(403).json(response);
  }

  const secretKeyResult=await getSecretKeyFromDatabaseAsync(clientId);
  if(secretKeyResult.isErr()){
    const response = DataResponseFactory.Response<undefined>(
      false,
      secretKeyResult.error.status,
      undefined,
      `Forbidden - You do not have permission to access this resource: ${secretKeyResult.error.message}`
    );
    return res.status(secretKeyResult.error.status).json(response);
  }

  const SECRET_KEY=secretKeyResult.value;

  const compareHmacResult = compareHmac(payload, SECRET_KEY, receivedSignature);
  if (compareHmacResult.isErr()) {
    const response = DataResponseFactory.Response<undefined>(
      false,
      compareHmacResult.error.status,
      undefined,
      compareHmacResult.error.message
    );
    return res.status(compareHmacResult.error.status).json(response);
  }

  next();
}

const getSecretKeyFromDatabaseAsync=async(clientId:string):Promise<Result<string,ResultError>>=>{

  // Get secret key from database by clientId

  return Promise.resolve(new Ok('secret_key'));
}

```

## Step 3: Use the middleware in your routes
https://github.com/KishorNaik/Sol_Hmac_Auth_ExpressJs/blob/main/src/modules/demo/apps/features/v1/demoAes/index.ts#L36
```typescript
@JsonController('/api/v1/demo')
@OpenAPI({ tags: ['demo'] })
export class DemoAesController {
	@Post()
	@OpenAPI({ summary: 'demo endpoint', tags: ['demo'] })
	@HttpCode(StatusCodes.OK)
	@OnUndefined(StatusCodes.BAD_REQUEST)
  @UseBefore(authenticateHmac)
	public async demoEndpoint(@Body() request: AesRequestDto, @Res() res: Response) {
		const response = await mediatR.send<ApiDataResponse<AesResponseDto>>(
			new DemoAesCommand(request)
		);
		return res.status(response.StatusCode).json(response);
	}
}
```
```typescript
 @UseBefore(authenticateHmac)
```

## Step 4: Test the endpoint
https://github.com/KishorNaik/Sol_Hmac_Auth_ExpressJs/blob/main/src/modules/demo/tests/integration/index.test.ts
```typescript
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
```

## .env file

- Create a .env file in the root directory of your project and add the following environment variables:

```bash
# PORT
PORT = 3000

# LOG
LOG_FORMAT = dev
LOG_DIR = ../logs

# CORS
ORIGIN = *
CREDENTIALS = true
```
