import { RequestHandler } from 'express';
import jwt, { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';
import getDatabase from '../database';
import env from '../env';
import { InvalidCredentialsException } from '../exceptions';
import asyncHandler from '../utils/async-handler';
import isJWT from '../utils/is-jwt';
import logger from '../logger';
import jwt_decode from 'jwt-decode';
import { find } from 'lodash';
import Joi from 'Joi';
import fs from 'fs';
import path from 'path';
const schema = Joi.array()
	.items(
		Joi.object({
			scope: Joi.string(),
			secret: Joi.string(),
			type: Joi.string(),
		})
	)
	.has(
		Joi.object({
			scope: Joi.string(),
			secret: Joi.string(),
		})
	);
let additionalScopes: [{ scope: string; secret: string; type: string }];
let scopesListIsLoaded = false;
if (env.ADDITIONAL_SCOPES_ENABLED) {
	try {
		schema.validate(env.ADDITIONAL_SCOPES_LIST);
		additionalScopes = env.ADDITIONAL_SCOPES_LIST.map((v: { scope: string; secret: string; type: string }) => {
			if (v.type === 'cert') {
				v.secret = fs.readFileSync(path.join('./certs', v.secret), 'utf8');
			}
			return v;
		});
		scopesListIsLoaded = true;
	} catch (err) {
		logger.err(err);
	}
}
/**
 * Verify the passed JWT and assign the user ID and role to `req`
 * Additionaly checks JWT from different scopes
 */
const authenticate: RequestHandler = asyncHandler(async (req, res, next) => {
	req.accountability = {
		user: null,
		role: null,
		admin: false,
		app: false,
		ip: req.ip.startsWith('::ffff:') ? req.ip.substring(7) : req.ip,
		userAgent: req.get('user-agent'),
		scope: null,
	};

	if (!req.token) return next();

	const database = getDatabase();

	if (isJWT(req.token)) {
		//Just pass execution to normal JWT verify flow if additional scopes aren't enabled
		if (!env.ADDITIONAL_SCOPES_ENABLED || (env.ADDITIONAL_SCOPES_ENABLED && !scopesListIsLoaded)) {
			let payload: { id: string; scope: string };

			try {
				payload = jwt.verify(req.token, env.SECRET as string) as { id: string; scope: string };
			} catch (err) {
				if (err instanceof TokenExpiredError) {
					throw new InvalidCredentialsException('Token expired.');
				} else if (err instanceof JsonWebTokenError) {
					throw new InvalidCredentialsException('Token invalid.');
				} else {
					throw err;
				}
			}
			const user = await database
				.select('role', 'directus_roles.admin_access', 'directus_roles.app_access')
				.from('directus_users')
				.leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
				.where({
					'directus_users.id': payload.id,
					status: 'active',
					scope: 'directus',
				})
				.first();

			if (!user) {
				throw new InvalidCredentialsException();
			}

			req.accountability.user = payload.id;
			req.accountability.role = user.role;
			req.accountability.admin = user.admin_access === true || user.admin_access == 1;
			req.accountability.app = user.app_access === true || user.app_access == 1;
			req.accountability.scope = 'directus';
		} else if (scopesListIsLoaded && env.ADDITIONAL_SCOPES_ENABLED) {
			let payload: { id: string; scope: string };
			let verificationScope: { scope: string; secret: string } | undefined;
			let token: { id: string; scope: string; exp: number; iat: number };
			try {
				token = jwt_decode(req.token);
				if (token.scope === '') {
					throw 'No scope provided';
				}
			} catch (err) {
				logger.error(err);
				throw new InvalidCredentialsException();
			}
			//Do it here, in case env.SECRET is being changed in runtime
			additionalScopes.push({ scope: 'directus', secret: env.SECRET, type: 'string' });
			try {
				verificationScope = find(additionalScopes, { scope: token.scope });
				if (typeof verificationScope === 'undefined') {
					throw 'Valid scope is not found';
				}
			} catch (err) {
				//Right scope is not present in token
				throw new InvalidCredentialsException();
			}
			try {
				payload = jwt.verify(req.token, verificationScope.secret as string) as { id: string; scope: string };
			} catch (err) {
				if (err instanceof TokenExpiredError) {
					throw new InvalidCredentialsException('Token expired.');
				} else if (err instanceof JsonWebTokenError) {
					throw new InvalidCredentialsException('Token invalid.');
				} else {
					throw err;
				}
			}
			const user = await database
				.select('role', 'directus_roles.admin_access', 'directus_roles.app_access')
				.from('directus_users')
				.leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
				.where({
					'directus_users.id': payload.id,
					status: 'active',
					scope: verificationScope.scope,
				})
				.first();

			if (!user) {
				throw new InvalidCredentialsException();
			}

			req.accountability.user = payload.id;
			req.accountability.role = user.role;
			req.accountability.admin = user.admin_access === true || user.admin_access == 1;
			req.accountability.app = user.app_access === true || user.app_access == 1;
			req.accountability.scope = verificationScope.scope;
		}
	} else {
		// Try finding the user with the provided token
		const user = await database
			.select('directus_users.id', 'directus_users.role', 'directus_roles.admin_access', 'directus_roles.app_access')
			.from('directus_users')
			.leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
			.where({
				'directus_users.token': req.token,
				status: 'active',
			})
			.first();

		if (!user) {
			throw new InvalidCredentialsException();
		}

		req.accountability.user = user.id;
		req.accountability.role = user.role;
		req.accountability.admin = user.admin_access === true || user.admin_access == 1;
		req.accountability.app = user.app_access === true || user.app_access == 1;
	}

	return next();
});

export default authenticate;
