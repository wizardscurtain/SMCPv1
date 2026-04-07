/**
 * Fastify Plugin for SMCP Security Framework
 */

import { FastifyPluginAsync } from 'fastify';
import { SMCPSecurityFramework } from '../core/SMCPSecurityFramework';

export const createFastifyPlugin = (framework: SMCPSecurityFramework): FastifyPluginAsync => {
  return async (fastify) => {
    fastify.addHook('preHandler', async (request, _reply) => {
      const token = request.headers.authorization?.replace('Bearer ', '');
      const userContext = {
        token,
        ip_address: request.ip,
        user_agent: request.headers['user-agent'],
      };
      try {
        const result = await framework.processRequest(
          request.body as Record<string, unknown>,
          userContext
        );
        (request as typeof request & { smcpContext?: unknown }).smcpContext = result;
      } catch (e) {
        throw e;
      }
    });
  };
};
