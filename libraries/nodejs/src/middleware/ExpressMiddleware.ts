/**
 * Express Middleware for SMCP Security Framework
 */

import { Request, Response, NextFunction } from 'express';
import { SMCPSecurityFramework } from '../core/SMCPSecurityFramework';

export function createExpressMiddleware(framework: SMCPSecurityFramework) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const userContext = {
      token,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
    };
    try {
      const result = await framework.processRequest(
        req.body as Record<string, unknown>,
        userContext
      );
      (req as Request & { smcpContext?: unknown }).smcpContext = result;
      next();
    } catch (e) {
      next(e);
    }
  };
}
