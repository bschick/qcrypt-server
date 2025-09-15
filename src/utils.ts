import { FilterXSS } from 'xss';

export class ParamError extends Error {
}

export class AuthError extends Error {
}


const filter = new FilterXSS({
   // remove rather than escape stuff
   stripIgnoreTag: true,
   escapeHtml: (html: string) => {
      return html.replace(/</g, "").replace(/>/g, "");
   }
});

const sanitizeXSS = filter.process.bind(filter);

export const sanitizeString = (input: string): string => {
   if (!input || typeof input !== 'string') {
      throw new ParamError('must be string value');
   }
   const sanitized = sanitizeXSS(input);
   if (!sanitized) {
      throw new ParamError('empty string value');
   }
   return sanitized;
}

export const validB64 = (base64: string | null | undefined): boolean => {
   return !!base64 &&
      typeof base64 === 'string' &&
      /^[A-Za-z0-9+/=_-]+$/.test(base64);
}
