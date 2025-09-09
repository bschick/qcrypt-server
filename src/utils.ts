import { FilterXSS } from 'xss';

const filter = new FilterXSS({
   // remove rather than escape stuff
   stripIgnoreTag: true,
   escapeHtml: (html: string) => {
      return html.replace(/</g, "").replace(/>/g, "");
   }
});

export const sanitizeXSS = filter.process.bind(filter);

export const validB64 = (base64: string | null | undefined): boolean => {
   return !!base64 && /^[A-Za-z0-9+/=_-]+$/.test(base64);
}
