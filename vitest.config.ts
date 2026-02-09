import { defineConfig } from 'vitest/config';

export default defineConfig({
   test: {
      include: ['spec/**/*.spec.ts'],
      testTimeout: 60000,
   },
});
