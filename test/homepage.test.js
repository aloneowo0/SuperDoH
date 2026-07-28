import { describe, expect, it } from 'vitest';
import { serveHomepage } from '../src/homepage.js';

describe('homepage runtime values', () => {
  it('preserves the base-path variable while replacing URL placeholders', async () => {
    const response = serveHomepage(
      new Request('https://doh.test/'),
      {},
      ['auto'],
      1,
      '/secure',
    );
    const html = await response.text();

    expect(html).toContain('window.__CONFIGURED__ = 1;');
    expect(html).toContain('window.__BASE_PATH__ = "/secure";');
    expect(html).toContain('href="/secure/en"');
    expect(html).not.toContain('window. =');
  });
});
