/** Public page context never includes userinfo, query or fragment. Known
 * credential-bearing route segments also hide the remainder of the path. */
export function publicURL(address: string, credentialPaths: readonly string[] = []): string {
  if (address === 'about:blank') return address;
  try {
    const url = new URL(address);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) return '';
    url.username = ''; url.password = ''; url.search = ''; url.hash = '';
    const segments = url.pathname.split('/');
    const secret = /^(?:oauth|authorize|authorization|callback|reset-password|password-reset|reset|verify|magic-link|token|access-token|id-token|secret|credential)s?$/i;
    if (credentialPaths.some(path => url.pathname.startsWith(path)) || segments.some(segment => {
      try { return secret.test(decodeURIComponent(segment)); } catch { return true; }
    })) url.pathname = '/redacted';
    const result = url.href;
    return Array.from(result).length <= 8192 ? result : '';
  } catch { return ''; }
}
