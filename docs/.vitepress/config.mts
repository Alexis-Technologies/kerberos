import { defineConfig } from 'vitepress';
import { withMermaid } from 'vitepress-plugin-mermaid';

const ogTitle = 'Kerberos.js — embedded authorization engine for Node.js & the browser';
const ogDescription =
  'Zero-dependency, in-process authorization engine for JavaScript. Cerbos-style RBAC + ABAC policies, ' +
  'Zanzibar-inspired ReBAC relations and Cerbos-compatible query plans — no server to deploy, ~25 KB min+gzip.';
const repo = 'https://github.com/Alexis-Technologies/kerberos';
const base = '/';
const hostname = 'https://kerberosjs.vercel.app/';
const ogImage = `${hostname}logo.png`;

// Mirrors package.json "keywords" — kept in one line-per-term list so the two stay easy to diff.
const keywords = [
  'authorization',
  'authorization engine',
  'access control',
  'fine-grained authorization',
  'permissions',
  'policy-as-code',
  'rbac',
  'abac',
  'rebac',
  'zanzibar',
  'spicedb',
  'openfga',
  'cerbos',
  'cerbos alternative',
  'derived roles',
  'query plan',
  'in-process authorization',
  'zero dependency authorization',
  'nodejs authorization',
  'browser authorization',
  'opentelemetry',
  'kerberos.js',
  '@alexify/kerberos',
].join(', ');

// schema.org structured data — helps search and AI engines understand the package
// as a software entity, not just text on a page.
const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: '@alexify/kerberos',
  alternateName: 'Kerberos.js',
  description: ogDescription,
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Node.js >= 18, modern browsers',
  url: hostname,
  downloadUrl: 'https://www.npmjs.com/package/@alexify/kerberos',
  codeRepository: repo,
  license: 'https://opensource.org/licenses/MIT',
  keywords,
  author: { '@type': 'Organization', name: 'Alexis Technologies' },
  offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
};

// https://vitepress.dev/reference/site-config
export default withMermaid(
  defineConfig({
    title: '@alexify/kerberos',
    titleTemplate: ':title — Kerberos.js',
    description: ogDescription,
    lang: 'en-US',
    base,
    cleanUrls: true,
    lastUpdated: true,
    sitemap: { hostname },

    head: [
      ['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}logo-mark.svg` }],
      ['link', { rel: 'icon', type: 'image/png', href: `${base}favicon.png` }],
      ['meta', { name: 'theme-color', content: '#FFC11E' }],
      ['meta', { name: 'author', content: 'Alexis Technologies' }],
      ['meta', { name: 'keywords', content: keywords }],
      ['meta', { name: 'robots', content: 'index, follow' }],
      ['meta', { property: 'og:type', content: 'website' }],
      ['meta', { property: 'og:site_name', content: '@alexify/kerberos' }],
      ['meta', { property: 'og:title', content: ogTitle }],
      ['meta', { property: 'og:description', content: ogDescription }],
      ['meta', { property: 'og:image', content: ogImage }],
      ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
      ['meta', { name: 'twitter:title', content: ogTitle }],
      ['meta', { name: 'twitter:description', content: ogDescription }],
      ['meta', { name: 'twitter:image', content: ogImage }],
      ['script', { type: 'application/ld+json' }, JSON.stringify(jsonLd)],
    ],

    // Per-page canonical + og:url for clean SEO indexing
    transformPageData(pageData) {
      const path = pageData.relativePath.replace(/index\.md$/, '').replace(/\.md$/, '');
      const canonical = `${hostname}${path}`;
      pageData.frontmatter.head ??= [];
      pageData.frontmatter.head.push(
        ['link', { rel: 'canonical', href: canonical }],
        ['meta', { property: 'og:url', content: canonical }],
      );
    },

    themeConfig: {
      logo: '/logo-mark.svg',

      // ─── Top navigation ──────────────────────────────────────────────
      nav: [
        { text: 'Guide', link: '/guide/why', activeMatch: '/guide/' },
        { text: 'API', link: '/api/kerberos', activeMatch: '/api/' },
        { text: 'Reference', link: '/reference/plan-operators', activeMatch: '/reference/' },
        {
          // Hand-synced with package.json "version" — part of the release checklist.
          text: 'v3.1.0',
          items: [
            { text: 'Changelog', link: `${repo}/blob/main/CHANGELOG.md` },
            { text: 'npm', link: 'https://www.npmjs.com/package/@alexify/kerberos' },
            { text: 'Releases', link: `${repo}/releases` },
          ],
        },
      ],

      // ─── Sidebar ─────────────────────────────────────────────────────
      sidebar: {
        '/guide/': [
          {
            text: 'Introduction',
            items: [
              { text: 'Why Kerberos.js?', link: '/guide/why' },
              { text: 'Installation', link: '/guide/installation' },
              { text: 'Quick Start', link: '/guide/getting-started' },
              { text: 'Policy Types', link: '/guide/policy-types' },
              { text: 'Scopes & Versions', link: '/guide/scopes' },
            ],
          },
          {
            text: 'Core features',
            items: [
              { text: 'Configuration', link: '/guide/configuration' },
              { text: 'Outputs', link: '/guide/outputs' },
              { text: 'Decision metadata', link: '/guide/decision-metadata' },
              { text: 'Schema validation', link: '/guide/schema-validation' },
              { text: 'Testing', link: '/guide/testing' },
            ],
          },
          {
            text: 'Advanced',
            items: [
              { text: 'Caching & dynamic policies', link: '/guide/caching' },
              { text: 'Serialization & security', link: '/guide/serialization' },
              { text: 'ReBAC (Relations)', link: '/guide/rebac' },
              { text: 'Built-in resolver', link: '/guide/relations-resolver' },
              { text: 'Query plans', link: '/guide/query-plans' },
              { text: 'OpenTelemetry', link: '/guide/telemetry' },
              { text: 'Benchmarks', link: '/guide/benchmarks' },
            ],
          },
        ],
        '/api/': [
          {
            text: 'API Reference',
            items: [
              { text: 'Kerberos class', link: '/api/kerberos' },
              { text: 'Errors', link: '/api/errors' },
              { text: 'Exports', link: '/api/exports' },
            ],
          },
        ],
        '/reference/': [
          {
            text: 'Reference',
            items: [
              { text: 'Plan operators', link: '/reference/plan-operators' },
              { text: 'Safe builtins', link: '/reference/safe-builtins' },
              { text: 'Security', link: '/reference/security' },
            ],
          },
        ],
      },

      // ─── Local, zero-config full-text search ─────────────────────────
      search: { provider: 'local' },

      socialLinks: [{ icon: 'github', link: repo }],

      editLink: {
        pattern: `${repo}/edit/main/docs/:path`,
        text: 'Edit this page on GitHub',
      },

      footer: {
        message: 'Released under the MIT License.',
        copyright: 'Copyright © 2026 Alexis Technologies',
      },

      docFooter: {
        prev: 'Previous page',
        next: 'Next page',
      },
    },
  }),
);
