import DefaultTheme from 'vitepress/theme';
import type { Theme } from 'vitepress';
import { inject } from '@vercel/analytics';
import { injectSpeedInsights } from '@vercel/speed-insights';
import './custom.css';

// Extends the default VitePress theme with our brand styling (see custom.css).
// This is exactly the pattern Pinia / Vite / Vue use to brand their docs —
// the layout/components stay the default theme, the look comes from CSS variables.
export default {
  extends: DefaultTheme,
  enhanceApp({ router }) {
    // Vercel Web Analytics + Speed Insights, for the docs site only. Both are
    // browser-only and the pages are prerendered, so they must never run in the
    // SSR pass; off a Vercel deployment they resolve to a development script
    // that logs instead of sending. The docs are not part of the published
    // package (`files` in package.json omits them), so nothing here ships to npm.
    if (import.meta.env.SSR) return;

    // Analytics tracks VitePress' pushState navigations on its own.
    inject();

    // Speed Insights does not: in an SPA the route has to be announced, or every
    // Core Web Vital lands on whichever page happened to be loaded first.
    const speedInsights = injectSpeedInsights({ route: location.pathname });
    const onAfterRouteChange = router.onAfterRouteChange;
    router.onAfterRouteChange = (to) => {
      speedInsights?.setRoute(new URL(to, location.origin).pathname);
      return onAfterRouteChange?.(to);
    };
  },
} satisfies Theme;
