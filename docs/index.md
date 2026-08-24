---
layout: home

title: Kerberos.js
titleTemplate: Embedded authorization engine for Node.js and the browser

hero:
  name: Kerberos.js
  text: Authorization that runs inside your app
  tagline: Cerbos-style RBAC + ABAC policies, Zanzibar-inspired ReBAC relations and Cerbos-compatible query plans — zero dependencies, no server to deploy, ~29 KB min+gzip.
  image:
    src: /logo-mark.svg
    alt: Kerberos.js
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: Why Kerberos.js?
      link: /guide/why
    - theme: alt
      text: View on GitHub
      link: https://github.com/Alexis-Technologies/kerberos

features:
  - icon: 📭
    title: Zero dependencies
    details: No runtime dependencies at all. ~29 KB min+gzip for the main entry, 16 KB for the /relations subpath — nothing extra in your lockfile, nothing extra in the process that makes your access decisions.
    link: /guide/installation#bundle-size
    linkText: Bundle size
  - icon: ⚡
    title: In-process, sub-millisecond
    details: No network hop to a policy server, no sidecar to operate. Decisions are a function call, which makes per-item checks over a list a realistic thing to do.
    link: /guide/why
    linkText: Why in-process
  - icon: 🧩
    title: Cerbos-compatible by design
    details: resourcePolicy / principalPolicy / rolePolicy, derived roles, conditions, variables, constants, outputs and scopes. If you know Cerbos, you already know Kerberos.js.
    link: /guide/policy-types
    linkText: Policy types
  - icon: 🕸️
    title: ReBAC without a Zanzibar cluster
    details: Relation-backed derived roles plus a built-in SpiceDB-inspired resolver — unions, intersections, exclusions, arrows, caveats, lookupSubjects and lookupResources.
    link: /guide/rebac
    linkText: Relations
  - icon: 🔍
    title: Query plans for your database
    details: planResources() returns a Cerbos-compatible condition tree over resource attributes, so you can push authorization down into a SQL/Mongo WHERE clause instead of over-fetching.
    link: /guide/query-plans
    linkText: Query plans
  - icon: 🗄️
    title: Dynamic policies, any cache
    details: Bring your own Keyv/cacheable/cache-manager store. Policies stored as JSON are evaluated by an eval-free AST interpreter — no new Function, no CSP violations.
    link: /guide/caching
    linkText: Caching
  - icon: 🌐
    title: Node.js and the browser
    details: One platform-specific file, swapped by the package.json browser field. Everything else is platform-neutral, so the same policies run on the server and in the client.
    link: /guide/installation#browser-usage
    linkText: Browser usage
  - icon: 📊
    title: Observable by default
    details: Structured audit logging (Pino-friendly), decision metadata explaining every deny, and optional OpenTelemetry traces and metrics — all opt-in, none of it can change a decision.
    link: /guide/telemetry
    linkText: OpenTelemetry
  - icon: ✅
    title: Declarative policy tests
    details: A Cerbos-style test DSL on the /tests subpath — describe principals, resources and expected effects as data, and run them against a live engine with node:test.
    link: /guide/testing
    linkText: Testing
---

## Used by

<table style="text-align:center;">
<tbody>
<tr>
<td><a href="https://hirevel.com" target="_blank"><img src="https://cdn.hirevel.com/hirevel/logo.svg" width="200" valign="middle" alt="Hirevel" /></a></td>
<td><a href="https://www.nexaflow.fi" target="_blank"><img src="data:image/svg+xml,%3csvg%20width='285'%20height='50'%20viewBox='0%200%20285%2050'%20fill='none'%20xmlns='http://www.w3.org/2000/svg'%3e%3cpath%20d='M41%204H3C1.34315%204%200%205.34315%200%207C0%208.65685%201.34315%2010%203%2010H41C42.6569%2010%2044%208.65685%2044%207C44%205.34315%2042.6569%204%2041%204Z'%20fill='%231E40AF'/%3e%3cpath%20opacity='0.6'%20d='M27%2022H3C1.34315%2022%200%2023.3431%200%2025C0%2026.6569%201.34315%2028%203%2028H27C28.6569%2028%2030%2026.6569%2030%2025C30%2023.3431%2028.6569%2022%2027%2022Z'%20fill='%231E40AF'/%3e%3cpath%20opacity='0.3'%20d='M15%2040H3C1.34315%2040%200%2041.3431%200%2043C0%2044.6569%201.34315%2046%203%2046H15C16.6569%2046%2018%2044.6569%2018%2043C18%2041.3431%2016.6569%2040%2015%2040Z'%20fill='%231E40AF'/%3e%3cpath%20d='M60.234%2011.012H64.476L80.268%2035.33H80.352V11.012H84.132V41H79.764L64.098%2016.934H64.014V41H60.234V11.012ZM90.5865%2011.012H111.293V14.372H94.5765V23.906H110.159V27.266H94.5765V37.64H111.419V41H90.5865V11.012ZM123.402%2025.586L113.532%2011.012H118.32L125.796%2022.73L133.608%2011.012H138.06L128.148%2025.586L138.69%2041H133.818L125.754%2028.61L117.438%2041H112.986L123.402%2025.586ZM147.104%2028.61H157.268L152.27%2014.624H152.186L147.104%2028.61ZM150.086%2011.012H154.496L166.214%2041H161.804L158.528%2031.97H145.844L142.484%2041H138.41L150.086%2011.012ZM169.172%2011.012H188.87V14.372H173.162V23.906H186.938V27.266H173.162V41H169.172V11.012ZM193.29%2011.012H197.28V37.64H213.156V41H193.29V11.012ZM218.938%2026.006C218.938%2027.518%20219.134%2029.016%20219.526%2030.5C219.918%2031.956%20220.534%2033.272%20221.374%2034.448C222.214%2035.624%20223.292%2036.576%20224.608%2037.304C225.924%2038.004%20227.492%2038.354%20229.312%2038.354C231.132%2038.354%20232.7%2038.004%20234.016%2037.304C235.332%2036.576%20236.41%2035.624%20237.25%2034.448C238.09%2033.272%20238.706%2031.956%20239.098%2030.5C239.49%2029.016%20239.686%2027.518%20239.686%2026.006C239.686%2024.494%20239.49%2023.01%20239.098%2021.554C238.706%2020.07%20238.09%2018.74%20237.25%2017.564C236.41%2016.388%20235.332%2015.45%20234.016%2014.75C232.7%2014.022%20231.132%2013.658%20229.312%2013.658C227.492%2013.658%20225.924%2014.022%20224.608%2014.75C223.292%2015.45%20222.214%2016.388%20221.374%2017.564C220.534%2018.74%20219.918%2020.07%20219.526%2021.554C219.134%2023.01%20218.938%2024.494%20218.938%2026.006ZM214.948%2026.006C214.948%2023.962%20215.242%2022.002%20215.83%2020.126C216.446%2018.222%20217.356%2016.542%20218.56%2015.086C219.764%2013.63%20221.262%2012.468%20223.054%2011.6C224.846%2010.732%20226.932%2010.298%20229.312%2010.298C231.692%2010.298%20233.778%2010.732%20235.57%2011.6C237.362%2012.468%20238.86%2013.63%20240.064%2015.086C241.268%2016.542%20242.164%2018.222%20242.752%2020.126C243.368%2022.002%20243.676%2023.962%20243.676%2026.006C243.676%2028.05%20243.368%2030.024%20242.752%2031.928C242.164%2033.804%20241.268%2035.47%20240.064%2036.926C238.86%2038.382%20237.362%2039.544%20235.57%2040.412C233.778%2041.252%20231.692%2041.672%20229.312%2041.672C226.932%2041.672%20224.846%2041.252%20223.054%2040.412C221.262%2039.544%20219.764%2038.382%20218.56%2036.926C217.356%2035.47%20216.446%2033.804%20215.83%2031.928C215.242%2030.024%20214.948%2028.05%20214.948%2026.006ZM275.628%2041H271.47L264.624%2015.8H264.54L257.61%2041H253.452L245.766%2011.012H249.84L255.72%2035.96H255.804L262.524%2011.012H266.85L273.486%2035.96H273.57L279.66%2011.012H283.65L275.628%2041Z'%20fill='%230C1F3F'/%3e%3c/svg%3e" width="200" valign="middle" alt="NexaFlow" /></a></td>
</tr>
</tbody>
</table>

Using Kerberos.js in production? [Open a PR](https://github.com/Alexis-Technologies/kerberos/pulls) to add your logo.
