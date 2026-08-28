<script setup lang="ts">
import { computed, onMounted, ref, shallowRef, watch } from 'vue';
import { EXAMPLES } from './playground-examples';

// The engine is loaded lazily on mount: VitePress prerenders every page on the
// server, and the browser runtime shim reads `globalThis.crypto`.
const engine = shallowRef<any>(null);
const loadError = ref('');

const exampleKey = ref<keyof typeof EXAMPLES>('quickstart');
const method = ref<'isAllowed' | 'checkResources' | 'planResources'>('checkResources');
const policiesText = ref(EXAMPLES.quickstart.policies);
const derivedRolesText = ref(EXAMPLES.quickstart.derivedRoles);
const requestText = ref(EXAMPLES.quickstart.checkResources);

const result = ref('');
const error = ref('');
const durationMs = ref<number | null>(null);
const running = ref(false);

const methods = ['isAllowed', 'checkResources', 'planResources'] as const;
const currentExample = computed(() => EXAMPLES[exampleKey.value]);

onMounted(async () => {
  try {
    const [kerberosMod, jsepMod, objMod, ternaryMod, newMod] = await Promise.all([
      // Supplied by the `kerberos-browser-bundle` plugin in config.mts — the
      // same esbuild browser bundle `pnpm size` measures.
      import('virtual:kerberos-browser'),
      import('jsep'),
      import('@jsep-plugin/object'),
      import('@jsep-plugin/ternary'),
      import('@jsep-plugin/new'),
    ]);
    const K = (kerberosMod as any).default ?? kerberosMod;
    const jsep = (jsepMod as any).default ?? jsepMod;
    jsep.plugins.register(
      (objMod as any).default ?? objMod,
      (ternaryMod as any).default ?? ternaryMod,
      (newMod as any).default ?? newMod,
    );
    jsep.addUnaryOp('typeof');
    engine.value = { K, codec: K.createSafeExprCodec({ jsep }) };
    run();
  } catch (cause: any) {
    loadError.value = cause?.message ?? String(cause);
  }
});

function selectExample(key: keyof typeof EXAMPLES) {
  exampleKey.value = key;
  const example = EXAMPLES[key];
  policiesText.value = example.policies;
  derivedRolesText.value = example.derivedRoles;
  if (!example[method.value]) method.value = 'checkResources';
  requestText.value = example[method.value] ?? example.checkResources;
}

function selectMethod(next: (typeof methods)[number]) {
  method.value = next;
  const preset = currentExample.value[next];
  if (preset) requestText.value = preset;
}

function parseJson(label: string, text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (cause: any) {
    throw new Error(`${label} is not valid JSON — ${cause.message}`);
  }
}

async function run() {
  if (!engine.value) return;
  running.value = true;
  error.value = '';
  const { K, codec } = engine.value;
  const startedAt = performance.now();
  try {
    const rawPolicies = parseJson('Policies', policiesText.value);
    const rawDerived = parseJson('Derived roles', derivedRolesText.value);
    const request = parseJson('Request', requestText.value);

    // Stored policies carry `{ $expr }` strings rather than live functions, so
    // they go through the eval-free codec exactly like cache-backed ones.
    const policies = (Array.isArray(rawPolicies) ? rawPolicies : [rawPolicies]).map((p: unknown) =>
      K.deserializePolicy(p, codec),
    );
    const derivedRoles = (Array.isArray(rawDerived) ? rawDerived : rawDerived ? [rawDerived] : []).map((d: unknown) =>
      K.deserializePolicy(d, codec),
    );

    const kerberos = new K.Kerberos(policies, derivedRoles);
    const output = await kerberos[method.value](request as any);
    result.value = JSON.stringify(output, null, 2);
    durationMs.value = performance.now() - startedAt;
  } catch (cause: any) {
    error.value = `${cause?.name ?? 'Error'}: ${cause?.message ?? String(cause)}`;
    result.value = '';
    durationMs.value = null;
  } finally {
    running.value = false;
  }
}

let debounce: ReturnType<typeof setTimeout> | undefined;
watch([policiesText, derivedRolesText, requestText, method], () => {
  clearTimeout(debounce);
  debounce = setTimeout(run, 300);
});
</script>

<template>
  <div class="kp">
    <div v-if="loadError" class="kp-fatal">Could not load the engine: {{ loadError }}</div>

    <div class="kp-bar">
      <div class="kp-group">
        <span class="kp-label">Example</span>
        <button
          v-for="(example, key) in EXAMPLES"
          :key="key"
          class="kp-chip"
          :class="{ 'kp-chip--on': exampleKey === key }"
          type="button"
          @click="selectExample(key as keyof typeof EXAMPLES)"
        >
          {{ example.title }}
        </button>
      </div>
      <div class="kp-group">
        <span class="kp-label">Method</span>
        <button
          v-for="name in methods"
          :key="name"
          class="kp-chip"
          :class="{ 'kp-chip--on': method === name }"
          type="button"
          @click="selectMethod(name)"
        >
          {{ name }}
        </button>
      </div>
    </div>

    <p class="kp-note">{{ currentExample.description }}</p>

    <div class="kp-grid">
      <div class="kp-pane">
        <label class="kp-pane-title" for="kp-policies">Policies</label>
        <textarea id="kp-policies" v-model="policiesText" class="kp-editor" spellcheck="false" rows="18" />
      </div>
      <div class="kp-pane">
        <label class="kp-pane-title" for="kp-derived">Derived roles</label>
        <textarea id="kp-derived" v-model="derivedRolesText" class="kp-editor" spellcheck="false" rows="7" />
        <label class="kp-pane-title" for="kp-request">Request</label>
        <textarea id="kp-request" v-model="requestText" class="kp-editor" spellcheck="false" rows="10" />
      </div>
    </div>

    <div class="kp-actions">
      <button class="kp-run" type="button" :disabled="!engine || running" @click="run">
        {{ engine ? 'Run' : 'Loading engine…' }}
      </button>
      <span v-if="durationMs !== null && !error" class="kp-timing">
        decided in {{ durationMs.toFixed(2) }} ms — in this tab, no network
      </span>
    </div>

    <div v-if="error" class="kp-error">{{ error }}</div>
    <pre v-else-if="result" class="kp-result"><code>{{ result }}</code></pre>
  </div>
</template>

<style scoped>
.kp {
  margin: 1.5rem 0;
}
.kp-fatal,
.kp-error {
  border: 1px solid var(--vp-c-danger-1, #d64550);
  border-radius: 8px;
  padding: 0.75rem 1rem;
  margin: 1rem 0 0;
  font-family: var(--vp-font-family-mono);
  font-size: 0.8rem;
  color: var(--vp-c-danger-1, #d64550);
  white-space: pre-wrap;
}
.kp-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 1.25rem;
  margin-bottom: 0.75rem;
}
.kp-group {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.4rem;
}
.kp-label {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--vp-c-text-3);
  margin-right: 0.15rem;
}
.kp-chip {
  border: 1px solid var(--vp-c-divider);
  border-radius: 999px;
  padding: 0.2rem 0.7rem;
  font-size: 0.78rem;
  line-height: 1.5;
  color: var(--vp-c-text-2);
  background: var(--vp-c-bg-alt);
  transition: color 0.2s, border-color 0.2s, background-color 0.2s;
}
.kp-chip:hover {
  border-color: var(--vp-c-brand-1);
  color: var(--vp-c-text-1);
}
.kp-chip--on {
  border-color: var(--vp-c-brand-1);
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-text-1);
  font-weight: 600;
}
.kp-note {
  font-size: 0.85rem;
  color: var(--vp-c-text-2);
  margin: 0 0 0.75rem;
}
.kp-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}
@media (max-width: 820px) {
  .kp-grid {
    grid-template-columns: 1fr;
  }
}
.kp-pane {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.kp-pane-title {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--vp-c-text-3);
  margin: 0 0 0.3rem;
}
.kp-pane-title + .kp-editor {
  margin-bottom: 0.75rem;
}
.kp-editor {
  width: 100%;
  resize: vertical;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  padding: 0.7rem 0.85rem;
  background: var(--vp-c-bg-alt);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.78rem;
  line-height: 1.6;
  tab-size: 2;
}
.kp-editor:focus {
  outline: none;
  border-color: var(--vp-c-brand-1);
}
.kp-actions {
  display: flex;
  align-items: center;
  gap: 0.9rem;
  margin-top: 0.9rem;
}
.kp-run {
  border-radius: 8px;
  padding: 0.4rem 1.4rem;
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--vp-c-bg);
  background: var(--vp-c-brand-1);
  transition: opacity 0.2s;
}
.kp-run:disabled {
  opacity: 0.55;
}
.kp-timing {
  font-size: 0.78rem;
  color: var(--vp-c-text-3);
}
.kp-result {
  margin-top: 0.9rem;
  max-height: 26rem;
  overflow: auto;
}
</style>
