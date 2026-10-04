<script setup lang="ts">
import { computed, ref } from 'vue';
import compare from '../../../../bench/results/compare.json';
import { compareCaption, compareModel, compareScenarios } from '../../../../bench/report/model.mjs';
import BenchBars from './BenchBars.vue';

const props = withDefaults(defineProps<{ scenario?: string }>(), { scenario: 'abac' });

const scenarios = compareScenarios(compare);
const current = ref(props.scenario);
// Log by default: the results span four orders of magnitude, so on a linear
// axis every sidecar bar would be invisible. The toggle shows the other view.
const scales = ['log', 'linear'] as const;
const scale = ref<(typeof scales)[number]>('log');
const model = computed(() => compareModel(compare, current.value, scale.value));
const caption = compareCaption(compare);
</script>

<template>
  <BenchBars :model="model" :caption="caption">
    <template #controls>
      <div class="kb-controls">
        <div class="kb-segmented" role="group" aria-label="Scenario">
          <button
            v-for="item in scenarios"
            :key="item.id"
            type="button"
            :aria-pressed="current === item.id"
            :class="{ 'is-on': current === item.id }"
            @click="current = item.id"
          >
            {{ item.title }}
          </button>
        </div>
        <div class="kb-segmented" role="group" aria-label="Axis scale">
          <button
            v-for="kind in scales"
            :key="kind"
            type="button"
            :aria-pressed="scale === kind"
            :class="{ 'is-on': scale === kind }"
            @click="scale = kind"
          >
            {{ kind === 'log' ? 'Log' : 'Linear' }}
          </button>
        </div>
      </div>
    </template>
  </BenchBars>
</template>

<style scoped>
.kb-controls {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 0.5rem;
  margin-bottom: 1rem;
}
.kb-segmented {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 2px;
  padding: 2px;
  border-radius: 8px;
  background: var(--vp-c-default-soft);
}
.kb-segmented button {
  padding: 0.3rem 0.7rem;
  border-radius: 6px;
  font-size: 0.78rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
  transition:
    color 0.2s,
    background-color 0.2s;
}
.kb-segmented button:hover {
  color: var(--vp-c-text-1);
}
.kb-segmented button.is-on {
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08);
}
.kb-segmented button:focus-visible {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: 1px;
}
</style>
