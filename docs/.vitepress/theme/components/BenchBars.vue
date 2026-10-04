<script setup lang="ts">
import { computed, ref } from 'vue';
// The chart models are shared with the README images (bench/report/svg.mjs),
// so the docs and the README cannot show different numbers.
import { allRows, createScale, formatValue } from '../../../../bench/report/model.mjs';

const props = defineProps<{ model: any; caption?: string | null }>();

const scale = computed(() =>
  createScale(
    allRows(props.model).map((row: any) => row.value),
    props.model.scale,
    props.model.unit,
  ),
);
const pct = (at: number) => `${(Math.max(0, Math.min(1, at)) * 100).toFixed(3)}%`;
const reference = computed(() =>
  props.model.reference === undefined ? null : pct(scale.value.at(props.model.reference)),
);

const body = ref<HTMLElement | null>(null);
const active = ref<{ row: any; top: number; left: number } | null>(null);

function show(row: any, event: Event) {
  const target = event.currentTarget as HTMLElement;
  const host = body.value;
  if (!host) return;
  const rowBox = target.getBoundingClientRect();
  const hostBox = host.getBoundingClientRect();
  const bar = target.querySelector('.kb-bar') as HTMLElement | null;
  const barEnd = bar ? bar.getBoundingClientRect().right - hostBox.left : rowBox.left - hostBox.left;
  const width = Math.min(280, hostBox.width);
  active.value = {
    row,
    top: rowBox.bottom - hostBox.top + 4,
    left: Math.max(0, Math.min(barEnd - width / 2, hostBox.width - width)),
  };
}

function hide() {
  active.value = null;
}

function ariaLabel(row: any) {
  const name = row.sublabel ? `${row.label} (${row.sublabel})` : row.label;
  return `${name}: ${row.details?.[0] ?? formatValue(row.value, props.model.unit)}`;
}
</script>

<template>
  <figure class="kb-chart">
    <slot name="controls" />
    <div class="kb-head">
      <div class="kb-title">{{ model.title }}</div>
      <div class="kb-subtitle">{{ model.subtitle }}</div>
    </div>

    <div ref="body" class="kb-body" @pointerleave="hide">
      <template v-for="group in model.groups" :key="group.id">
        <div v-if="group.label" class="kb-group">{{ group.label }}</div>
        <div
          v-for="row in group.rows"
          :key="row.id"
          class="kb-row"
          :class="{ 'is-hl': row.highlight, 'is-active': active?.row === row }"
          tabindex="0"
          :aria-label="ariaLabel(row)"
          @pointerenter="show(row, $event)"
          @focus="show(row, $event)"
          @blur="hide"
        >
          <div class="kb-label">
            <span class="kb-name">{{ row.label }}</span>
            <span v-if="row.sublabel" class="kb-sub">{{ row.sublabel }}</span>
          </div>
          <div class="kb-plot">
            <span v-for="tick in scale.ticks" :key="tick.value" class="kb-gridline" :style="{ left: pct(tick.at) }" />
            <span v-if="reference" class="kb-reference" :style="{ left: reference }" />
            <span class="kb-bar" :style="{ width: pct(scale.at(row.value)) }" />
            <span class="kb-value" :style="{ left: pct(scale.at(row.value)) }">{{ formatValue(row.value, model.unit) }}</span>
          </div>
        </div>
      </template>

      <div class="kb-row kb-axis" aria-hidden="true">
        <div class="kb-label" />
        <div class="kb-plot">
          <span v-for="tick in scale.ticks" :key="tick.value" class="kb-tick" :style="{ left: pct(tick.at) }">{{
            tick.label
          }}</span>
        </div>
      </div>

      <div v-if="active" class="kb-tooltip" :style="{ top: `${active.top}px`, left: `${active.left}px` }" role="status">
        <div class="kb-tooltip-value">{{ active.row.details?.[0] ?? formatValue(active.row.value, model.unit) }}</div>
        <div class="kb-tooltip-name">
          {{ active.row.label }}<template v-if="active.row.sublabel"> · {{ active.row.sublabel }}</template>
        </div>
        <div v-for="line in active.row.details?.slice(1) ?? []" :key="line" class="kb-tooltip-line">{{ line }}</div>
      </div>
    </div>

    <figcaption v-if="caption" class="kb-caption">{{ caption }}</figcaption>
  </figure>
</template>

<style scoped>
.kb-chart {
  --kb-accent: #b37e00;
  --kb-bar: #c6c5bf;
  --kb-label-w: 13.5rem;
  --kb-value-w: 3.75rem;
  --kb-row-h: 2.6rem;
  margin: 1.25rem 0 1.5rem;
  padding: 1.1rem 1.25rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  background: var(--vp-c-bg);
}
.dark .kb-chart {
  --kb-accent: #e3a500;
  --kb-bar: #55544f;
}

.kb-head {
  margin-bottom: 0.9rem;
}
.kb-title {
  font-size: 1rem;
  font-weight: 700;
  line-height: 1.4;
  color: var(--vp-c-text-1);
}
.kb-subtitle {
  font-size: 0.8rem;
  line-height: 1.45;
  color: var(--vp-c-text-2);
}

.kb-body {
  position: relative;
}
.kb-group {
  padding: 0.6rem 0 0.25rem;
  font-size: 0.68rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--vp-c-text-3);
}
.kb-row {
  display: grid;
  grid-template-columns: var(--kb-label-w) 1fr;
  column-gap: 0.75rem;
  align-items: stretch;
  min-height: var(--kb-row-h);
  border-radius: 6px;
  outline: none;
}
.kb-row:not(.kb-axis):hover,
.kb-row.is-active,
.kb-row:focus-visible {
  background: var(--vp-c-default-soft);
}
.kb-row:focus-visible {
  box-shadow: 0 0 0 2px var(--vp-c-brand-1);
}

.kb-label {
  display: flex;
  flex-direction: column;
  justify-content: center;
  min-width: 0;
  padding: 0.2rem 0 0.2rem 0.4rem;
}
.kb-name {
  font-size: 0.85rem;
  font-weight: 600;
  line-height: 1.3;
  color: var(--vp-c-text-1);
}
.is-hl .kb-name {
  font-weight: 700;
}
.kb-sub {
  overflow: hidden;
  font-size: 0.72rem;
  line-height: 1.3;
  color: var(--vp-c-text-2);
  white-space: nowrap;
  text-overflow: ellipsis;
}

.kb-plot {
  position: relative;
  margin-right: var(--kb-value-w);
}
.kb-gridline,
.kb-reference {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--vp-c-divider);
}
.kb-gridline:first-child {
  background: var(--vp-c-border);
}
.kb-reference {
  background: var(--vp-c-text-3);
}
.kb-bar {
  position: absolute;
  top: 50%;
  left: 0;
  min-width: 2px;
  height: 14px;
  transform: translateY(-50%);
  border-radius: 0 4px 4px 0;
  background: var(--kb-bar);
  transition: width 0.25s ease;
}
.is-hl .kb-bar {
  background: var(--kb-accent);
}
.kb-value {
  position: absolute;
  top: 50%;
  padding-left: 6px;
  transform: translateY(-50%);
  font-size: 0.78rem;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  color: var(--vp-c-text-2);
  white-space: nowrap;
  transition: left 0.25s ease;
}

.kb-axis {
  min-height: 1.6rem;
}
.kb-tick {
  position: absolute;
  top: 0.3rem;
  transform: translateX(-50%);
  font-size: 0.7rem;
  font-variant-numeric: tabular-nums;
  color: var(--vp-c-text-3);
  white-space: nowrap;
}

.kb-tooltip {
  position: absolute;
  z-index: 10;
  width: max-content;
  max-width: 280px;
  padding: 0.5rem 0.7rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg-elv);
  box-shadow: var(--vp-shadow-3);
  pointer-events: none;
}
.kb-tooltip-value {
  font-size: 0.85rem;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  color: var(--vp-c-text-1);
}
.kb-tooltip-name {
  margin-bottom: 0.15rem;
  font-size: 0.75rem;
  color: var(--vp-c-text-2);
}
.kb-tooltip-line {
  font-size: 0.72rem;
  line-height: 1.45;
  color: var(--vp-c-text-2);
}

.kb-caption {
  margin-top: 0.6rem;
  font-size: 0.72rem;
  line-height: 1.45;
  color: var(--vp-c-text-3);
}

@media (max-width: 640px) {
  .kb-chart {
    --kb-value-w: 3.25rem;
    padding: 0.9rem 0.75rem 0.8rem;
  }
  .kb-row {
    grid-template-columns: 1fr;
    min-height: 0;
  }
  .kb-label {
    padding-top: 0.35rem;
  }
  .kb-plot {
    height: 1.4rem;
  }
  .kb-axis .kb-label {
    display: none;
  }
}
</style>
