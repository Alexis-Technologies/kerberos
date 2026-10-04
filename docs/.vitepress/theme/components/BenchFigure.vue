<script setup lang="ts">
import { computed } from 'vue';
import compare from '../../../../bench/results/compare.json';
import engine from '../../../../bench/results/engine.json';
import size from '../../../../bench/results/size.json';
import {
  coldStartModel,
  engineModel,
  latestRelease,
  machineCaption,
  releaseModel,
  sizeModel,
} from '../../../../bench/report/model.mjs';
import BenchBars from './BenchBars.vue';

const props = defineProps<{ chart: 'coldstart' | 'size' | 'engine' | 'releases' }>();

const figure = computed(() => {
  switch (props.chart) {
    case 'coldstart':
      return { model: coldStartModel(compare), caption: machineCaption(compare.machine) };
    case 'size':
      return { model: sizeModel(size), caption: null };
    case 'engine':
      return { model: engineModel(engine), caption: machineCaption(latestRelease(engine).machine) };
    case 'releases':
      return { model: releaseModel(engine), caption: machineCaption(latestRelease(engine).machine) };
  }
});
</script>

<template>
  <BenchBars v-if="figure.model" :model="figure.model" :caption="figure.caption" />
</template>
