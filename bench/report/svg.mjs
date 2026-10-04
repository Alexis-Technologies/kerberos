/**
 * Renders a chart model (bench/report/model.mjs) as a standalone SVG for the
 * README, where no script runs: horizontal bars, direct value labels, a
 * hairline grid and an embedded stylesheet whose prefers-color-scheme block
 * re-colors it for dark mode (GitHub renders README images that way).
 * Text widths are estimated, not measured — long labels are truncated.
 */
import { allRows, createScale, formatValue } from './model.mjs';

const WIDTH = 760;
const PAD = 20;
const ROW = 40;
const BAR = 14;
const RADIUS = 4;
const GROUP = 28;
const VALUE_W = 64;
const CHAR = { label: 7.2, sublabel: 5.9, body: 6.4 };

const STYLE = `
  text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
  .title { font-size: 15px; font-weight: 700; fill: #1b1c1e; }
  .subtitle, .caption { font-size: 12px; fill: #67676c; }
  .caption { font-size: 11px; }
  .group { font-size: 11px; font-weight: 600; letter-spacing: 0.06em; fill: #67676c; }
  .label { font-size: 13px; font-weight: 600; fill: #1b1c1e; }
  .label.hl { font-weight: 700; }
  .sublabel { font-size: 11px; fill: #67676c; }
  .value { font-size: 12px; font-weight: 600; fill: #3c3c43; font-variant-numeric: tabular-nums; }
  .tick { font-size: 11px; fill: #67676c; font-variant-numeric: tabular-nums; }
  .grid { stroke: #e4e4e7; stroke-width: 1; }
  .axis, .ref { stroke: #c2c2c4; stroke-width: 1; }
  .ref { stroke: #67676c; }
  .bar { fill: #c6c5bf; }
  .bar.hl { fill: #b37e00; }
  @media (prefers-color-scheme: dark) {
    .title, .label { fill: #dfdfd6; }
    .subtitle, .caption, .group, .sublabel, .tick { fill: #98989f; }
    .value { fill: #c2c2c4; }
    .grid { stroke: #2e2e32; }
    .axis { stroke: #48484c; }
    .ref { stroke: #98989f; }
    .bar { fill: #55544f; }
    .bar.hl { fill: #e3a500; }
  }
`;

const escape = (text) => String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function truncate(text, width, charWidth) {
  const max = Math.floor(width / charWidth);
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}

function wrap(text, width, charWidth) {
  const max = Math.floor(width / charWidth);
  const lines = [];
  let line = '';
  for (const word of text.split(' ')) {
    if (line && line.length + word.length + 1 > max) {
      lines.push(line);
      line = word;
    } else line = line ? `${line} ${word}` : word;
  }
  if (line) lines.push(line);
  return lines;
}

/** A bar with a rounded data end and a square baseline end. */
function barPath(x0, y, length, height) {
  const r = Math.min(RADIUS, length, height / 2);
  const x1 = x0 + length;
  return `M${x0},${y}H${x1 - r}A${r},${r} 0 0 1 ${x1},${y + r}V${y + height - r}A${r},${r} 0 0 1 ${x1 - r},${y + height}H${x0}Z`;
}

export function renderSvg(model, { caption } = {}) {
  const rows = allRows(model);
  const widest = Math.max(
    ...rows.map((row) => Math.max(row.label.length * CHAR.label, (row.sublabel ?? '').length * CHAR.sublabel)),
  );
  const labelWidth = Math.min(340, Math.max(170, Math.ceil(widest) + 8));
  const x0 = PAD + labelWidth + 12;
  const x1 = WIDTH - PAD - VALUE_W;
  const scale = createScale(
    rows.map((row) => row.value),
    model.scale,
    model.unit,
  );
  const out = [];
  let y = PAD;

  out.push(`<text class="title" x="${PAD}" y="${y + 15}">${escape(model.title)}</text>`);
  y += 24;
  for (const line of wrap(model.subtitle, WIDTH - 2 * PAD, CHAR.body)) {
    out.push(`<text class="subtitle" x="${PAD}" y="${y + 12}">${escape(line)}</text>`);
    y += 17;
  }
  y += 10;

  const bodyTop = y;
  const marks = [];
  for (const group of model.groups) {
    if (group.label) {
      marks.push(`<text class="group" x="${PAD}" y="${y + 18}">${escape(group.label.toUpperCase())}</text>`);
      y += GROUP;
    }
    for (const row of group.rows) {
      const hl = row.highlight ? ' hl' : '';
      const length = Math.max(2, scale.at(row.value) * (x1 - x0));
      const title = escape(
        [`${row.label}${row.sublabel ? ` · ${row.sublabel}` : ''}`, ...(row.details ?? [])].join('\n'),
      );
      marks.push(`<g><title>${title}</title>`);
      if (row.sublabel) {
        marks.push(
          `<text class="label${hl}" x="${PAD}" y="${y + 17}">${escape(truncate(row.label, labelWidth, CHAR.label))}</text>`,
        );
        marks.push(
          `<text class="sublabel" x="${PAD}" y="${y + 32}">${escape(truncate(row.sublabel, labelWidth, CHAR.sublabel))}</text>`,
        );
      } else {
        marks.push(
          `<text class="label${hl}" x="${PAD}" y="${y + 24}">${escape(truncate(row.label, labelWidth, CHAR.label))}</text>`,
        );
      }
      const barY = y + (ROW - BAR) / 2;
      marks.push(`<path class="bar${hl}" d="${barPath(x0, barY, length, BAR)}"/>`);
      marks.push(
        `<text class="value" x="${x0 + length + 6}" y="${barY + BAR - 2}">${escape(formatValue(row.value, model.unit))}</text>`,
      );
      marks.push('</g>');
      y += ROW;
    }
  }
  const bodyBottom = y;

  for (const tick of scale.ticks) {
    const x = x0 + tick.at * (x1 - x0);
    out.push(`<line class="grid" x1="${x}" y1="${bodyTop}" x2="${x}" y2="${bodyBottom}"/>`);
    out.push(`<text class="tick" x="${x}" y="${bodyBottom + 16}" text-anchor="middle">${escape(tick.label)}</text>`);
  }
  out.push(`<line class="axis" x1="${x0}" y1="${bodyTop}" x2="${x0}" y2="${bodyBottom}"/>`);
  if (model.reference !== undefined) {
    const x = x0 + scale.at(model.reference) * (x1 - x0);
    out.push(`<line class="ref" x1="${x}" y1="${bodyTop}" x2="${x}" y2="${bodyBottom}"/>`);
  }
  out.push(...marks);
  y = bodyBottom + 30;

  if (caption) {
    for (const line of wrap(caption, WIDTH - 2 * PAD, 5.9)) {
      out.push(`<text class="caption" x="${PAD}" y="${y + 11}">${escape(line)}</text>`);
      y += 16;
    }
  }
  const height = y + PAD - 6;

  const label = `${model.title}. ${model.subtitle}`;
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${height}" viewBox="0 0 ${WIDTH} ${height}" role="img" aria-label="${escape(label)}">`,
    `<style>${STYLE}</style>`,
    ...out,
    '</svg>',
    '',
  ].join('\n');
}
