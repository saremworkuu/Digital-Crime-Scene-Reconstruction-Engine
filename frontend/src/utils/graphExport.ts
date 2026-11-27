export interface SvgExportBox {
  minX: number;
  minY: number;
  width: number;
  height: number;
}

/**
 * Compute an uncropped SVG viewBox encompassing all positioned nodes (including
 * halos and bottom labels), optional DOM <g> bounding box, and generous padding.
 */
export function computeGraphExportBox(
  nodes: Array<{ id: string; label?: string }>,
  positions: Record<string, { x: number; y: number }>,
  domBBox?: { x: number; y: number; width: number; height: number } | null,
  fallbackSize: { width: number; height: number } = { width: 880, height: 520 },
  padding = 48
): SvgExportBox {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;

  for (const node of nodes) {
    const pos = positions[node.id];
    if (!pos) continue;
    const labelHalfWidth = Math.max(70, Math.min((node.label || '').length, 18) * 3.6 + 16);
    minX = Math.min(minX, pos.x - labelHalfWidth);
    maxX = Math.max(maxX, pos.x + labelHalfWidth);
    minY = Math.min(minY, pos.y - 32);
    maxY = Math.max(maxY, pos.y + 56);
  }

  if (
    domBBox &&
    Number.isFinite(domBBox.width) &&
    Number.isFinite(domBBox.height) &&
    (domBBox.width > 0 || domBBox.height > 0)
  ) {
    minX = Math.min(minX, domBBox.x);
    minY = Math.min(minY, domBBox.y);
    maxX = Math.max(maxX, domBBox.x + domBBox.width);
    maxY = Math.max(maxY, domBBox.y + domBBox.height);
  }

  if (!Number.isFinite(minX) || !Number.isFinite(minY) || !Number.isFinite(maxX) || !Number.isFinite(maxY)) {
    return { minX: 0, minY: 0, width: fallbackSize.width, height: fallbackSize.height };
  }

  const x = Math.floor(minX - padding);
  const y = Math.floor(minY - padding);
  const width = Math.max(240, Math.ceil(maxX - minX + padding * 2));
  const height = Math.max(200, Math.ceil(maxY - minY + padding * 2));
  return { minX: x, minY: y, width, height };
}
