const Z95_ONE_SIDED = 1.6448536269514722;

function bound(successes, total, direction) {
  if (!Number.isInteger(successes) || !Number.isInteger(total)
    || total < 0 || successes < 0 || successes > total) {
    throw new TypeError('invalid Wilson sample');
  }
  if (total === 0) return null;

  const z2 = Z95_ONE_SIDED * Z95_ONE_SIDED;
  const p = successes / total;
  const center = (p + z2 / (2 * total)) / (1 + z2 / total);
  const margin = Z95_ONE_SIDED
    * Math.sqrt((p * (1 - p) / total) + (z2 / (4 * total * total)))
    / (1 + z2 / total);
  const result = direction === 'lower' ? center - margin : center + margin;
  return Math.max(0, Math.min(1, result));
}

export const wilsonLower = (successes, total) => bound(successes, total, 'lower');
export const wilsonUpper = (successes, total) => bound(successes, total, 'upper');
