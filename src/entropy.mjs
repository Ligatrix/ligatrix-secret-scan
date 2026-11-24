/**
 * Shannon entropy in bits per character.
 *
 * Random credentials sit around 4 to 6 bits per character; words, placeholders
 * and repeated characters sit well below 3. Rules use this to drop matches
 * that have the right shape but are plainly not a real credential.
 *
 * @param {string} value
 * @returns {number}
 */
export function shannonEntropy(value) {
  if (typeof value !== 'string' || value.length === 0) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const length = [...value].length;
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * Round to two decimals for stable output.
 * @param {number} value
 */
export function roundEntropy(value) {
  return Math.round(value * 100) / 100;
}
