/** Split text into segments for safe keyword highlighting (no innerHTML). */
export function highlightSegments(text, term) {
  if (!text || !term || term.length < 2) {
    return [{ text: text || "", match: false }];
  }
  const lower = text.toLowerCase();
  const tLower = term.toLowerCase();
  const segments = [];
  let pos = 0;
  while (pos < text.length) {
    const idx = lower.indexOf(tLower, pos);
    if (idx === -1) {
      segments.push({ text: text.slice(pos), match: false });
      break;
    }
    if (idx > pos) segments.push({ text: text.slice(pos, idx), match: false });
    segments.push({ text: text.slice(idx, idx + term.length), match: true });
    pos = idx + term.length;
  }
  return segments.length ? segments : [{ text, match: false }];
}
