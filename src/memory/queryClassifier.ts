import { BlendPreset } from '../types/index';

export type QueryType = 'temporal' | 'exact' | 'semantic';

export interface ClassificationResult {
  type: QueryType;
  recommendedBlend: number; // weight for vector similarity
  boostDecay?: boolean;
}

const TEMPORAL_KEYWORDS = [
  'yesterday', 'today', 'recently', 'last week', 'last month', 'last year',
  'ago', 'since', 'before', 'after', 'current', 'latest'
];

const DATE_PATTERN = /\b(\d{1,2}\/\d{1,2}\/\d{2,4})|(\d{4}-\d{2}-\d{2})\b/;

const QUOTED_PATTERN = /["'].+?["']/;

export function classifyQuery(text: string): ClassificationResult {
  const lower = text.toLowerCase();

  // 1. Detect Temporal
  const isTemporal = TEMPORAL_KEYWORDS.some(kw => lower.includes(catMatch(kw))) || DATE_PATTERN.test(text);
  if (isTemporal) {
    return { type: 'temporal', recommendedBlend: 0.7, boostDecay: true };
  }

  // 2. Detect Exact Recall
  // Proper nouns heuristic: Uppercase words that aren't at the start of sentences
  const words = text.split(/\s+/);
  let properNounCount = 0;
  for (let i = 1; i < words.length; i++) {
    if (/^[A-Z][a-z]+/.test(words[i])) properNounCount++;
  }

  const isExact = properNounCount >= 2 || QUOTED_PATTERN.test(text);
  if (isExact) {
    return { type: 'exact', recommendedBlend: 0.6 };
  }

  // 3. Default: Semantic/Vague
  // Short queries or no specific entities
  return { type: 'semantic', recommendedBlend: 0.9 };
}

function catMatch(keyword: string): string {
  return keyword; // simple wrapper for now
}

export const BLEND_PRESETS: Record<BlendPreset, number> = {
  agent: 0.9,
  human: 0.7,
  balanced: 0.8,
};
