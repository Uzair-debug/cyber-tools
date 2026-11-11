import type zxcvbn from 'zxcvbn';
import { PasswordAnalysis, AttackScenario, DetectedPattern } from './types';

// zxcvbn (Dropbox) does the pattern matching: 30k leaked passwords, English Wikipedia words, names,
// l33t-speak, keyboard walks, repeats, sequences and dates. It is ~800 KB, so the page loads it lazily
// and passes it in here. Everything runs in the browser.
export type PasswordEstimator = typeof zxcvbn;
type Match = zxcvbn.ZXCVBNSequence;

// zxcvbn slows down sharply on very long input; nothing past this changes a strength verdict
const MAX_ANALYZED_LENGTH = 100;

const DICTIONARY_LABELS: Record<string, string> = {
  passwords: 'leaked-password lists',
  english_wikipedia: 'common English words',
  female_names: 'common first names',
  male_names: 'common first names',
  surnames: 'common surnames',
  us_tv_and_film: 'common words from TV and film',
  user_inputs: 'user-specific words',
};

function describeMatch(m: Match, bits: number): DetectedPattern {
  const b = `~${bits} bits`;
  switch (m.pattern) {
    case 'dictionary': {
      const source = DICTIONARY_LABELS[m.dictionary_name] || 'wordlists';
      const extras = [m.l33t ? `leet-speak for "${m.matched_word}"` : '', m.reversed ? 'written backwards' : ''].filter(Boolean).join(', ');
      return {
        type: 'DICTIONARY_WORD',
        token: m.token,
        entropyCostBits: bits,
        description: `Rank ${m.rank.toLocaleString()} in ${source}${extras ? ` (${extras})` : ''}. ${b}.`,
      };
    }
    case 'spatial':
      return { type: 'SEQUENCE', token: m.token, entropyCostBits: bits, description: `Keyboard pattern on the ${(m as Match & { graph?: string }).graph || "keyboard"} layout. ${b}.` };
    case 'sequence':
      return { type: 'SEQUENCE', token: m.token, entropyCostBits: bits, description: `Character sequence ("abc", "6543" style). ${b}.` };
    case 'repeat':
      return { type: 'REPEAT', token: m.token, entropyCostBits: bits, description: `"${m.base_token}" repeated ${m.repeat_count} times. ${b}.` };
    case 'regex':
      return { type: 'YEAR', token: m.token, entropyCostBits: bits, description: `Recent year. ${b}.` };
    case 'date':
      return { type: 'YEAR', token: m.token, entropyCostBits: bits, description: `Looks like a date. ${b}.` };
    default:
      return { type: 'RANDOM_SEGMENT', token: m.token, entropyCostBits: bits, description: `No pattern found: guessed by brute force. ${b}.` };
  }
}

// zxcvbn charges brute-force characters at ~3.3 bits each and only knows years up to 2019, so the parts it
// leaves as brute force are re-scored here: recent years, repeats, pronounceable word-like tokens (jargon,
// names it doesn't list) and true random characters at the password's real character-set size.

// Leet characters read as the letter they stand in for when looking for words
const DELEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i' };
// Short digit/symbol runs beside words are separators or suffixes from small common sets
const SHORT_SUFFIX_BITS = Math.log2(10);

interface ResidualToken {
  token: string;
  bits: number;
  kind: 'year' | 'repeat' | 'word' | 'random';
}

// Three-consonant clusters that occur in English words; any other run of 3+ consonants reads as random
const CONSONANT_TRIOS = new Set(['str', 'spr', 'scr', 'spl', 'sch', 'thr', 'chr', 'shr', 'phr', 'ght', 'nch', 'tch', 'nth', 'rst', 'nst', 'mpl', 'ngl', 'ndl', 'rch', 'nds', 'nts', 'rts', 'lls', 'ngs', 'cks']);

// Pronounceable letters rather than random ones: sane vowel ratio, no unusual consonant or vowel clusters
function isWordLike(plain: string): boolean {
  if (plain.length < 3) return false;
  const vowels = (plain.match(/[aeiouy]/g) || []).length / plain.length;
  if (vowels < 0.25 || vowels > 0.6 || /[aeiouy]{3,}/.test(plain) || /[^aeiouy]{4,}/.test(plain)) return false;
  const trios = plain.match(/[^aeiouy]{3}/g) || [];
  return trios.every(t => CONSONANT_TRIOS.has(t));
}

// Minimum-cost split of a brute-force segment into word-like tokens and single characters
function splitWords(text: string, charBits: (ch: string) => number): ResidualToken[] {
  const n = text.length;
  const dp: number[] = new Array(n + 1).fill(Infinity);
  const back: Array<{ from: number; bits: number; kind: 'word' | 'random' } | null> = new Array(n + 1).fill(null);
  dp[0] = 0;
  for (let i = 0; i < n; i++) {
    if (dp[i] === Infinity) continue;
    const c = charBits(text[i]);
    if (dp[i] + c < dp[i + 1]) {
      dp[i + 1] = dp[i] + c;
      back[i + 1] = { from: i, bits: c, kind: 'random' };
    }
    for (let len = 4; len <= Math.min(12, n - i); len++) {
      const raw = text.substring(i, i + len);
      const plain = Array.from(raw, ch => DELEET[ch] || ch.toLowerCase()).join('');
      if (!/^[a-z]+$/.test(plain)) break;
      // Leet-speak only counts inside a word; a trailing "@" or "!" is a separator
      if (!/^[a-zA-Z].*[a-zA-Z]$/.test(raw)) continue;
      const letters = raw.replace(/[^a-zA-Z]/g, '');
      const leetCount = raw.length - letters.length;
      if (leetCount > 2 || leetCount * 4 > raw.length) continue;
      // Capitalisation an attacker would try: lower, Title, UPPER, or CamelCase jargon like "SecOps"
      const camel = /^[A-Z][a-z]+[A-Z][a-z]+$/.test(raw) ? raw.split(/(?=[A-Z])/) : null;
      const caseBits = /^[a-z]+$/.test(letters) ? 0 : /^[A-Z][a-z]*$/.test(letters) || /^[A-Z]+$/.test(letters) ? 1 : camel ? 2 : null;
      if (caseBits === null || !isWordLike(plain)) continue;
      if (camel && !camel.every(part => isWordLike(part.toLowerCase()))) continue;
      const bits = 13 + caseBits + leetCount; // ~10,000-word dictionary, plus casing and leet
      if (dp[i] + bits < dp[i + len]) {
        dp[i + len] = dp[i] + bits;
        back[i + len] = { from: i, bits, kind: 'word' };
      }
    }
  }
  const out: ResidualToken[] = [];
  for (let at = n; at > 0; ) {
    const b = back[at]!;
    const token = text.slice(b.from, at);
    const prev = out[0];
    if (b.kind === 'random' && prev && prev.kind === 'random') {
      prev.token = token + prev.token;
      prev.bits += b.bits;
    } else {
      out.unshift({ token, bits: b.bits, kind: b.kind });
    }
    at = b.from;
  }
  return out;
}

function scoreResidual(text: string, fullCharBits: number, structured: boolean): ResidualToken[] {
  const tokens: ResidualToken[] = [];
  // Years 1900-2099 not inside a longer digit run, and runs of one repeated character
  const fixedRe = /(?<!\d)(?:19|20)\d{2}(?!\d)|(.)\1{2,}/g;
  const charBits = (ch: string) => (structured && !/[a-zA-Z]/.test(ch) ? SHORT_SUFFIX_BITS : fullCharBits);
  let cursor = 0;
  let m: RegExpExecArray | null;
  const pushFree = (slice: string) => {
    for (const t of splitWords(slice, charBits)) {
      // A random run longer than a short suffix is charged at the full character set
      if (t.kind === 'random' && t.token.length > 3) t.bits = t.token.length * fullCharBits;
      tokens.push(t);
    }
  };
  while ((m = fixedRe.exec(text)) !== null) {
    if (m.index > cursor) pushFree(text.slice(cursor, m.index));
    tokens.push(
      m[1] === undefined
        ? { token: m[0], bits: Math.log2(100), kind: 'year' }
        : { token: m[0], bits: fullCharBits + Math.log2(m[0].length), kind: 'repeat' }
    );
    cursor = m.index + m[0].length;
  }
  if (cursor < text.length) pushFree(text.slice(cursor));
  return tokens;
}

function residualPattern(t: ResidualToken): DetectedPattern {
  const bits = Math.round(t.bits * 10) / 10;
  const b = `~${bits} bits`;
  switch (t.kind) {
    case 'year':
      return { type: 'YEAR', token: t.token, entropyCostBits: bits, description: `Year (about 100 likely candidates). ${b}.` };
    case 'repeat':
      return { type: 'REPEAT', token: t.token, entropyCostBits: bits, description: `One character repeated ${t.token.length} times. ${b}.` };
    case 'word':
      return { type: 'DICTIONARY_WORD', token: t.token, entropyCostBits: bits, description: `Word-like token a dictionary attack would try (not in zxcvbn's lists). ${b}.` };
    default:
      return t.token.length === 1 && /[^a-zA-Z0-9]/.test(t.token)
        ? { type: 'DELIMITER', token: t.token, entropyCostBits: bits, description: `Separator symbol. ${b}.` }
        : { type: 'RANDOM_SEGMENT', token: t.token, entropyCostBits: bits, description: `No pattern found: guessed by brute force. ${b}.` };
  }
}

export function analyzePassword(password: string, estimate: PasswordEstimator): PasswordAnalysis {
  if (!password) {
    return {
      passwordLength: 0,
      entropy: 0,
      theoreticalEntropy: 0,
      score: 0,
      label: 'Empty',
      crackTimeOfflineBruteForce: 'Instant (< 1 millisecond)',
      crackTimeOnlineSlow: 'Instant (< 1 millisecond)',
      crackTimeSlowHash: 'Instant (< 1 millisecond)',
      crackTimePureBruteForce: 'Instant (< 1 millisecond)',
      detectedPatterns: [],
      attackScenarios: [],
      charDistribution: { lowercase: 0, uppercase: 0, digits: 0, special: 0 },
      warnings: ['Please enter a password to analyze.'],
      suggestions: ['Use at least 15+ characters with random words or characters generated by a password manager.'],
    };
  }

  const length = password.length;
  let poolSize = 0;

  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);

  const lowercaseCount = (password.match(/[a-z]/g) || []).length;
  const uppercaseCount = (password.match(/[A-Z]/g) || []).length;
  const digitsCount = (password.match(/[0-9]/g) || []).length;
  const specialCount = (password.match(/[^a-zA-Z0-9]/g) || []).length;

  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasDigit) poolSize += 10;
  if (hasSpecial) poolSize += 33;

  // 1. Raw Theoretical Shannon Entropy (Pure Uniform Randomness Assumption)
  const theoreticalEntropy = Math.round(length * Math.log2(poolSize || 1) * 10) / 10;

  // 2. Pattern-aware estimate: zxcvbn's matches, with its brute-force gaps re-scored by scoreResidual
  const fullCharBits = Math.log2(poolSize || 1);
  const analyzed = password.slice(0, MAX_ANALYZED_LENGTH);
  const sequence = estimate(analyzed).sequence;
  const structuredByZxcvbn = sequence.some(m => m.pattern !== 'bruteforce');
  const firstPass = sequence.flatMap(m => (m.pattern === 'bruteforce' ? scoreResidual(m.token, fullCharBits, false) : []));
  const structured = structuredByZxcvbn || firstPass.some(t => t.kind !== 'random');

  const detectedPatterns: DetectedPattern[] = [];
  for (const m of sequence) {
    if (m.pattern === 'bruteforce') {
      detectedPatterns.push(...scoreResidual(m.token, fullCharBits, structured).map(residualPattern));
    } else {
      detectedPatterns.push(describeMatch(m, Math.round(Math.log2(Math.max(1, m.guesses)) * 10) / 10));
    }
  }
  if (length > analyzed.length) {
    const rest = password.slice(analyzed.length);
    detectedPatterns.push(residualPattern({ token: rest, bits: rest.length * fullCharBits, kind: 'random' }));
  }

  // Like zxcvbn, add log2(k!) for the attacker not knowing the order of k parts
  const k = detectedPatterns.length;
  let orderBits = 0;
  for (let i = 2; i <= k; i++) orderBits += Math.log2(i);
  const guessBits = detectedPatterns.reduce((sum, p) => sum + p.entropyCostBits, 0) + (k > 1 ? orderBits : 0);
  const effectiveEntropy = Math.max(0, Math.round(Math.min(guessBits, theoreticalEntropy) * 10) / 10);

  const dictionaryMatches = sequence.filter(m => m.pattern === 'dictionary');
  const isExactBreachMatch =
    sequence.length === 1 && sequence[0].pattern === 'dictionary' && sequence[0].dictionary_name === 'passwords' && !sequence[0].l33t && !sequence[0].reversed;
  const isTopBreachedVariant = !isExactBreachMatch && dictionaryMatches.some(m => m.dictionary_name === 'passwords' && m.rank <= 1000);
  const hasCompoundWords = detectedPatterns.filter(p => p.type === 'DICTIONARY_WORD').length >= 2;
  const hasYear = detectedPatterns.some(p => p.type === 'YEAR');
  const hasSequence = detectedPatterns.some(p => p.type === 'SEQUENCE');
  const hasRepeat = detectedPatterns.some(p => p.type === 'REPEAT');

  // A breached root only means "instant" when little else protects the password
  const isInstantBreach = isExactBreachMatch || (isTopBreachedVariant && effectiveEntropy < 20);

  // Warnings & suggestions
  const warnings: string[] = [];
  const suggestions: string[] = [];

  if (isExactBreachMatch) {
    warnings.push('🚨 EXACT BREACH LIST MATCH: This exact password is in public breach wordlists and is cracked in under a millisecond.');
    suggestions.push('Never use passwords found in public breach databases. Change this credential immediately.');
  } else if (isTopBreachedVariant) {
    warnings.push(
      isInstantBreach
        ? '🚨 BREACHED PASSWORD VARIANT: This is a variant of a top breached password (e.g. "password" / "admin"). Attackers test these variations first.'
        : 'Contains a variant of a top breached password (e.g. "password" / "admin"). Attackers try these first, so only the rest of the password is protecting it.'
    );
    suggestions.push('Avoid variations of "password", "admin", or common service account names, even with symbols like @, 0, or dots.');
  } else if (hasCompoundWords) {
    warnings.push('⚠️ DICTIONARY COMBINATOR / PRINCE VULNERABILITY: Built from dictionary words that attackers combine automatically.');
    suggestions.push('Joining 2-3 common words is cracked by Hashcat combinator (-a 1) and PRINCE attacks. Use 4+ randomly chosen words (Diceware) or a generated password.');
  }

  if (length > MAX_ANALYZED_LENGTH) {
    warnings.push(`Only the first ${MAX_ANALYZED_LENGTH} characters were checked for patterns; the rest are counted as random.`);
  }

  if (length < 8) {
    warnings.push('Critically short password (under 8 characters). An offline GPU attack can try every combination within hours or less.');
  } else if (length < 12 && !isInstantBreach) {
    warnings.push('Password is shorter than the modern recommended 14-16 character baseline.');
  }

  if (hasYear) {
    warnings.push('Contains a year or date. Attackers try these early.');
    suggestions.push('Avoid using calendar years, birth years, or current dates in passwords.');
  }

  if (hasSequence) {
    warnings.push('Contains keyboard walks or sequential sequences (e.g. "123", "abc", "qwerty").');
    suggestions.push('Eliminate sequential and keyboard walk patterns.');
  }

  if (hasRepeat) {
    warnings.push('Repeated characters or chunks detected (e.g. "aaa", "abcabc").');
    suggestions.push('Avoid repeating characters or chunks.');
  }

  // Score determination based on EFFECTIVE entropy
  let score: 0 | 1 | 2 | 3 | 4 = 0;
  let label = 'Very Weak';

  if (isInstantBreach) {
    score = 0;
    label = 'Critically Compromised / In Wordlists';
  } else if (effectiveEntropy < 28 || length < 7) {
    score = 0;
    label = 'Very Weak';
  } else if (effectiveEntropy < 42 || length < 10) {
    score = 1;
    label = 'Weak';
  } else if (effectiveEntropy < 60 || length < 12) {
    score = 2;
    label = 'Moderate';
  } else if (effectiveEntropy < 78 || length < 14) {
    score = 3;
    label = 'Strong';
  } else {
    score = 4;
    label = 'Very Strong';
  }

  // 3. Crack Time Calculations Across Real-World Attack Scenarios
  const effectiveCombinations = Math.pow(2, effectiveEntropy);
  const theoreticalCombinations = Math.pow(poolSize || 1, length);

  // A. Fast unsalted hash (NTLM / MD5): 100 billion guesses/sec, roughly one current high-end GPU
  const fastHashRate = 1e11;
  const fastHashSeconds = isInstantBreach
    ? 0.0001
    : Math.max(0.0001, effectiveCombinations / (fastHashRate * 2));

  // B. Rule-Based Dictionary & Mask Attack (Hashcat OneRule on RockYou): 10 Billion hashes/sec (10 GH/s)
  const ruleAttackRate = 1e10;
  const ruleAttackSeconds = isInstantBreach
    ? 0.0001
    : Math.max(0.0001, effectiveCombinations / (ruleAttackRate * 2));

  // C. Slow KDF (bcrypt cost 10): ~10,000 guesses/sec, roughly two current high-end GPUs
  const slowHashRate = 10000;
  const slowHashSeconds = isInstantBreach
    ? 0.05
    : Math.max(0.001, effectiveCombinations / (slowHashRate * 2));

  // D. Online Throttled Web Login (100 attempts / sec with rate-limiting / CAPTCHA)
  const onlineSlowRate = 100;
  const onlineSeconds = isInstantBreach
    ? 0.5
    : Math.max(0.001, effectiveCombinations / (onlineSlowRate * 2));

  // E. Pure Unguided Brute Force (Theoretical 100 GH/s)
  const pureBruteSeconds = theoreticalCombinations / (fastHashRate * 2);

  const crackTimeOfflineBruteForce = formatTimeEstimate(fastHashSeconds);
  const crackTimeOnlineSlow = formatTimeEstimate(onlineSeconds);
  const crackTimeSlowHash = formatTimeEstimate(slowHashSeconds);
  const crackTimePureBruteForce = formatTimeEstimate(pureBruteSeconds);

  // Build Attack Scenario Matrix
  const attackScenarios: AttackScenario[] = [
    {
      name: 'Fast Hash Offline Rig (NTLM / MD5)',
      hashSpeed: '100 GH/s (about one high-end GPU)',
      timeEstimate: crackTimeOfflineBruteForce,
      technique: isInstantBreach
        ? 'Direct RockYou / SecLists Wordlist Match'
        : hasCompoundWords
        ? 'Hashcat Combinator (-a 1) / Prince Attack'
        : hasYear
        ? 'Dictionary + Year Mask Attack'
        : 'Optimized GPU Keyspace Search',
      riskLevel: fastHashSeconds < 60 ? 'CRITICAL' : fastHashSeconds < 86400 ? 'HIGH' : fastHashSeconds < 31536000 ? 'MEDIUM' : 'LOW',
      explanation: isInstantBreach
        ? 'Found in public password leak wordlists. Cracked in under a millisecond on any GPU.'
        : hasCompoundWords
        ? 'Combinator attacks join wordlist tokens, so word-based passwords fall far faster than their length suggests.'
        : 'Speed when an Active Directory NTDS.dit database or unsalted password hash dump is cracked offline.',
    },
    {
      name: 'Rule-Based Wordlist Attack (RockYou + Hashcat)',
      hashSpeed: '10 GH/s (Mutated Dictionary)',
      timeEstimate: formatTimeEstimate(ruleAttackSeconds),
      technique: 'Wordlist Combinator & Rule Mutations',
      riskLevel: ruleAttackSeconds < 3600 ? 'CRITICAL' : ruleAttackSeconds < 604800 ? 'HIGH' : 'LOW',
      explanation: 'Applies common capitalizations, leet-speak substitutions, and numeric/symbol suffixes to wordlists.',
    },
    {
      name: 'Hardened KDF Hash (bcrypt cost 10)',
      hashSpeed: '10 kH/s (bcrypt cost 10)',
      timeEstimate: crackTimeSlowHash,
      technique: 'Throttled Key Derivation Function',
      riskLevel: slowHashSeconds < 60 ? 'CRITICAL' : slowHashSeconds < 86400 ? 'HIGH' : slowHashSeconds < 31536000 ? 'MEDIUM' : 'SECURE',
      explanation: 'Protection from slow, salted password hashing such as bcrypt. Argon2id with memory hardness is slower still.',
    },
    {
      name: 'Online Throttled Web Login (100 req/s)',
      hashSpeed: '100 requests/sec',
      timeEstimate: crackTimeOnlineSlow,
      technique: isInstantBreach ? 'Immediate Credential Stuffing Hit' : 'Targeted Web / API Credential Stuffing',
      riskLevel: onlineSeconds < 3600 ? 'CRITICAL' : 'SECURE',
      explanation: isInstantBreach
        ? 'Tested in the first 100 requests of any automated credential stuffing attack.'
        : 'Rate-limited login endpoints or cloud identity providers with smart lockout (e.g. Entra ID Smart Lockout).',
    },
  ];

  if (warnings.length === 0) {
    suggestions.push('No weaknesses found. Store it in a password manager and use it for this account only.');
  } else if (suggestions.length === 0) {
    suggestions.push('Use 15+ characters, ideally generated by a password manager.');
  }

  return {
    passwordLength: length,
    entropy: effectiveEntropy,
    theoreticalEntropy,
    score,
    label,
    crackTimeOfflineBruteForce,
    crackTimeOnlineSlow,
    crackTimeSlowHash,
    crackTimePureBruteForce,
    // A password with no patterns is one brute-force token; nothing to break down
    detectedPatterns: detectedPatterns.every(p => p.type === 'RANDOM_SEGMENT') ? [] : detectedPatterns,
    attackScenarios,
    charDistribution: {
      lowercase: lowercaseCount,
      uppercase: uppercaseCount,
      digits: digitsCount,
      special: specialCount,
    },
    warnings,
    suggestions,
  };
}

function formatTimeEstimate(seconds: number): string {
  if (seconds < 0.001) return 'Instant (< 1 millisecond)';
  if (seconds < 1) return '< 1 second';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes * 10) / 10} minutes`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours * 10) / 10} hours`;
  const days = hours / 24;
  if (days < 30) return `${Math.round(days)} days`;
  const months = days / 30;
  if (months < 12) return `${Math.round(months)} months`;
  const years = days / 365.25;
  if (years < 100) return `${Math.round(years)} years`;
  if (years < 10000) return `${Math.round(years).toLocaleString()} years`;
  if (years < 1e6) return `${Math.round(years / 1000)} thousand years`;
  if (years < 1e9) return `${Math.round(years / 1e6)} million years`;
  if (years < 1e12) return `${Math.round(years / 1e9)} billion years`;
  return 'Trillions of years';
}
