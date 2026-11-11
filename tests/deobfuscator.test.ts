import { describe, expect, it } from 'vitest';
import { deobfuscatePowerShell } from '@/components/tenant-powershell/deobfuscator';

// Harmless words only: the dev machine runs Cynet EDR, so these tests exercise the parsing steps
// and never contain real attack command lines.
const output = (script: string) => deobfuscatePowerShell(script).deobfuscatedScript;

describe('deobfuscation steps', () => {
  it('joins char codes concatenated with +', () => {
    expect(output('([char]72+[char]73)')).toBe("('HI')");
  });

  it('resolves format operators', () => {
    expect(output(`("{1}{0}" -f 'lo','hel')`)).toBe("'hello'");
  });

  it('leaves a format operator with a missing argument alone', () => {
    const script = `"{0}{1}" -f 'a'`;
    expect(output(script)).toBe(script);
  });

  it('joins string concatenation', () => {
    expect(output("'he'+'ll'+'o'")).toBe("'hello'");
  });

  it('removes backticks from words', () => {
    expect(output('he`ll`o')).toBe('hello');
  });

  it('resolves single-digit, hex and mixed-case char codes', () => {
    expect(output('[char]9')).toBe("'\t'");
    expect(output('[CHAR]0x41')).toBe("'A'");
  });

  it('keeps an apostrophe char code as a valid string', () => {
    expect(output('[char]39')).toBe(`"'"`);
  });
});

describe('verdict', () => {
  it('does not treat the word bypass as an indicator', () => {
    expect(deobfuscatePowerShell('Write-Host "Bypass the proxy for internal sites"').detectedIndicators).toEqual([]);
  });

  it('reports no match as no indicators, never as clean', () => {
    expect(deobfuscatePowerShell('Get-Process | Sort-Object CPU').threatSeverity).toBe('NO_INDICATORS');
    expect(deobfuscatePowerShell('').threatSeverity).toBe('NO_INDICATORS');
  });
});
