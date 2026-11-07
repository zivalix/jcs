import { createHash, createHmac } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { canonicalBytes, canonicalize, hash, hmac, isCanonical, JcsError, verifyHmac } from './index';

const KEY = new Uint8Array(32).fill(7);

function fromBits(hex: string): number {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(`0x${hex}`));
  return view.getFloat64(0);
}

function errorOf(fn: () => unknown): JcsError {
  try {
    fn();
  } catch (error) {
    if (error instanceof JcsError) return error;
    throw error;
  }
  throw new Error('expected a JcsError');
}

function setOwn(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

describe('RFC 8785 conformance', () => {
  test('§3.2.2 worked example', () => {
    const input = String.raw`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/","literals":[null,true,false]}`;
    const expected = String.raw`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`;
    expect(canonicalize(JSON.parse(input))).toBe(expected);
  });

  test('Appendix B number vectors', () => {
    const vectors: Array<[string, string]> = [
      ['0000000000000000', '0'],
      ['8000000000000000', '0'],
      ['0000000000000001', '5e-324'],
      ['8000000000000001', '-5e-324'],
      ['7fefffffffffffff', '1.7976931348623157e+308'],
      ['4340000000000000', '9007199254740992'],
      ['444b1ae4d6e2ef50', '1e+21'],
      ['3eb0c6f7a0b5ed8d', '0.000001'],
      ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
      ['41b3de4355555553', '333333333.3333332'],
      ['41b3de4355555557', '333333333.33333343'],
      ['3ff0000000000000', '1'],
    ];
    for (const [bits, expected] of vectors) expect(canonicalize(fromBits(bits))).toBe(expected);
  });

  test('§3.2.3 keys ordered by UTF-16 code units', () => {
    const obj: Record<string, number> = { '\u20ac': 1, '\r': 2, '\ufb33': 3, '1': 4, '\ud83d\ude00': 5, '\u0080': 6, '\u00f6': 7 };
    const order = ['\r', '1', '\u0080', '\u00f6', '\u20ac', '\ud83d\ude00', '\ufb33'];
    expect(canonicalize(obj)).toBe(`{${order.map((k) => `${JSON.stringify(k)}:${obj[k]}`).join(',')}}`);
  });

  test('integer-like keys sort lexicographically', () => {
    expect(canonicalize({ b: 0, '2': 1, '10': 2, a: 3 })).toBe('{"10":2,"2":1,"a":3,"b":0}');
  });

  test('§3.2.2.2 string escaping', () => {
    expect(canonicalize('\b\t\n\f\r')).toBe('"\\b\\t\\n\\f\\r"');
    expect(canonicalize('\u0000\u001f')).toBe('"\\u0000\\u001f"');
    expect(canonicalize('"\\/')).toBe('"\\"\\\\/"');
    expect(canonicalize('\u2028\u2029\u007f')).toBe('"\u2028\u2029\u007f"');
    expect(canonicalize('😀')).toBe('"😀"');
  });

  test('primitives and empty containers', () => {
    expect(canonicalize(null)).toBe('null');
    expect(canonicalize([true, false])).toBe('[true,false]');
    expect(canonicalize({})).toBe('{}');
    expect(canonicalize({ a: [], b: {} })).toBe('{"a":[],"b":{}}');
  });

  test('canonicalBytes is UTF-8', () => {
    expect(Array.from(canonicalBytes('€'))).toEqual([0x22, 0xe2, 0x82, 0xac, 0x22]);
  });
});

describe('isCanonical', () => {
  test('accepts canonical text', () => {
    expect(isCanonical('{"a":1,"b":[true,null,"x"]}')).toBe(true);
    expect(isCanonical('0')).toBe(true);
  });

  test.each([
    ['whitespace', '{"a": 1}'],
    ['trailing newline', '{"a":1}\n'],
    ['unsorted keys', '{"b":1,"a":2}'],
    ['duplicate keys', '{"a":1,"a":2}'],
    ['negative zero', '-0'],
    ['1.0', '1.0'],
    ['exponent form', '1E3'],
    ['uppercase hex escape', '"\\u00AF"'],
    ['needless slash escape', '"\\/"'],
    ['lone surrogate escape', '"\\ud800"'],
    ['unsafe integer', '9007199254740993'],
    ['overflow to Infinity', '1e999'],
    ['invalid JSON', '{"a":'],
    ['empty string', ''],
  ])('rejects %s', (_name, text) => {
    expect(isCanonical(text)).toBe(false);
  });

  test('never throws on hostile input', () => {
    expect(isCanonical(undefined as unknown as string)).toBe(false);
    expect(isCanonical('['.repeat(100_000) + ']'.repeat(100_000))).toBe(false);
  });
});

describe('prototype pollution and hostile shapes', () => {
  test('__proto__ from JSON.parse is data, never pollution', () => {
    const evil = JSON.parse('{"__proto__":{"polluted":true},"a":1}') as object;
    expect(canonicalize(evil)).toBe('{"__proto__":{"polluted":true},"a":1}');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  test('inherited properties are never serialized', () => {
    const proto = Object.prototype as unknown as Record<string, unknown>;
    proto.injected = 'evil';
    try {
      expect(canonicalize({ a: 1 })).toBe('{"a":1}');
    } finally {
      delete proto.injected;
    }
  });

  test('getters are rejected and never executed', () => {
    let calls = 0;
    const o = {};
    Object.defineProperty(o, 'x', { enumerable: true, get: () => ++calls });
    expect(errorOf(() => canonicalize(o)).message).toMatch(/accessor/);
    expect(calls).toBe(0);
  });

  test('class instances, Map, Date and Array subclasses are rejected', () => {
    class Foo { a = 1; }
    class Tagged extends Array {}
    for (const value of [new Foo(), new Map(), new Date(0), Tagged.from([1])]) {
      expect(() => canonicalize(value)).toThrow(JcsError);
      expect(() => canonicalize({ nested: value })).toThrow(JcsError);
    }
  });

  test('null-prototype array is rejected; null-prototype object is accepted', () => {
    const arr = [1];
    Object.setPrototypeOf(arr, null);
    expect(() => canonicalize(arr)).toThrow(JcsError);
    const obj = Object.create(null) as Record<string, unknown>;
    obj.b = 1;
    obj.a = 2;
    expect(canonicalize(obj)).toBe('{"a":2,"b":1}');
  });

  test('cross-realm values are accepted', () => {
    expect(canonicalize(runInNewContext('[1, { b: 2, a: [3] }]'))).toBe('[1,{"a":[3],"b":2}]');
  });

  test('enumerable symbol keys are rejected; non-enumerable ones are ignored', () => {
    expect(() => canonicalize({ [Symbol('s')]: 1 })).toThrow(/symbol/);
    const o: Record<string, unknown> = { a: 1 };
    Object.defineProperty(o, Symbol('hidden'), { value: 2, enumerable: false });
    expect(canonicalize(o)).toBe('{"a":1}');
  });

  test('non-index array properties are rejected', () => {
    expect(() => canonicalize(Object.assign([1], { foo: 'x' }))).toThrow(/non-index/);
  });

  test('non-enumerable non-index array property is ignored, not treated as a leak', () => {
    const arr: unknown[] = [1, 2, 3];
    Object.defineProperty(arr, 'hidden', { value: 'leak', enumerable: false, configurable: true });
    // Non-enumerable keys never reach JSON.stringify, so there is nothing to lose or reject here.
    expect(canonicalize(arr)).toBe('[1,2,3]');
  });

  test('error message stays bounded for a huge hostile key', () => {
    const error = errorOf(() => canonicalize({ ['k'.repeat(10_000)]: () => 1 }));
    expect(error.code).toBe('INVALID_VALUE');
    expect(error.message.length).toBeLessThan(200);
  });
});

describe('rejected values (no silent coercion)', () => {
  test('undefined-valued properties are omitted; undefined elsewhere is rejected', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(() => canonicalize(undefined)).toThrow(JcsError);
    expect(() => canonicalize([undefined])).toThrow(JcsError);
  });

  test('sparse arrays, functions, symbols and bigints are rejected', () => {
    // eslint-disable-next-line no-sparse-arrays
    expect(() => canonicalize([1, , 3])).toThrow(/sparse/);
    expect(() => canonicalize(() => 1)).toThrow(JcsError);
    expect(() => canonicalize([Symbol('x')])).toThrow(JcsError);
    expect(() => canonicalize({ n: 10n })).toThrow(JcsError);
  });

  test('NaN and Infinity are rejected; -0 becomes 0', () => {
    for (const n of [NaN, Infinity, -Infinity]) expect(() => canonicalize({ n })).toThrow(JcsError);
    expect(canonicalize(-0)).toBe('0');
  });

  test('lone surrogates are rejected in values and keys', () => {
    expect(() => canonicalize('\ud800')).toThrow(/lone surrogate/);
    expect(() => canonicalize('a\ud83dz')).toThrow(/lone surrogate/);
    expect(() => canonicalize({ '\udc00': 1 })).toThrow(/lone surrogate/);
    expect(canonicalize('\ud83d\ude00')).toBe('"😀"');
  });

  test('an unpaired low surrogate at the very end of a string is rejected', () => {
    expect(() => canonicalize('abc\udc00')).toThrow(/lone surrogate/);
    expect(() => canonicalize({ k: 'x\udfff' })).toThrow(/lone surrogate/);
  });

  test('astral keys sort by code units and stay consistent with their escaped form', () => {
    // U+1F600 is the surrogate pair D83D DE00, which sorts after U+0061 and before U+FB33.
    expect(canonicalize({ '\ud83d\ude00': 1, a: 2 })).toBe('{"a":2,"😀":1}');
    expect(isCanonical('{"a":2,"😀":1}')).toBe(true);
    expect(isCanonical('{"😀":1,"a":2}')).toBe(false);
  });

  test('error carries code and exact path', () => {
    const error = errorOf(() => canonicalize({ a: [1, { b: NaN }] }));
    expect(error.code).toBe('INVALID_VALUE');
    expect(error.path).toBe('$["a"][1]["b"]');
  });
});

describe('resource limits', () => {
  test('circular references throw instead of overflowing the stack', () => {
    const o: Record<string, unknown> = {};
    o.self = o;
    expect(() => canonicalize(o)).toThrow(/circular/);
  });

  test('shared, non-circular references are allowed', () => {
    const shared = { x: 1 };
    expect(canonicalize({ a: shared, b: shared })).toBe('{"a":{"x":1},"b":{"x":1}}');
  });

  test('depth limit is enforced', () => {
    let deep: unknown = [];
    for (let i = 0; i < 10_000; i++) deep = [deep];
    expect(errorOf(() => canonicalize(deep)).code).toBe('LIMIT_EXCEEDED');
  });

  test('exponential shared-reference blowup is stopped by maxLength', () => {
    let n: unknown = 1;
    for (let i = 0; i < 40; i++) n = [n, n];
    expect(() => canonicalize(n, { maxLength: 10_000 })).toThrow(/maxLength/);
  });

  test('maxLength counts the escaped output exactly', () => {
    // '"\\u0001"' is 8 characters after escaping, so a limit of 7 must reject it.
    expect(canonicalize('\u0001', { maxLength: 8 })).toBe('"\\u0001"');
    expect(() => canonicalize('\u0001', { maxLength: 7 })).toThrow(/maxLength/);
  });

  test('maxEntries is enforced', () => {
    expect(errorOf(() => canonicalize({ a: 1, b: 2 }, { maxEntries: 1 })).code).toBe('LIMIT_EXCEEDED');
    expect(errorOf(() => canonicalize([1, 2], { maxEntries: 1 })).code).toBe('LIMIT_EXCEEDED');
  });

  test('invalid options throw INVALID_OPTION', () => {
    for (const bad of [0, -1, 1.5, NaN]) {
      expect(errorOf(() => canonicalize(1, { maxDepth: bad })).code).toBe('INVALID_OPTION');
    }
  });
});

describe('hash', () => {
  test('SHA-256 of "{}" matches the known digest', async () => {
    expect(await hash({})).toBe('44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');
  });

  test('matches node:crypto over the canonical text, independent of key order', async () => {
    const value = { z: [1, { y: 'é😀' }], a: null };
    expect(await hash(value)).toBe(createHash('sha256').update(canonicalize(value), 'utf8').digest('hex'));
    expect(await hash({ a: 1, b: 2 })).toBe(await hash({ b: 2, a: 1 }));
  });

  test('rejects on unsupported values', async () => {
    await expect(hash(undefined)).rejects.toThrow(JcsError);
  });
});

describe('hmac and verifyHmac', () => {
  test('matches node:crypto HMAC-SHA256 over the canonical text', async () => {
    const value = { z: [1, { y: 'é😀' }], a: null };
    expect(await hmac(KEY, value)).toBe(createHmac('sha256', KEY).update(canonicalize(value), 'utf8').digest('hex'));
  });

  test('verifies valid signatures regardless of key order', async () => {
    const sig = await hmac(KEY, { a: 1, b: 2 });
    expect(await verifyHmac(KEY, { b: 2, a: 1 }, sig)).toBe(true);
  });

  test('rejects tampered body, wrong key, wrong signature', async () => {
    const sig = await hmac(KEY, { amount: 100 });
    expect(await verifyHmac(KEY, { amount: 101 }, sig)).toBe(false);
    expect(await verifyHmac(new Uint8Array(32).fill(8), { amount: 100 }, sig)).toBe(false);
    expect(await verifyHmac(KEY, { amount: 100 }, '0'.repeat(64))).toBe(false);
  });

  test('rejects malformed signature encodings without throwing', async () => {
    const sig = await hmac(KEY, {});
    for (const candidate of [sig.toUpperCase(), sig.slice(0, 63), `${sig}0`, 'zz'.repeat(32), undefined, 42]) {
      expect(await verifyHmac(KEY, {}, candidate as string)).toBe(false);
    }
  });

  test('returns false when the body cannot be canonicalized', async () => {
    expect(await verifyHmac(KEY, { t: NaN }, await hmac(KEY, {}))).toBe(false);
  });

  test('keys shorter than 32 bytes throw, even with a malformed signature', async () => {
    await expect(hmac(new Uint8Array(16), {})).rejects.toThrow(/at least 32 bytes/);
    await expect(verifyHmac(new Uint8Array(4), {}, 'not-hex')).rejects.toThrow(/at least 32 bytes/);
  });

  test('the key length boundary is exact: 31 bytes rejects, 32 bytes accepts', async () => {
    await expect(hmac(new Uint8Array(31), {})).rejects.toThrow(/at least 32 bytes/);
    await expect(verifyHmac(new Uint8Array(31), {}, '0'.repeat(64))).rejects.toThrow(/at least 32 bytes/);
    const sig = await hmac(new Uint8Array(32), {});
    expect(await verifyHmac(new Uint8Array(32), {}, sig)).toBe(true);
  });

  test('a key view with a non-zero byteOffset signs the same slice, not the whole buffer', async () => {
    const backing = new Uint8Array(64).fill(9);
    const middle = new Uint8Array(backing.buffer, 16, 32);
    expect(await hmac(middle, { a: 1 })).toBe(await hmac(new Uint8Array(32).fill(9), { a: 1 }));
  });
});

describe('deterministic property checks', () => {
  let state = 987654321;
  const rand = (): number => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
  const int = (min: number, max: number): number => min + Math.floor(rand() * (max - min + 1));
  const POOL = ['a', 'Z', '0', ' ', '"', '\\', '\n', '\u0000', '\u007f', 'é', '€', '\u2028', '😀', '\ufb33'];
  const randString = (): string => Array.from({ length: int(0, 6) }, () => POOL[int(0, POOL.length - 1)]).join('');

  function gen(depth: number): unknown {
    const r = rand();
    if (depth <= 0 || r < 0.35) {
      const kind = int(0, 3);
      if (kind === 0) return null;
      if (kind === 1) return rand() < 0.5;
      if (kind === 2) return rand() < 0.5 ? int(-1000, 1000) : (rand() - 0.5) * 10 ** int(-20, 20);
      return randString();
    }
    if (r < 0.65) return Array.from({ length: int(0, 4) }, () => gen(depth - 1));
    const o: Record<string, unknown> = {};
    for (let i = int(0, 4); i > 0; i--) {
      const key = rand() < 0.05 ? '__proto__' : randString();
      setOwn(o, key, gen(depth - 1));
    }
    return o;
  }

  function reverseKeys(v: unknown): unknown {
    if (Array.isArray(v)) return v.map(reverseKeys);
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v).reverse()) setOwn(out, k, reverseKeys((v as Record<string, unknown>)[k]));
      return out;
    }
    return v;
  }

  test('canonical form is idempotent, order-independent and self-recognized', () => {
    for (let i = 0; i < 300; i++) {
      const value = gen(4);
      const text = canonicalize(value);
      expect(canonicalize(JSON.parse(text))).toBe(text);
      expect(canonicalize(reverseKeys(value))).toBe(text);
      expect(isCanonical(text)).toBe(true);
    }
  });
});

describe('options', () => {
  test('non-object options are rejected', () => {
    expect(errorOf(() => canonicalize(1, 'abc' as unknown as null)).code).toBe('INVALID_OPTION');
    expect(errorOf(() => canonicalize(1, [] as unknown as null)).code).toBe('INVALID_OPTION');
  });
});

describe('fail-fast guards (memory and parse avoidance)', () => {
  test('a string that cannot fit is rejected before it is escaped or buffered', () => {
    const huge = 'a'.repeat(1_000_000);
    // 1e6 + 2 > 100: the guard fires on the raw length, before JSON.stringify allocates a copy.
    expect(errorOf(() => canonicalize(huge, { maxLength: 100 })).code).toBe('LIMIT_EXCEEDED');
    // A string that fits exactly is still accepted.
    expect(canonicalize('ab', { maxLength: 4 })).toBe('"ab"');
  });

  test('the escaped form can still be what trips the limit, not just the raw length', () => {
    // Raw length fits the budget, escaping does not: '\u0001' -> 8 units.
    expect(() => canonicalize('\u0001', { maxLength: 7 })).toThrow(/maxLength/);
  });

  test('isCanonical short-circuits oversized text without parsing it', () => {
    const text = `[${'1,'.repeat(50_000)}1]`;
    expect(isCanonical(text, { maxLength: 10 })).toBe(false);
    // The same text is canonical under the default limit, so the guard must not misfire.
    expect(isCanonical(text)).toBe(true);
  });
});
