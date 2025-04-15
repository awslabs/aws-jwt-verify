import { SimpleLruCache } from "../../src/cache";

describe("unit test SimpleLruCache", () => {
  test("should throw an error if capacity is less than 1", () => {
    expect(() => new SimpleLruCache<number, number>(0)).toThrow(
      "capacity must be greater than 0, but got 0"
    );
  });

  test("should initialize with the correct capacity", () => {
    const cache = new SimpleLruCache<number, number>(2);
    expect(cache.capacity).toBe(2);
  });

  test("should return undefined for a non-existent key", () => {
    const cache = new SimpleLruCache<number, number>(2);
    expect(cache.get(1)).toBeUndefined();
  });

  test("should set and get a value", () => {
    const cache = new SimpleLruCache<number, number>(2);
    cache.set(1, 100);
    expect(cache.get(1)).toBe(100);
  });

  test("should evict the least recently used item when capacity is exceeded", () => {
    const cache = new SimpleLruCache<number, number>(2);
    cache.set(1, 100);
    cache.set(2, 200);
    cache.set(3, 300);
    expect(cache.get(1)).toBeUndefined();
    expect(cache.get(2)).toBe(200);
    expect(cache.get(3)).toBe(300);
  });

  test("should move accessed item to the most recent position", () => {
    const cache = new SimpleLruCache<number, number>(2);
    cache.set(1, 100);
    cache.set(2, 200);
    cache.get(1);
    cache.set(3, 300);
    expect(cache.get(2)).toBeUndefined();
    expect(cache.get(1)).toBe(100);
    expect(cache.get(3)).toBe(300);
  });

  test("should return the correct size", () => {
    const cache = new SimpleLruCache<number, number>(2);
    expect(cache.size).toBe(0);
    cache.set(1, 100);
    expect(cache.size).toBe(1);
    cache.set(2, 200);
    expect(cache.size).toBe(2);
    cache.set(3, 300);
    expect(cache.size).toBe(2);
  });

  test("should convert the cache to an array in the correct order", () => {
    const cache = new SimpleLruCache<number, number>(2);
    cache.set(1, 100);
    cache.set(2, 200);
    expect(cache.toArray()).toEqual([
      [1, 100],
      [2, 200],
    ]);
    cache.get(1);
    cache.set(3, 300);
    expect(cache.toArray()).toEqual([
      [1, 100],
      [3, 300],
    ]);
  });
});
