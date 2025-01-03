import {
  SimpleLruCache,
} from "../../src/cache";

describe("unit tests cache", () => {

  test("CacheLru get undefined", () => {
    const cache = new SimpleLruCache<string,string>(2);
    return expect(cache.get("key1")).toBeUndefined();
  });

  test("CacheLru get value1 with 1 element", () => {
    const cache = new SimpleLruCache<string,string>(3);
    cache.set("key1","value1");

    expect(cache.size).toBe(1);
    expect(cache.toArray()).toStrictEqual([["key1","value1"]]);

    return expect(cache.get("key1")).toBe("value1");
  });

  test("CacheLru get value1 with 2 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);

    cache.set("key1","value1");
    cache.set("key2","value2");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(2);
    expect(cache.toArray()).toStrictEqual([["key1","value1"],["key2","value2"]]);

    return expect(cache.get("key1")).toBe("value1");
  });

  
  test("CacheLru get value1 with 3 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);

    cache.set("key1","value1");
    cache.set("key2","value2");
    cache.set("key3","value3");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(3);
    expect(cache.toArray()).toStrictEqual([["key1","value1"],["key2","value2"],["key3","value3"]]);

    return expect(cache.get("key1")).toBe("value1");
  });

  
  test("CacheLru get value 1 with 4 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);

    cache.set("key1","value1");
    cache.set("key2","value2");
    cache.set("key3","value3");
    cache.set("key4","value4");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(3);
    expect(cache.toArray()).toStrictEqual([["key2","value2"],["key3","value3"],["key4","value4"]]);

    return expect(cache.get("key1")).toBeUndefined();
  });
  

  test("CacheLru change priority value1 with 2 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);
   
    cache.set("key1","value1");
    cache.set("key2","value2");
  
    const value = cache.get("key1");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(2);
    expect(cache.toArray()).toStrictEqual([["key2","value2"],["key1","value1"]]);

    return expect(value).toBe("value1");
  });

  test("CacheLru change priority value2 with 3 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);
    
    cache.set("key1","value1");
    cache.set("key2","value2");
    cache.set("key3","value3");

    const value = cache.get("key2");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(3);
    expect(cache.toArray()).toStrictEqual([["key1","value1"],["key3","value3"],["key2","value2"]]);

    return expect(value).toBe("value2");

  });

  test("CacheLru change priority value3 with 4 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);
    
    cache.set("key1","value1");
    cache.set("key2","value2");
    cache.set("key3","value3");
    cache.set("key4","value4");

    const value = cache.get("key3");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(3);
    expect(cache.toArray()).toStrictEqual([["key2","value2"],["key4","value4"],["key3","value3"]]);

    return expect(value).toBe("value3");

  });
  
  test("CacheLru update key1", () => {
    const cache = new SimpleLruCache<string,string>(3);

    cache.set("key1","value1");
    cache.set("key1","value2");

    expect(cache.size).toBe(1);
    expect(cache.toArray()).toStrictEqual([["key1","value2"]]);

    return expect(cache.get("key1")).toBe("value2");
  });

});
