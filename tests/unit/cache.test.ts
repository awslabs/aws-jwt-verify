import {
  SimpleLinkedList,
  SimpleLruCache,
} from "../../src/cache";

describe("unit tests cache", () => {

  test("SimpleLinkedList with 0 element", () => {
    const list = new SimpleLinkedList<string>();
    expect(list.size).toBe(0);
    expect(list.first).toBeUndefined();
    expect(list.last).toBeUndefined();
  });

  test("SimpleLinkedList addFirst 1 element", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");

    expect(list.size).toBe(1);

    expect(node1.t).toBe("value1");
    expect(node1.prev).toBeUndefined();
    expect(node1.next).toBeUndefined();

    expect(list.first).toBe(node1);
    expect(list.last).toBe(node1);

  });

  test("SimpleLinkedList addFirst 2 elements", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");
    const node2 = list.addFirst("value2");

    expect(list.size).toBe(2);
    
    expect(node1.t).toBe("value1");
    expect(node1.prev).toBeUndefined();
    expect(node1.next).toBe(node2);

    expect(node2.t).toBe("value2");
    expect(node2.prev).toBe(node1);
    expect(node2.next).toBeUndefined();

    expect(list.first).toBe(node2);
    expect(list.last).toBe(node1);
  });

  test("SimpleLinkedList addFirst 3 elements", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");
    const node2 = list.addFirst("value2");
    const node3 = list.addFirst("value3");

    expect(list.size).toBe(3);

    expect(node1.t).toBe("value1");
    expect(node1.prev).toBeUndefined();
    expect(node1.next).toBe(node2);

    expect(node2.t).toBe("value2");
    expect(node2.prev).toBe(node1);
    expect(node2.next).toBe(node3);

    expect(node3.t).toBe("value3");
    expect(node3.prev).toBe(node2);
    expect(node3.next).toBeUndefined();

    expect(list.first).toBe(node3);
    expect(list.last).toBe(node1);

  });

  test("SimpleLinkedList removeLast with 0 elements", () => {
    const list = new SimpleLinkedList<string>();

    const lastRemoved  = list.removeLast();

    expect(list.size).toBe(0);
    expect(list.first).toBeUndefined();
    expect(list.last).toBeUndefined();

    return expect(lastRemoved).toBeUndefined();

  });

  test("SimpleLinkedList removeLast with 1 elements", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");

    const lastRemoved  = list.removeLast();

    expect(list.size).toBe(0);
    
    expect(node1.t).toBe("value1");
    expect(node1.prev).toBeUndefined();
    expect(node1.next).toBeUndefined();

    expect(list.first).toBeUndefined();
    expect(list.last).toBeUndefined();

    return expect(lastRemoved).toBe("value1");

  });

  test("SimpleLinkedList removeLast with 2 elements", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");
    const node2 = list.addFirst("value2");

    const lastRemoved  = list.removeLast();

    expect(list.size).toBe(1);

    expect(node1.t).toBe("value1");
    expect(node1.prev).toBeUndefined();
    expect(node1.next).toBeUndefined();

    expect(node2.t).toBe("value2");
    expect(node2.prev).toBeUndefined();
    expect(node2.next).toBeUndefined();

    expect(list.first).toBe(node2);
    expect(list.last).toBe(node2);

    return expect(lastRemoved).toBe("value1");

  });

  test("SimpleLinkedList removeLast with 3 elements", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");
    const node2 = list.addFirst("value2");
    const node3 = list.addFirst("value3");

    const lastRemoved  = list.removeLast();

    expect(list.size).toBe(2);

    expect(node1.t).toBe("value1");
    expect(node1.prev).toBeUndefined();
    expect(node1.next).toBeUndefined();

    expect(node2.t).toBe("value2");
    expect(node2.prev).toBeUndefined();
    expect(node2.next).toBe(node3);

    expect(node3.t).toBe("value3");
    expect(node3.prev).toBe(node2);
    expect(node3.next).toBeUndefined();

    expect(list.first).toBe(node3);
    expect(list.last).toBe(node2);

    return expect(lastRemoved).toBe("value1");

  });

  test("SimpleLinkedList moveFirst with 1 element", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");
    list.moveFirst(node1);

    expect(list.size).toBe(1);
    
    expect(node1.t).toBe("value1");
    expect(node1.prev).toBeUndefined();
    expect(node1.next).toBeUndefined();

    expect(list.first).toBe(node1);
    expect(list.last).toBe(node1);

  });

  test("SimpleLinkedList moveFirst with 2 elements", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");
    const node2 = list.addFirst("value2");
    list.moveFirst(node1);
    
    expect(list.size).toBe(2);

    expect(node1.t).toBe("value1");
    expect(node1.prev).toBe(node2);
    expect(node1.next).toBeUndefined();

    expect(node2.t).toBe("value2");
    expect(node2.prev).toBeUndefined();
    expect(node2.next).toBe(node1);

    expect(list.first).toBe(node1);
    expect(list.last).toBe(node2);
  });

  test("SimpleLinkedList moveFirst the last element with 3 elements", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");
    const node2 = list.addFirst("value2");
    const node3 = list.addFirst("value3");
    list.moveFirst(node1);

    expect(list.size).toBe(3);

    expect(node1.t).toBe("value1");
    expect(node1.prev).toBe(node3);
    expect(node1.next).toBeUndefined();

    expect(node2.t).toBe("value2");
    expect(node2.prev).toBeUndefined();
    expect(node2.next).toBe(node3);

    expect(node3.t).toBe("value3");
    expect(node3.prev).toBe(node2);
    expect(node3.next).toBe(node1);

    expect(list.first).toBe(node1);
    expect(list.last).toBe(node2);

  });

  test("SimpleLinkedList moveFirst the second element with 3 elements", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");
    const node2 = list.addFirst("value2");
    const node3 = list.addFirst("value3");
    list.moveFirst(node2);

    expect(list.size).toBe(3);

    expect(node1.t).toBe("value1");
    expect(node1.prev).toBeUndefined();
    expect(node1.next).toBe(node3);

    expect(node2.t).toBe("value2");
    expect(node2.prev).toBe(node3);
    expect(node2.next).toBeUndefined();

    expect(node3.t).toBe("value3");
    expect(node3.prev).toBe(node1);
    expect(node3.next).toBe(node2);

    expect(list.first).toBe(node2);
    expect(list.last).toBe(node1);

  });

  test("SimpleLinkedList moveFirst the first element with 3 elements", () => {
    const list = new SimpleLinkedList<string>();
    const node1 = list.addFirst("value1");
    const node2 = list.addFirst("value2");
    const node3 = list.addFirst("value3");
    list.moveFirst(node3);

    expect(list.size).toBe(3);

    expect(node1.t).toBe("value1");
    expect(node1.prev).toBeUndefined();
    expect(node1.next).toBe(node2);

    expect(node2.t).toBe("value2");
    expect(node2.prev).toBe(node1);
    expect(node2.next).toBe(node3);

    expect(node3.t).toBe("value3");
    expect(node3.prev).toBe(node2);
    expect(node3.next).toBeUndefined();

    expect(list.first).toBe(node3);
    expect(list.last).toBe(node1);

  });


  test("CacheLru get undefined", () => {
    const cache = new SimpleLruCache<string,string>(2);
    return expect(cache.get("key1")).toBeUndefined();
  });

  test("CacheLru get value1 with 1 element", () => {
    const cache = new SimpleLruCache<string,string>(3);

    const addFirst = jest.spyOn(cache.list,'addFirst');

    cache.set("key1","value1");

    expect(cache.size).toBe(1);

    expect(addFirst).toHaveBeenCalledWith(["key1","value1"]);

    return expect(cache.get("key1")).toBe("value1");
  });

  test("CacheLru get value1 with 2 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);

    const set = jest.spyOn(cache.index,'set');
    const addFirst = jest.spyOn(cache.list,'addFirst');

    cache.set("key1","value1");
    cache.set("key2","value2");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(2);

    const node1 = {
      t:["key1", "value1"],
    } as any;
    const node2 = {
      t:["key2", "value2"],
    } as any;
    node1.next = node2;
    node2.prev = node1;

    expect(set).toHaveBeenNthCalledWith(1,"key1", node1);
    expect(set).toHaveBeenNthCalledWith(2,"key2", node2);

    expect(addFirst).toHaveBeenNthCalledWith(1, ["key1","value1"]);
    expect(addFirst).toHaveBeenNthCalledWith(2, ["key2","value2"]);

    return expect(cache.get("key1")).toBe("value1");
  });

  
  test("CacheLru get value1 with 3 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);

    const set = jest.spyOn(cache.index,'set');
    const addFirst = jest.spyOn(cache.list,'addFirst');

    cache.set("key1","value1");
    cache.set("key2","value2");
    cache.set("key3","value3");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(3);

    const node1 = {
      t:["key1", "value1"],
    } as any;
    const node2 = {
      t:["key2", "value2"],
    } as any;
    const node3 = {
      t:["key3", "value3"],
    } as any;
    node1.next = node2;
    node2.prev = node1;
    node2.next = node3;
    node3.prev = node2;

    expect(set).toHaveBeenNthCalledWith(1,"key1", node1);
    expect(set).toHaveBeenNthCalledWith(2,"key2", node2);
    expect(set).toHaveBeenNthCalledWith(3,"key3", node3);

    expect(addFirst).toHaveBeenNthCalledWith(1, ["key1","value1"]);
    expect(addFirst).toHaveBeenNthCalledWith(2, ["key2","value2"]);
    expect(addFirst).toHaveBeenNthCalledWith(3, ["key3","value3"]);

    return expect(cache.get("key1")).toBe("value1");
  });

  
  test("CacheLru get value 1 with 4 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);

    const set = jest.spyOn(cache.index,'set');
    const addFirst = jest.spyOn(cache.list,'addFirst');
    const removeLast = jest.spyOn(cache.list,'removeLast');

    cache.set("key1","value1");
    cache.set("key2","value2");
    cache.set("key3","value3");
    cache.set("key4","value4");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(3);

    const node1 = {
      t:["key1", "value1"],
    } as any;
    const node2 = {
      t:["key2", "value2"],
    } as any;
    const node3 = {
      t:["key3", "value3"],
    } as any;
    const node4 = {
      t:["key4", "value4"],
    } as any;
    node2.next = node3;
    node3.prev = node2;
    node3.next = node4;
    node4.prev = node3;

    expect(set).toHaveBeenNthCalledWith(1,"key1", node1);
    expect(set).toHaveBeenNthCalledWith(2,"key2", node2);
    expect(set).toHaveBeenNthCalledWith(3,"key3", node3);
    expect(set).toHaveBeenNthCalledWith(4,"key4", node4);

    expect(addFirst).toHaveBeenNthCalledWith(1, ["key1","value1"]);
    expect(addFirst).toHaveBeenNthCalledWith(2, ["key2","value2"]);
    expect(addFirst).toHaveBeenNthCalledWith(3, ["key3","value3"]);
    expect(addFirst).toHaveBeenNthCalledWith(4, ["key4","value4"]);

    expect(removeLast).toHaveReturnedWith(["key1","value1"]);

    return expect(cache.get("key1")).toBeUndefined();
  });
  

  test("CacheLru change priority value1 with 2 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);
    
    const addFirst = jest.spyOn(cache.list,'addFirst');
    const moveFirst = jest.spyOn(cache.list,'moveFirst');
    
    cache.set("key1","value1");
    cache.set("key2","value2");
  
    const value = cache.get("key1");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(2);

    const node1 = {
      t:["key1", "value1"],
    } as any;
    const node2 = {
      t:["key2", "value2"],
    } as any;
    node2.next = node1;
    node1.prev = node2;

    expect(addFirst).toHaveBeenNthCalledWith(1, ["key1","value1"]);
    expect(addFirst).toHaveBeenNthCalledWith(2, ["key2","value2"]);

    expect(moveFirst).toHaveBeenCalledWith(node1);

    return expect(value).toBe("value1");
  });

  test("CacheLru change priority value2 with 3 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);
    
    const addFirst = jest.spyOn(cache.list,'addFirst');
    const moveFirst = jest.spyOn(cache.list,'moveFirst');
    
    cache.set("key1","value1");
    cache.set("key2","value2");
    cache.set("key3","value3");

    const value = cache.get("key2");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(3);

    const node1 = {
      t:["key1", "value1"],
    } as any;
    const node2 = {
      t:["key2", "value2"],
    } as any;
    const node3 = {
      t:["key3", "value3"],
    } as any;
    node2.prev = node3;
    node3.next = node2;
    node3.prev = node1
    node1.next = node3;

    expect(addFirst).toHaveBeenNthCalledWith(1, ["key1","value1"]);
    expect(addFirst).toHaveBeenNthCalledWith(2, ["key2","value2"]);
    expect(addFirst).toHaveBeenNthCalledWith(3, ["key3","value3"]);

    expect(moveFirst).toHaveBeenCalledWith(node2);

    return expect(value).toBe("value2");

  });

  test("CacheLru change priority value3 with 4 elements", () => {
    const cache = new SimpleLruCache<string,string>(3);
    
    const addFirst = jest.spyOn(cache.list,'addFirst');
    const moveFirst = jest.spyOn(cache.list,'moveFirst');
    const removeLast = jest.spyOn(cache.list,'removeLast');
    
    cache.set("key1","value1");
    cache.set("key2","value2");
    cache.set("key3","value3");
    cache.set("key4","value4");

    const value = cache.get("key3");

    expect(cache.capacity).toBe(3);
    expect(cache.size).toBe(3);

    const node2 = {
      t:["key2", "value2"],
    } as any;
    const node3 = {
      t:["key3", "value3"],
    } as any;
    const node4 = {
      t:["key4", "value4"],
    } as any;
    node3.prev = node4;
    node4.next = node3;
    node4.prev = node2;
    node2.next = node4;

    expect(addFirst).toHaveBeenNthCalledWith(1, ["key1","value1"]);
    expect(addFirst).toHaveBeenNthCalledWith(2, ["key2","value2"]);
    expect(addFirst).toHaveBeenNthCalledWith(3, ["key3","value3"]);
    expect(addFirst).toHaveBeenNthCalledWith(4, ["key4","value4"]);

    expect(moveFirst).toHaveBeenCalledWith(node3);

    expect(removeLast).toHaveReturnedWith(["key1","value1"]);

    return expect(value).toBe("value3");

  });
  
  test("CacheLru update key1", () => {
    const cache = new SimpleLruCache<string,string>(3);

    const addFirst = jest.spyOn(cache.list,'addFirst');
    const moveFirst = jest.spyOn(cache.list,'moveFirst');

    cache.set("key1","value1");
    cache.set("key1","value2");

    expect(cache.size).toBe(1);

    expect(addFirst).toHaveBeenCalledTimes(1);
    expect(moveFirst).toHaveBeenCalledTimes(1);

    return expect(cache.get("key1")).toBe("value2");
  });

});
