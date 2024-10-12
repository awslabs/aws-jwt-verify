import assert from "assert";

export class SimpleLruCache<Key,Value> {

    private index:Map<Key,Value>;
    
    constructor(public readonly capacity:number){
        assert(capacity>0);
        this.index = new Map<Key,Value>();
    }
    
    public get size(){
        return this.index.size;
    }

    public get(key:Key):Value|undefined{
        const value = this.index.get(key);
        if(value){
            this.moveFirst(key,value);

            return value;
        }else{
            return undefined;
        }
    }

    public set(key:Key, value:Value):this{
        if(this.size>=this.capacity){
            this.removeLast();
        }

        this.moveFirst(key,value);
    
        return this;
    }

    private moveFirst(key:Key, value:Value){
        this.index.delete(key);
        this.index.set(key,value);
    }

    private removeLast(){
        const last = this.index.keys().next().value;
        if(last){
            this.index.delete(last)
        }
    }

    /**
     * 
     * @returns array ordered from the least recent to the most recent
     */
    public toArray():Array<[Key,Value]>{
        return Array.from(this.index);
    }
    
}

