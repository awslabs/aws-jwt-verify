import assert from "assert";

interface LinkedListNode<T> {
    t:T
    prev?:LinkedListNode<T>;
    next?:LinkedListNode<T>;
}

export class SimpleLinkedList<T> {

    first?:LinkedListNode<T>;
    last?:LinkedListNode<T>;
    size: number = 0;
    
    public moveFirst(node:LinkedListNode<T>){
        if(node !== this.first){
            this.moveNodeAfter(node,'first');
        }
    }

    private removeNode(node:LinkedListNode<T>){
        if(node === this.last){
            this.last = this.last.next;
        }

        if(node === this.first){
            this.first = this.first.prev;
        }
 
        if(node.prev){
            node.prev.next = node.next;
        }
        if(node.next){
            node.next.prev = node.prev; 
        }

        node.next = undefined;
        node.prev = undefined;
        
        this.size--;
    }

    private addAfter(t:T, after:LinkedListNode<T> | 'first'):LinkedListNode<T>{
        const newNode: LinkedListNode<T> = { t };
        this.moveNodeAfter(newNode,after);
        this.size++;
        return newNode;
    }

    private moveNodeAfter(node:LinkedListNode<T>,after:LinkedListNode<T> | 'first'):void{
        if(after==='first'){
            if(this.first){
                return this.moveNodeAfter(node,this.first);
            }else{
                //When empty LinkedList
                this.first = node;
                this.last = node;
            }
        }else{
            
            if(node === this.last){
                this.last = this.last.next;
            }
     
            if(after === this.first){
                this.first = node;
            }
            
            // nodePrev -- node -- nodeNext -- afterPrev --- after -- afterNext
            // =>
            // nodePrev -- nodeNext -- afterPrev --- after -- node -- afterNext
            
            const afterNext = after.next;
            const nodePrev = node.prev;
            const nodeNext = node.next;

            if(afterNext){
                afterNext.prev = node;
            }
            if(nodePrev){
                nodePrev.next = node.next;
            }
            if(nodeNext){
                nodeNext.prev = node.prev; 
            }
    
            after.next = node;
            node.next = afterNext;
            node.prev = after;
        }
    }

    public addFirst(t:T):LinkedListNode<T>{
        return this.addAfter(t,'first');
    }

    public removeLast():T|undefined{
        const last = this.last;
        if(last){
            this.removeNode(last);
            return last.t;
        }else{
            return undefined;
        }
    }

}

export class SimpleLruCache<Key,Value> {

    index:Map<Key,LinkedListNode<[Key,Value]>>;
    list:SimpleLinkedList<[Key,Value]>;

    constructor(public readonly capacity:number){
        assert(capacity>0);
        this.index = new Map<Key,LinkedListNode<[Key,Value]>>();
        this.list = new SimpleLinkedList<[Key,Value]>();
    }
    
    public get size(){
        return this.index.size;
    }

    public get(key:Key):Value|undefined{
        const node = this.index.get(key);
        if(node){
            this.list.moveFirst(node);
            return node.t[1];
        }else{
            return undefined;
        }
    }

    public set(key:Key, value:Value):this{
        const node = this.index.get(key);
        if(node){
            this.list.moveFirst(node);
            node.t[1] = value;
        }else{
            if(this.size>=this.capacity){
                const last = this.list.removeLast();
                assert(last);
                assert(this.index.delete(last[0]));
            }

            const newNode = this.list.addFirst([key,value]);
            this.index.set(key,newNode);
        }
        return this;
    }
    
}

