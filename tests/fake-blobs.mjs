const stores={};
export function getStore({name}){const m=stores[name]||(stores[name]=new Map());return{
 async get(k,o){if(!m.has(k))return null;const v=m.get(k);return o?.type==="json"?JSON.parse(v):v},
 async set(k,v,o){if(o?.onlyIfNew&&m.has(k))return{modified:false};m.set(k,v);return{modified:true}},
 async setJSON(k,v,o){return this.set(k,JSON.stringify(v),o)},
 async list(){return{blobs:[...m.keys()].map(key=>({key}))}},
 async delete(k){m.delete(k)}}}
