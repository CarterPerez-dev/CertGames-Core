# Important Github Replace Regexp
---------------------------------------
### Find all words/characters in ()
 ```bash
\(([^()]+)\)
 ```
---------------------------------------
### Replace with a negtave space (-1 space)
 ```bash
-1 $1
 ```
### Replace MongoSh Object ID's
```bash
^\s*_id:\s*ObjectId\("[^"]+"\),?\s*(?:\r?\n)?
```
