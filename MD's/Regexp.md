# Important Github Replace ```Regexp```
---------------------------------------
### Find all words/characters in ()
```regex
\(([^()]+)\)
 ```
---------------------------------------
### Replace with a negtave space (-1 space)
```regex
-1 $1
 ```
### Replace MongoSh Object ID's
```regex
^\s*_id:\s*ObjectId\("[^"]+"\),?\s*(?:\r?\n)?
```

### Move XYZ spaces back

#### Find: 
```regex 
^( {replace with number})
```

### Removes /* xyz */ comments
```regex
\/\*[\s\S]*?\*\/(\s*\n)?
```

### removes empty lines
```regex
^[ \t]*\n
```
