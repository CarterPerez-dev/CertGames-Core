# Important Github Replace Regexp
---------------------------------------
### Find all words/characters in ()
 ```python
\(([^()]+)\)
 ```
---------------------------------------
### Replace with a negtave space (-1 space)
 ```bash
-1 $1
 ```
### Replace MongoSh Object ID's
```python
^\s*_id:\s*ObjectId\("[^"]+"\),?\s*(?:\r?\n)?
```

### Move XYZ spaces back

#### Find: 
```python 
^( {4})
```

### Removes /* xyz */ comments and its respective line (white space)
```python
(?m)^\s*\/\*[\s\S]*?\*\/\s*(\r?\n\s*)+
```
