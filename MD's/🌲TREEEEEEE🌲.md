# Tree 🌳 command to ouput my codebase Tree 🌲
## I planted one tree, but now there’s a tree in the tree, and a subtree in the tree’s tree." 🌳➕🌳
-------------------------------------------------------------------------------------------------
 ```bash
tree -I "$(grep -Ev '^#|^$' .gitignore | tr '\n' '|' | sed 's/|$//')"
```
-------------------------------------------------------------------------------------------------
