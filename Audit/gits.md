```regex
git rev-list --objects --all | \
  git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | \
  awk '$1 == "blob" { print $3, $4 }' | \
  sort -n | tail -n 10
```
---
```regex
git rev-list --all | while read commit; do
  git ls-tree -r $commit | grep 6cba5ac6bc103ab994762d2a6f2ed6879c419da5
done
```
