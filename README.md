# malloc
To run `vim` that uses this malloc implementation:
```bash
make
LD_PRELOAD=$PWD/build/malloc.so vim
```
Tested on `vim`, `ls`, `xeyes`, `gnome-calculator`, `firefox`, `nautilus`.