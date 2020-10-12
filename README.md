# What is CornerShot
In warfare, CornerShot is a weapon that allows a solder to look past a corner (and possibly take a shot), without risking exposure.
Similarly, the CornerShot package allows one to look at a remote host’s network access without the need to have any special privileges on that host.

Using CornerShot, a **source** host A, with network access to **destination** host B, can determine whether there is network access from B to **target** host C.  

+-----+        +-----+    ?    +-----+
|     |        |     |         |     |
|  A  +-------->  B  +------->(p) C  |
|     |        |     |         |     |
+-----+        +-----+         +-----+
 source      destination        target

Similarly to [nmap](https://nmap.org/), CornerShot determines between the following state of ports: *open*,*closed*, *filtered* and *unknown* (if it can't be determined). 

## How Does it Work?

## Getting Started

```bash
pip install cornershot
```

Using as standalone

```bash
python -m cornershot --c 123
```


Using in code

```python

```