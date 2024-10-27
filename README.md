zip2rpk
=======

This is a python script to

 * Create an RPK file from MAME's TI-99/4A software list and a
   matching zip file
 * Validate an existing RPK against the same software list (no zip
   file needed)

This is useful because there seems to be a lot of broken RPKs
floating around.


Usage
=====

Convert a MAME zip to an RPK:

```
zip2rpk.py ti99_cart.xml minimem.zip minimem.rpk
```

Test if an RPK is valid:

```
zip2rpk.py ti99_cart.xml -c ms_multiplan.rpk 
```

The `ti99_cart.xml` file can be found in MAME distributions,
or [on GitHub](https://raw.githubusercontent.com/mamedev/mame/refs/heads/master/hash/ti99_cart.xml).
