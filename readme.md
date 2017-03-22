SHA-1 / SHA-2 PL/SQL library
============================

Descritpion
-----------
This package allows to calculate SHA-1 and SHA-2 hashes. It's written in pure 
PL/SQL and does not require access to DBMS_CRYPTO and external Java functions.

Author
------
This library is written by Vadim Dvorovenko <Vadimon@mail.ru>.

License
-------
The MIT License (MIT)

Copyright (c) 2014-2016 Vadim Dvorovenko

Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.

Limitations
-----------
For RAW versions of functions, hash cannot be calculated for data larger than 16384 bytes. 
For larger data you can use BLOB versions.

Currently all calculations are performed using NUMBER datatype, code is very 
inefficent.

Examples
--------

```
BEGIN
  DBMS_OUTPUT.PUT_LINE(RAWTOHEX(HASH_UTIL_PKG.SHA1(UTL_RAW.CAST_TO_RAW(''))));
  DBMS_OUTPUT.PUT_LINE(RAWTOHEX(HASH_UTIL_PKG.SHA1(UTL_RAW.CAST_TO_RAW('The quick brown fox jumps over the lazy dog'))));
  DBMS_OUTPUT.PUT_LINE(RAWTOHEX(HASH_UTIL_PKG.SHA256(UTL_RAW.CAST_TO_RAW(''))));
  DBMS_OUTPUT.PUT_LINE(RAWTOHEX(HASH_UTIL_PKG.SHA256(UTL_RAW.CAST_TO_RAW('The quick brown fox jumps over the lazy dog'))));
END;
```
results in

```
DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592
```