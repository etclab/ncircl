Ran Canetti and Susan Hohenberger. 2007.
Chosen-ciphertext secure proxy re-encryption.
In Proceedings of the 2007 ACM Conference on Computer and Communications Security, (CCS’07),

Properties:
- CCA-secure
- bidirectional (a re-encryption key from Alice to Bob also permits
  re-encryptino from Bob to Alice)
- multihop (a ciphertext may be re-encrypted multiple times---from Alice to Bob
  to Carol, etc.)


```
KeyGen() -> (pk, sk)


```

```
ReKeyGen(sk1, sk2) -> rk12


```


```
Enc(pk, m) -> ct


```

```
ReEnc


```

```
Dec


```
