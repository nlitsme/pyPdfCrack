Pdf Encryption
==============

Using sample data from:
 * https://github.com/itext/itext7/tree/develop/kernel/src/test/resources/com/itextpdf/kernel/pdf/PdfEncryptionTest

Example code demonstating how pdf encryption with certificates works.

    python3 decryptpdf.py encryptedWithCertificateAes128.pdf test.p12 kspass

Will output the following decrypted data:

    priv b'a2d0faa52fee8453fe20150505050505'
    cert b'37373532393731340808080808080808'
    seed = b'cd532522a3f5943f66479ab8b0aa32d0609a0e18'
    mkey= b'b1ce00167f01fc074d49d6fe18069b942ed9c428'
    b'Author' b'Alexander Chingarev\r\r\r\r\r\r\r\r\r\r\r\r\r'
    b'CreationDate' b"D:20160809103103-03'00'\t\t\t\t\t\t\t\t\t"
    b'Creator' b'iText 6\t\t\t\t\t\t\t\t\t'
    b'ModDate' b"D:20160809103103-03'00'\t\t\t\t\t\t\t\t\t"
    b'Producer' b'iText\xae 7.0.1-SNAPSHOT \xa92000-2016 iText Group NV (AGPL-version)\x02\x02'

The repeating sequences at the end of each decrypted text are the PKCS7 padding.


Pdf Parser
==========

As a side project i created a simple PDF parser, which outputs the parsing stack plus a list of objects.

    python pdfparser.py encryptedWithCertificateAes128.pdf

producing the following output:

    [PdfComment: ascii:'PDF-1.7', PdfComment: hex:'e2e3cfd3', 
     PdfOperator: xref,
         PdfNumber: 0, PdfNumber: 9,
            PdfNumber: 0000000000, PdfNumber: 65535, PdfOperator: f,
            PdfNumber: 0000000294, PdfNumber: 00000, PdfOperator: n,
            PdfNumber: 0000000873, PdfNumber: 00000, PdfOperator: n,
            PdfNumber: 0000000354, PdfNumber: 00000, PdfOperator: n,
            PdfNumber: 0000000161, PdfNumber: 00000, PdfOperator: n,
            PdfNumber: 0000000015, PdfNumber: 00000, PdfOperator: n,
            PdfNumber: 0000000785, PdfNumber: 00000, PdfOperator: n,
            PdfNumber: 0000000924, PdfNumber: 00000, PdfOperator: n,
            PdfNumber: 0000003847, PdfNumber: 00000, PdfOperator: n,
     PdfOperator: trailer, PdfDictionary: [
         PdfName: Encrypt, PdfReference: 00008.0, 
         PdfName: ID, PdfArray: [PdfHexdata: eadf305edab34545d11859b727274d71, PdfHexdata: eadf305edab34545d11859b727274d71], 
         PdfName: Info, PdfReference: 00003.0, 
         PdfName: Root, PdfReference: 00001.0, 
         PdfName: Size, PdfNumber: 9],
     PdfComment: ascii:'iText-7.0.1-SNAPSHOT',
     PdfOperator: startxref, PdfNumber: 4893]

    00001: PdfObject: [PdfDictionary: [
         PdfName: Metadata, PdfReference: 00007.0, 
         PdfName: Pages, PdfReference: 00002.0, 
         PdfName: Type, 
         PdfName: Catalog]]
    00002: PdfObject: [PdfDictionary: [
         PdfName: Count, PdfNumber: 1, 
         PdfName: Kids, PdfArray: [PdfReference: 00004.0], 
         PdfName: Type, 
         PdfName: Pages]]
    00003: PdfObject: [PdfDictionary: [
         PdfName: Author, PdfString: hex:'5b97d367c7310b9d80761c86e66fa2c71dab01fb150e6fa4c55cb4bf80fac19cda79513966f9d6c1e938080fc8c87800', 
         PdfName: CreationDate, PdfString: hex:'5b97d367c7310b9d80761c86e66fa2c710cf138a9608a559cf8aa4e14fe9f97ee6e7ef89029fb1f7399dd9e64b0d7cab', 
         PdfName: Creator, PdfString: hex:'5b97d367c7310b9d80761c86e66fa2c7ee23708d7b3f6973b01ff75dae7e0fca', 
         PdfName: ModDate, PdfString: hex:'5b97d367c7310b9d80761c86e66fa2c710cf138a9608a559cf8aa4e14fe9f97ee6e7ef89029fb1f7399dd9e64b0d7cab', 
         PdfName: Producer, PdfString: hex:'5b97d367c7310b9d80761c86e66fa2c7ba3a4b524f422411b737667f5c50c98f8e864b96999ed6247270483364dd492a28c0a6f50da37bfe8e0ad618f419d4e77f31179bf7502fd8606af1b81e271ae3']]
    00004: PdfObject: [PdfDictionary: [
         PdfName: Contents, PdfReference: 00005.0, 
         PdfName: MediaBox, PdfArray: [PdfNumber: 0, PdfNumber: 0, PdfNumber: 595, PdfNumber: 842], 
         PdfName: Parent, PdfReference: 00002.0, 
         PdfName: Resources, PdfDictionary: [
             PdfName: Font, PdfDictionary: [
             PdfName: F1, PdfReference: 00006.0]], 
         PdfName: TrimBox, PdfArray: [PdfNumber: 0, PdfNumber: 0, PdfNumber: 595, PdfNumber: 842], 
         PdfName: Type, 
         PdfName: Page]]
    00005: PdfObject: [PdfStream: PdfDictionary: [
         PdfName: Filter, 
         PdfName: FlateDecode, 
         PdfName: Length, PdfNumber: 80]]
    00006: PdfObject: [PdfDictionary: [
         PdfName: BaseFont, 
         PdfName: Helvetica, 
         PdfName: Encoding, 
         PdfName: WinAnsiEncoding, 
         PdfName: Subtype, 
         PdfName: Type1, 
         PdfName: Type, 
         PdfName: Font]]
    00007: PdfObject: [PdfStream: PdfDictionary: [
         PdfName: Length, PdfNumber: 2848, 
         PdfName: Subtype, 
         PdfName: XML, 
         PdfName: Type, 
         PdfName: Metadata]]
    00008: PdfObject: [PdfDictionary: [
         PdfName: CF, PdfDictionary: [
             PdfName: DefaultCryptFilter, PdfDictionary: [
             PdfName: CFM, 
             PdfName: AESV2, 
             PdfName: Recipients, PdfArray: [PdfString: hex:'308201f706092a'...]]], 
         PdfName: Filter, 
         PdfName: Adobe.PubSec, 
         PdfName: Length, PdfNumber: 128, 
         PdfName: R, PdfNumber: 4, 
         PdfName: StmF, 
         PdfName: DefaultCryptFilter, 
         PdfName: StrF, 
         PdfName: DefaultCryptFilter, 
         PdfName: SubFilter, 
         PdfName: adbe.pkcs7.s5, 
         PdfName: V, PdfNumber: 4]]


Cracking a PKCS12 certificate
=============================


hexdump of the first couple of encrypted and decrypted blocks of the 40-bit RC2 encrypted certificate in test.p12:

    2408c5d658c61cad 43036642daa47c52 9023df09863bd662 28c700fee6c81f86 ac5d3c4debda9148 0ac6535dd9574d06  << cipher text
    3082____3082____ 060b2a864886f70d 010c0a0103a082__ __3082____060a2a 864886f70d010916 01a082____0482__  << plain text

The length dependent parts have been replaced with '\_\_\_\_'.
As you can see the 2nd block contains part of the 'pkcs12' OID representation,
and will be the same for all PKCS12 encoded data.

So we can use this as the known plain + cipher pair target for the brute force encryption.
Since the cipher is used in CBC mode, we have to XOR the plaintext with the 1st cipher block

    2408c5d658c61cad XOR 060b2a864886f70d  = 2203ef501040eba0

And then do a full 40-bit search for the key:

    openssl_rc2_crack -e 43036642daa47c52 -p 2203ef501040eba0 -v

Running on a single core, this will take about 5 days.
Using the `-f` and `-t` parameters you can run several instances searching different parts
of the keyspace.

    ./openssl_rc2_crack -e 43036642daa47c52 -p 2203ef501040eba0 -f 0x6896000000 -t 0x6896300000 -v
    FOUND key: 689629ff1a

Note that this is the key in reverse byte order.

Now we can search for the passphrase using the following commandline.

    cat wordlist.txt | ./openssl_pass_crack -s 68e8f778efe0db98453532b7ede8e0c09830ec81  -k 1aff299668 -i 1 -n 1024
    FOUND key: kspass

Instead of `cat wordlist.txt`  you can use JohnTheRipper for password generation:

    john --wordlist=dict.txt --rules --stdout" | ./openssl_pass_crack ....



Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
