import binascii
from cryptopals.utils import b64encode, force_bytes, static_xor, string_xor, score_string


def test_challenge1():
    vector = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    vector_bytes = bytes.fromhex(vector)
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert b64encode(vector_bytes, urlsafe=True) == expected


def test_challenge2():
    assert static_xor(bytes.fromhex("1c0111001f010100061a024b53535009181c"), bytes.fromhex("686974207468652062756c6c277320657965")) == bytes.fromhex("746865206b696420646f6e277420706c6179")


def test_challenge3():
    ciphered = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    for x in range(0, 255):
        result = string_xor(ciphered, x)
        score = score_string(result)
        if score > 0:
            continue
        
        # Commenting out to minimize spam in the tests
        # print(f"key: {x} result: {result}")

        # The above returned the following candidate lines, the key was recovered by determining which looked the most human. 
        # If there were more than 17 candidates I would have dug deeper into letter occurance analysis.
        # I could have also only checked for a-z as well to lower the number of candidates down to one
        # key: 71 result: b'\\pptvqx?R\\8l?svtz?~?opjq{?py?}~|pq'
        # key: 74 result: b'Q}}y{|u2_Q5a2~{yw2s2b}g|v2}t2psq}|'
        # key: 77 result: b'Vzz~|{r5XV2f5y|~p5t5ez`{q5zs5wtvz{'
        # key: 79 result: b'Txx|~yp7ZT0d7{~|r7v7gxbys7xq7uvtxy'
        # key: 80 result: b'Kggcafo(EK/{(dacm(i(xg}fl(gn(jikgf'
        # key: 81 result: b'Jffb`gn)DJ.z)e`bl)h)yf|gm)fo)khjfg'
        # key: 83 result: b'Hdd`bel+FH,x+gb`n+j+{d~eo+dm+ijhde'
        # key: 85 result: b'Nbbfdcj-@N*~-adfh-l-}bxci-bk-olnbc'
        # key: 86 result: b'Maaeg`i.CM)}.bgek.o.~a{`j.ah.loma`'
        # key: 88 result: b"Cooking MC's like a pound of bacon"
        # key: 89 result: b'Bnnjhof!LB&r!mhjd!`!qntoe!ng!c`bno'
        # key: 90 result: b'Ammikle"OA%q"nkig"c"rmwlf"md"`caml'
        # key: 91 result: b'@llhjmd#N@$p#ojhf#b#slvmg#le#ab`lm'
        # key: 92 result: b'Gkkomjc$IG#w$hmoa$e$tkqj`$kb$fegkj'
        # key: 93 result: b'Fjjnlkb%HF"v%iln`%d%ujpka%jc%gdfjk'
        # key: 94 result: b'Eiimoha&KE!u&jomc&g&vishb&i`&dgeih'
        # key: 95 result: b"Dhhlni`'JD t'knlb'f'whric'ha'efdhi"

    assert string_xor(ciphered, 88) == b"Cooking MC's like a pound of bacon"


def test_challenge5():
    import itertools

    ciphered = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    expected = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    key = itertools.cycle("ICE".encode("utf-8"))
    cipher1 = binascii.hexlify(static_xor(force_bytes(ciphered), key))

    assert cipher1 == expected