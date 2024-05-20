import binascii

ciphertexts = [
    "160111433b00035f536110435a380402561240555c526e1c0e431300091e4f04451d1d490d1c49010d000a0a4510111100000d434202081f0755034f13031600030d0204040e",
    "050602061d07035f4e3553501400004c1e4f1f01451359540c5804110c1c47560a1415491b06454f0e45040816431b144f0f4900450d1501094c1b16550f0b4e151e03031b450b4e020c1a124f020a0a4d09071f16003a0e5011114501494e16551049021011114c291236520108541801174b03411e1d124554284e141a0a1804045241190d543c00075453020a044e134f540a174f1d080444084e01491a090b0a1b4103570740",
    "000000000000001a49320017071704185941034504524b1b1d40500a0352441f021b0708034e4d0008451c40450101064f071d1000100201015003061b0b444c00020b1a16470a4e051a4e114f1f410e08040554154f064f410c1c00180c0010000b0f5216060605165515520e09560e00064514411304094c1d0c411507001a1b45064f570b11480d001d4c134f060047541b185c",
    "0b07540c1d0d0b4800354f501d131309594150010011481a1b5f11090c0845124516121d0e0c411c030c45150a16541c0a0b0d43540c411b0956124f0609075513051816590026004c061c014502410d024506150545541c450110521a111758001d0607450d11091d00121d4f0541190b45491e02171a0d49020a534f",
    "031a5410000a075f5438001210110a011c5350080a0048540e431445081d521345111c041f0245174a0006040002001b01094914490f0d53014e570214021d00160d151c57420a0d03040b4550020e1e1f001d071a56110359420041000c0b06000507164506151f104514521b02000b0145411e05521c1852100a52411a0054180a1e49140c54071d5511560201491b0944111a011b14090c0e41"
    "0b4916060808001a542e0002101309050345500b00050d04005e030c071b4c1f111b161a4f01500a08490b0b451604520d0b1d1445060f531c48124f1305014c051f4c001100262d38490f0b4450061800004e001b451b1d594e45411d014e004801491b0b0602050d41041e0a4d53000d0c411c41111c184e130a0015014f03000c1148571d1c011c55034f12030d4e0b45150c5c",
    "011b0d131b060d4f5233451e161b001f59411c090a0548104f431f0b48115505111d17000e02000a1e430d0d0b04115e4f190017480c14074855040a071f4448001a050110001b014c1a07024e5014094d0a1c541052110e54074541100601014e101a5c",
    "0c06004316061b48002a4509065e45221654501c0a075f540c42190b165c",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
]

ciphertexts = [binascii.unhexlify(x) for x in ciphertexts]
target_ciphertext = ciphertexts[-1]


def strxor(a, b):
    return "".join([chr(x ^ y) for x, y in zip(a, b)])


# per the professor's hint, the key is NOT repeating, so then it 's safe to assume that the key is the same length as the longest ciphertext
key = [0] * max(len(ciphertext) for ciphertext in ciphertexts)
for ciphertext_a in ciphertexts:
    space_suspect_counts = [0] * len(ciphertext_a)
    for ciphertext_b in ciphertexts:
        if ciphertext_a == ciphertext_b:
            continue

        # the insight below is well explained in this post
        # https://crypto.stackexchange.com/questions/33200/decrypting-messages-crypted-with-one-time-pad-used-more-than-once
        a_xor_b = strxor(ciphertext_a, ciphertext_b)

        for char_idx, xor_resulting_char in enumerate(a_xor_b):
            # since the language given is english, then assume it's all alphanumerical or special characters (common ones), or space
            ascii_null = "\x00"
            special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/`~"
            if (
                    xor_resulting_char.isalnum()
                    or xor_resulting_char == ascii_null
                    or xor_resulting_char in special_chars
            ):
                space_suspect_counts[char_idx] += 1

    # if a character is a space in all but one ciphertext, then it's likely a space
    space_tolerance_threshold = 0.8
    for char_idx, suspect_count in enumerate(space_suspect_counts):
        if suspect_count >= (len(ciphertexts) - 1) * space_tolerance_threshold:
            whitespace = ord(" ")
            key[char_idx] = ciphertext_a[char_idx] ^ whitespace

target_plaintext = strxor(target_ciphertext, key)
print(f"Target plaintext decryption:\n{target_plaintext}")

# from here on it was a trial-and-error guess. once the first few worlds became clear I figured it's from the bitcoin whitepaper
target_key = "Bitcoin: A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution"
hex_key = binascii.hexlify(target_key.encode()).decode()

# below is the resulting test with the target_key (handwritten) above
# The Times 03/Jan/2009 Chancellor on brink of second bailout for banks.
# Governments are good at cutting off the heads of a centrally controlled networks like Napster, but pure P2P networks like Gnutella and Tor seem to be holding their own.
# Bitcoin is great as a form of digital money, but its scripting language is too weak for any kind of serious advanced applications to be built on top.
# In order to have a decentralized database, you need to have security. In order to have security, you need to have incentives.
# As society becomes more and more complex, cheating will in many ways become progressively easier and easier to do and harder to police or even understand. +/hifcs5B k~`}lw0$bok
# Cryptocurrencies allowed non-custodial exchange, without users having to sign up or create accounts.
# Not your keys, Not your coins.
# Bitcoin: A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution

for s in ciphertexts:
    print(strxor(s, binascii.unhexlify(hex_key)))
