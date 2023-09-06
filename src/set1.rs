#[cfg(test)]
mod test {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyInit};
    use base64::{engine::general_purpose, Engine as _};
    use itertools::Itertools;

    #[test]
    fn challenge1() {
        const HEX_STRING: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        const EXPECTED_BASE64_STRING: &str =
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let raw_bytes = hex::decode(HEX_STRING).expect("String is valid hex");
        let base64_string = general_purpose::STANDARD.encode(raw_bytes.as_slice());

        assert_eq!(EXPECTED_BASE64_STRING, base64_string);
    }

    #[test]
    fn challenge2() {
        const EXPECTED_RESULT: &str = "746865206b696420646f6e277420706c6179";

        let hex_bytes =
            hex::decode("1c0111001f010100061a024b53535009181c").expect("String is valid hex");
        let xor_bytes =
            hex::decode("686974207468652062756c6c277320657965").expect("String is valid hex");

        let result = xor_in_place(hex_bytes, xor_bytes);
        assert_eq!(hex::encode(result), EXPECTED_RESULT)
    }

    fn xor_in_place(mut v1: Vec<u8>, v2: Vec<u8>) -> Vec<u8> {
        v1.iter_mut().zip(v2.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
        v1
    }

    #[test]
    fn challenge3() {
        let bytes =
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .expect("Should be valid hex");

        let winner = find_winner(&bytes);
        println!("Winner is: {:?}", winner);
    }

    fn find_winner(bytes: &Vec<u8>) -> Data {
        let mut winner = Data::default();
        for i in 32..u8::MAX / 2 {
            let result: Vec<u8> = bytes.iter().map(|b| *b ^ i).collect();
            let str = String::from_utf8_lossy(result.as_slice());
            let score = score_message(str.as_ref());
            let data = Data::new(i as char, String::from(str.trim()), score);
            if score > winner.score {
                winner = data
            }
        }
        winner
    }

    fn score_message(msg: &str) -> u32 {
        let mut score = 0;
        msg.chars().for_each(|c| {
            if c.is_alphanumeric() || c.is_ascii_whitespace() {
                score += 1;
            }
        });
        score
    }

    #[allow(dead_code)]
    #[derive(Default, Debug)]
    struct Data {
        char: char,
        msg: String,
        score: u32,
    }

    impl Data {
        fn new(char: char, msg: String, score: u32) -> Self {
            Self { char, msg, score }
        }
    }

    #[test]
    fn challenge4() {
        let str = include_str!("SingleCharacterXor.txt");
        let lines: Vec<_> = str.split("\n").collect();
        let mut winner = Data::default();
        lines.iter().for_each(|line| {
            let bytes = hex::decode(line).expect("should be valid hex");
            let current = find_winner(&bytes);
            if current.score > winner.score {
                winner = current
            }
        });
        println!("{:?}", winner);
    }

    #[test]
    fn challenge5() {
        const KEY: &[u8; 3] = b"ICE";
        const DATA: &[u8; 74] =
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

        let mut output = DATA.clone();
        repeated_key_xor(KEY, &mut output);

        assert_eq!(
            output.as_slice(),
            hex::decode(
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
            )
            .expect("should be valid hex")
            .as_slice()
        )
    }

    fn repeated_key_xor(key: &[u8], data: &mut [u8]) {
        let mut index = 0;
        data.iter_mut().for_each(|b| {
            *b ^= key[index % key.len()];
            index += 1;
        });
    }

    #[test]
    fn challenge6() {
        let data = include_str!("Challenge6.txt");
        let decoded = base64_decode(data);

        let key_size = find_key_size(decoded.clone());

        let chunks: Vec<_> = decoded
            .chunks_exact(key_size)
            .map(|v| Vec::from(v))
            .collect();
        let transposed = transpose(chunks);

        let mut key = String::new();
        transposed
            .iter()
            .for_each(|v| key.push(find_winner(v).char));
        println!("Key is: {}", key);

        let mut output = decoded.clone();

        repeated_key_xor(key.as_bytes(), &mut output);

        println!("{:?}", String::from_utf8_lossy(&output));
    }

    fn base64_decode(str: &str) -> Vec<u8> {
        general_purpose::STANDARD
            .decode(str.split('\n').collect::<String>())
            .expect("Should be valid base64")
    }

    fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>>
    where
        T: Copy,
    {
        (0..v[0].len())
            .map(|col| (0..v.len()).map(|row| v[row][col]).collect())
            .collect()
    }

    fn find_key_size(data: Vec<u8>) -> usize {
        let mut result = Vec::new();
        for i in 2..40 {
            let mut avg = 0;
            for j in 0..10 {
                let first = &data[j * i..(j + 1) * i];
                let second = &data[(j + 1) * i..(j + 2) * i];
                avg += hamming_distance(first, second);
            }
            avg /= 10;

            let normalized_distance = avg as f32 / i as f32;
            result.push((i, normalized_distance));
        }

        result.sort_by(|x1, x2| x1.1.partial_cmp(&x2.1).expect(""));
        result[0].0
    }

    fn hamming_distance_str(s1: &str, s2: &str) -> u32 {
        let mut str1 = String::from(s1);
        let b1 = unsafe { str1.as_bytes_mut() };
        let b2 = s2.as_bytes();

        hamming_distance(b1, b2)
    }

    fn hamming_distance(b1: &[u8], b2: &[u8]) -> u32 {
        let mut copied = vec![0; b1.len()];
        copied.clone_from_slice(b1);

        let mut result = 0;
        xor_slice_in_place(&mut copied, b2);
        copied.iter().for_each(|b| result += b.count_ones());
        result
    }

    fn xor_slice_in_place(v1: &mut [u8], v2: &[u8]) {
        v1.iter_mut().zip(v2.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    }

    #[test]
    fn test_hamming() {
        let str1 = "this is a test";
        let str2 = "wokka wokka!!!";
        let dist = hamming_distance_str(str1, str2);
        assert_eq!(37, dist);
    }

    type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

    #[test]
    fn challenge7() {
        const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
        let mut bytes = base64_decode(include_str!("Challenge7.txt"));
        let decrypter = Aes128EcbDec::new(KEY.into());
        let _ = decrypter.decrypt_padded_mut::<Pkcs7>(bytes.as_mut_slice());
        print!("{}", String::from_utf8_lossy(&bytes));
    }

    #[test]
    fn challenge8() {
        let lines = include_str!("Challenge8.txt").trim().split('\n');
        let mut distances = Vec::new();
        for (i, line) in lines.enumerate() {
            let bytes = hex::decode(line).expect("Provided data should be valid hex");
            let mut total_distance = 0;
            for (a, b) in bytes.chunks_exact(16).tuple_combinations() {
                total_distance += hamming_distance(a, b)
            }
            distances.push((i, total_distance));
        }
        distances.sort_by_key(|x| x.1);
        println!("{:?}", distances)
    }
}
