# shatool
A tool to perform common attacks (e.g. length extension) and operations relating to the SHA256 hashing algorithm

### Currently implemented: Hash calculation, length extension attacks
### WIP: Preimage brute-force attacks

## Hash calculation
Simply calculate the SHA256 digest of some input data and output it in the desired format:

![Screenshot 2023-05-17 231907](https://github.com/joedthomas2005/shatool/assets/38348883/74d0425f-bcb3-4cdb-bf98-5b455ab74358)

## Length Extension Attack
Perform a length extension attack given the hash of some unknown data, the length of the data, and some additional data to append. 

Given H(m) and some data d, calculate H(m|p|d) where p is the original SHA256 padding added to m.
![Screenshot 2023-05-17 233046](https://github.com/joedthomas2005/shatool/assets/38348883/dbaf398e-5363-4a58-9192-7dc6e68437b3)

### Demo
![Screenshot 2023-05-17 232912](https://github.com/joedthomas2005/shatool/assets/38348883/39855d07-8cc7-471a-b95d-ce6b028e1621)
The hash of the unknown data + the original sha256 padding + the new message was successfully calculated (as it matches the expected value at the bottom).
