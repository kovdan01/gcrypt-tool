#include <gcrypt.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

static constexpr std::size_t AES256_KEY_SIZE = 32;
static constexpr std::size_t AES256_BLOCK_SIZE = 16;
static constexpr std::size_t HMAC_KEY_SIZE = 64;
static constexpr std::size_t KDF_ITERATIONS = 50000;
static constexpr std::size_t KDF_SALT_SIZE = 128;
static constexpr std::size_t KDF_KEY_SIZE = AES256_KEY_SIZE + HMAC_KEY_SIZE;

using byte_t = std::uint8_t;

std::vector<byte_t> read_file_into_buf(std::string_view filepath)
{
    std::ifstream f(filepath.data(), std::ios_base::binary);
    std::vector<byte_t> contents{std::istreambuf_iterator<char>{f}, std::istreambuf_iterator<char>{}};
    return contents;
}

void write_buf_to_file(std::string_view filepath, std::span<const byte_t> data)
{
    std::ofstream f(filepath.data(), std::ios_base::binary);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

class GcryCipherWrapper
{
public:
    GcryCipherWrapper(int algo, int mode, unsigned int flags)
    {
        gcry_error_t err = gcry_cipher_open(&m_raw, algo, mode, flags);
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "cipher_open: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
    }

    ~GcryCipherWrapper()
    {
        if (m_raw != nullptr)
        {
            gcry_cipher_close(m_raw);
        }
    }

    void setkey(std::span<const byte_t> key)
    {
        gcry_error_t err = gcry_cipher_setkey(m_raw, key.data(), key.size());
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "cipher_setkey: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
    }

    void setiv(std::span<const byte_t> init_vector)
    {
        gcry_error_t err = gcry_cipher_setiv(m_raw, init_vector.data(), init_vector.size());
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "cipher_setiv: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
    }

    void encrypt(std::span<byte_t> out, std::span<const byte_t> in)
    {
        gcry_error_t err = gcry_cipher_encrypt(m_raw, out.data(), out.size(), in.data(), in.size());
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "cipher_encrypt: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
    }

    void decrypt(std::span<byte_t> out, std::span<const byte_t> in)
    {
        gcry_error_t err = gcry_cipher_decrypt(m_raw, out.data(), out.size(), in.data(), in.size());
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "cipher_decrypt: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
    }

    [[nodiscard]] const gcry_cipher_hd_t raw() const
    {
        return m_raw;
    }

private:
    gcry_cipher_hd_t m_raw = nullptr;
};

class GcryMacWrapper
{
public:
    GcryMacWrapper(int algo, unsigned int flags, gcry_ctx_t ctx)
    {
        gcry_error_t err = gcry_mac_open(&m_raw, algo, flags, ctx);
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "mac_open: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
    }

    ~GcryMacWrapper()
    {
        if (m_raw != nullptr)
        {
            gcry_mac_close(m_raw);
        }
    }

    void setkey(std::span<const byte_t> key)
    {
        gcry_error_t err = gcry_mac_setkey(m_raw, key.data(), key.size());
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "mac_setkey: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
    }

    void write(std::span<const byte_t> data)
    {
        gcry_error_t err = gcry_mac_write(m_raw, data.data(), data.size());
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "mac_write: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
    }

    std::size_t read(std::span<byte_t> buffer)
    {
        std::size_t len;
        gcry_error_t err = gcry_mac_read(m_raw, buffer.data(), &len);
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "mac_read during encryption: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
        return len;
    }

    void verify(std::span<const byte_t> hmac)
    {
        gcry_error_t err = gcry_mac_verify(m_raw, hmac.data(), hmac.size());
        if (err != 0)
        {
            std::ostringstream ss;
            ss << "HMAC verification failed: " << gcry_strsource(err) << '/' << gcry_strerror(err);
            throw std::runtime_error(ss.str());
        }
    }

    [[nodiscard]] const gcry_mac_hd_t raw() const
    {
        return m_raw;
    }

private:
    gcry_mac_hd_t m_raw = nullptr;
};

GcryCipherWrapper init_cipher(std::span<byte_t> key, std::span<byte_t> init_vector)
{
    // 256-bit AES using cipher-block chaining; with ciphertext stealing, no manual padding is required
    GcryCipherWrapper cipher(GCRY_CIPHER_AES256,
                             GCRY_CIPHER_MODE_CBC,
                             GCRY_CIPHER_CBC_CTS);

    cipher.setkey(key);
    cipher.setiv(init_vector);

    return cipher;
}

void encrypt_file(std::string_view infile, std::string_view outfile, std::string_view password)
{
    std::array<byte_t, AES256_BLOCK_SIZE> init_vector;
    std::array<byte_t, KDF_SALT_SIZE> kdf_salt;
    std::array<byte_t, KDF_KEY_SIZE> kdf_key;
    std::array<byte_t, AES256_KEY_SIZE> aes_key;
    std::array<byte_t, HMAC_KEY_SIZE> hmac_key;
    gcry_error_t err;

    std::vector<byte_t> plaintext = read_file_into_buf(infile);

    // Find number of blocks required for data
    std::uint8_t padding = AES256_BLOCK_SIZE - (plaintext.size() % AES256_BLOCK_SIZE);
    plaintext.insert(plaintext.end(), padding, padding);

    // Generate 128 byte salt in preparation for key derivation
    gcry_create_nonce(kdf_salt.data(), kdf_salt.size());

    // Key derivation: PBKDF2 using SHA512 w/ 128 byte salt over 10 iterations into a 64 byte key
    err = gcry_kdf_derive(password.data(),
                          password.size(),
                          GCRY_KDF_PBKDF2,
                          GCRY_MD_SHA512,
                          kdf_salt.data(),
                          kdf_salt.size(),
                          KDF_ITERATIONS,
                          kdf_key.size(),
                          kdf_key.data());
    if (err != 0)
    {
        std::ostringstream ss;
        ss << "kdf_derive: " << gcry_strsource(err) << '/' << gcry_strerror(err);
        throw std::runtime_error(ss.str());
    }

    // Copy the first 32 bytes of kdf_key into aes_key
    std::memcpy(aes_key.data(), kdf_key.data(), aes_key.size());

    // Copy the last 32 bytes of kdf_key into hmac_key
    std::memcpy(hmac_key.data(), kdf_key.data() + aes_key.size(), hmac_key.size());

    // Generate the initialization vector
    gcry_create_nonce(init_vector.data(), init_vector.size());

    // Begin encryption
    GcryCipherWrapper cipher = init_cipher(aes_key, init_vector);

    // Encryption is performed in-place
    cipher.encrypt(plaintext, {});

    // Compute and allocate space required for packed data
    std::vector<byte_t> hmac(gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512));
    std::vector<byte_t> packed_data(kdf_salt.size() + init_vector.size() + plaintext.size() + hmac.size());

    // Pack data before writing: salt::IV::ciphertext::HMAC where "::" denotes concatenation
    std::memcpy(packed_data.data(), kdf_salt.data(), kdf_salt.size());
    std::memcpy(packed_data.data() + kdf_salt.size(), init_vector.data(), init_vector.size());
    std::memcpy(packed_data.data() + kdf_salt.size() + init_vector.size(), plaintext.data(), plaintext.size());

    // Begin HMAC computation on encrypted/packed data

    GcryMacWrapper mac(GCRY_MAC_HMAC_SHA512, 0, nullptr);
    mac.setkey(hmac_key);

    // Add packed_data to the MAC computation
    mac.write({packed_data.data(), packed_data.size() - hmac.size()});

    // Finalize MAC and save it in the hmac buffer
    std::size_t hmac_len = mac.read(hmac);

    // Append the computed HMAC to packed_data
    std::memcpy(packed_data.data() + kdf_salt.size() + init_vector.size() + plaintext.size(), hmac.data(), hmac_len);

    // Write packed data to file
    write_buf_to_file(outfile, {packed_data.data(), packed_data.size()});
}

void decrypt_file(std::string_view infile, std::string_view outfile, std::string_view password)
{
    std::array<byte_t, AES256_BLOCK_SIZE> init_vector;
    std::array<byte_t, KDF_SALT_SIZE> kdf_salt;
    std::array<byte_t, KDF_KEY_SIZE> kdf_key;
    std::array<byte_t, AES256_KEY_SIZE> aes_key;
    std::array<byte_t, HMAC_KEY_SIZE> hmac_key;

    gcry_error_t err;

    // Read in file contents
    std::vector<byte_t> packed_data = read_file_into_buf(infile);

    // Compute necessary lengths
    std::vector<byte_t> hmac(gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512));
    std::vector<byte_t> ciphertext(packed_data.size() - kdf_salt.size() - init_vector.size() - hmac.size());

    // Unpack data
    std::memcpy(kdf_salt.data(), packed_data.data(), kdf_salt.size());
    std::memcpy(init_vector.data(), packed_data.data() + kdf_salt.size(), init_vector.size());
    std::memcpy(ciphertext.data(), packed_data.data() + kdf_salt.size() + init_vector.size(), ciphertext.size());
    std::memcpy(hmac.data(), packed_data.data()  + kdf_salt.size() + init_vector.size() + ciphertext.size(), hmac.size());

    // Key derivation: PBKDF2 using SHA512 w/ 128 byte salt over 10 iterations into a 64 byte key
    err = gcry_kdf_derive(password.data(),
                          password.size(),
                          GCRY_KDF_PBKDF2,
                          GCRY_MD_SHA512,
                          kdf_salt.data(),
                          kdf_salt.size(),
                          KDF_ITERATIONS,
                          kdf_key.size(),
                          kdf_key.data());
    if (err != 0)
    {
        std::ostringstream ss;
        ss << "kdf_derive: " << gcry_strsource(err) << '/' << gcry_strerror(err);
        throw std::runtime_error(ss.str());
    }

    // Copy the first 32 bytes of kdf_key into aes_key
    std::memcpy(aes_key.data(), kdf_key.data(), aes_key.size());

    // Copy the last 32 bytes of kdf_key into hmac_key
    std::memcpy(hmac_key.data(), kdf_key.data() + aes_key.size(), hmac_key.size());

    // Begin HMAC verification
    GcryMacWrapper mac(GCRY_MAC_HMAC_SHA512, 0, nullptr);
    mac.setkey(hmac_key);
    mac.write({packed_data.data(), kdf_salt.size() + init_vector.size() + ciphertext.size()});

    // Verify HMAC
    mac.verify(hmac);

    // Begin decryption
    GcryCipherWrapper cipher = init_cipher(aes_key, init_vector);
    cipher.decrypt(ciphertext, {});

    // Write plaintext to the output file
    write_buf_to_file(outfile, {ciphertext.data(), ciphertext.size() - ciphertext.back()});
}

void display_usage()
{
    std::cerr << "Usage: ./gcrypt-tool [encrypt|decrypt] <input file path> <output file path> <password>" << std::endl;
}

int main(int argc, const char* argv[]) try
{
    if (argc < 5)
    {
        display_usage();
        throw std::runtime_error("not enough arguments");
    }

    std::string operation = argv[1];

    if (operation == "encrypt")
    {
        encrypt_file(argv[2], argv[3], argv[4]);
    }
    else if (operation == "decrypt")
    {
        decrypt_file(argv[2], argv[3], argv[4]);
    }
    else
    {
        display_usage();
        throw std::runtime_error("invalid action");
    }

    return EXIT_SUCCESS;
}
catch (const std::exception& e)
{
    std::cerr << "Error: " << e.what() << std::endl;
    return EXIT_FAILURE;
}
catch (...)
{
    std::cerr << "Unknown error" << std::endl;
    return EXIT_FAILURE;
}
