// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#ifndef WAPP_H
#define WAPP_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>
#include <exception>


// TODO list:
/*
    [x] rename vs solution
    [x] lower c++ standard to c++20
    [x] remove print in win_cpp_crypt lib
    [x] make those vars global: const uint32_t key_size = 32; // 256 bit, const uint32_t nonce_size = 12; // 96 bit, const uint32_t tag_size =  auth_tag_lengths.dwMaxLength; // usually 16 byte, 128 bit,
    [x] ByteBuffer -> variable size
    [x] ByteArray -> fixed size
    [x] harmonize sha256 signature
    [x] use pair instead of tuple
    [x] uniform input/output parameters to functions
    [x] returning Salt from encrypt
    [x] return optional Error
    [x] fix all the warnings
    [x] fix const issue while calling win api
    [x] create distinct type for Ciphertext, Plaintext, Tag...
    [x] vs2022 format after saving
    [x] remove internal from base64 function?
    [x] internalBase64Decode need to return error
    [x] base64Encode(), base64Decode(), does not return error! fix that
    [x] create a file format for saving encrypted data
    [x] sha256::generate() does not return error! fix that
    [x] unify Result and Error struct for all functions?
    [x] harmonize return value of all functions
    [x] support utf-8 // we are dealing with bytes and not characters
    [] make ByteBuffer a struct?
        [] make toSv(), toBB(), toHexString() a memeber function?
    [] settings for AES256-GCM are hardcoded, make them configurable
    [] use c++ cast?
    [] get rid of namespace?
    [] fix TODO's in code
*/

namespace WAPP
{
using std::string_view;
using std::string;
using std::vector;
using std::format;

using byte = uint8_t;
using ByteBuffer = vector<byte>;

template <typename T>
struct Error
{
    Error(const string& desc, T code)
        : description(desc), code(code)
    {
    }

    string what() const
    {
        return std::format("{} ({:#x})", description, code);
    }

    Error() = default;
    Error(const Error& other) = default;
    Error(Error&& other) noexcept = default;
    Error& operator=(const Error& other) = default;
    Error& operator=(Error&& other) noexcept = default;

    string description;
    T code = 0;
};

class UnwrapException: public std::exception
{
public:
    explicit UnwrapException(char const* const message) noexcept
        : std::exception(message)
    {
    }
};

template<typename ResType, typename Err>
struct Result
{
    Result(const ResType& res,
           const Err& err) :
        res(res), err(err)
    {
    }

    Result() = default;
    Result(const Result& other) = default;
    Result(Result&& other) noexcept = default;
    Result& operator=(const Result& other) = default;
    Result& operator=(Result&& other) noexcept = default;

    static auto Success(const ResType& res)
    {
        return Result(res, {});
    }

    static auto Error(const Err& err)
    {
        return Result({}, err);
    }

    bool isValid() const
    {
        return err.description.size() == 0;
    }

    bool hasError() const
    {
        return !isValid();
    }

    const ResType& unwrap() const
    {
        if (isValid())
            return res;
        else
            throw UnwrapException("Unwrap invalid result");
    }

    const Err& error() const
    {
        return err;
    }

private:
    ResType res;
    Err err;
};

namespace Util
{

string toUTF8(const wchar_t* wide_str);

string_view toSv(const ByteBuffer& input);

ByteBuffer toBB(string_view input);

string toHexString(const ByteBuffer& data);

ByteBuffer randomBytes(uint32_t count);

using ReadResult = Result<ByteBuffer, Error<DWORD>>;
ReadResult readEntireFile(const char* filepath);
using WriteResult = Result<bool, Error<DWORD>>;
WriteResult writeContentToFile(const char* filepath, LPCVOID data, DWORD data_len);

using Base64Result = Result<ByteBuffer, Error<DWORD>>;

Base64Result base64Encode(const BYTE* input, DWORD input_size);
Base64Result base64Encode(const ByteBuffer& input);
Base64Result base64Encode(const string& input);
Base64Result base64Encode(const string_view& input);
Base64Result base64Encode(const char* input);

Base64Result base64Decode(LPCSTR input, DWORD input_size);
Base64Result base64Decode(const ByteBuffer& input);
Base64Result base64Decode(const string& input);
Base64Result base64Decode(const string_view& input);
Base64Result base64Decode(const char* input);

using CompressionResult = Result<ByteBuffer, Error<DWORD>>;
CompressionResult compress(LPCVOID data, SIZE_T data_size);
CompressionResult decompress(LPCVOID data, SIZE_T data_size);

} // Util namespace

namespace SHA256
{

using SHA256Result = Result<ByteBuffer, Error<NTSTATUS>>;

SHA256Result generate(PUCHAR data, ULONG data_size);
SHA256Result generate(const ByteBuffer& input);
SHA256Result generate(const string& input);
SHA256Result generate(string_view input);
SHA256Result generate(const char* input);


} // SHA256 namespace

namespace AES256_GCM
{

using Ciphertext = ByteBuffer;
using Plaintext = ByteBuffer;
using Nonce = ByteBuffer;
using Tag = ByteBuffer;
using Salt = ByteBuffer;

struct Encryption
{
    ByteBuffer ciphertext;
    ByteBuffer nonce;
    ByteBuffer tag;
    ByteBuffer salt;
    ByteBuffer additional_data;
};

using EncryptionResult = Result<Encryption, Error<NTSTATUS>>;

EncryptionResult encrypt(
    PUCHAR plaintext, ULONG plaintext_size,
    PUCHAR password, ULONG password_size,
    PUCHAR additional_data, ULONG additional_data_size
);

EncryptionResult encrypt(
    const ByteBuffer& plaintext,
    string_view password,
    string_view additional_data
);

EncryptionResult encrypt(
    void* data, size_t data_size,
    string_view password,
    string_view additional_data
);

EncryptionResult encrypt(
    string_view plaintext,
    string_view password,
    string_view additional_data
);


struct Decryption
{
    ByteBuffer plaintext;
};

using DecryptionResult = Result<Decryption, Error<NTSTATUS>>;

DecryptionResult decrypt(
    PUCHAR ciphertext, ULONG ciphertext_size,
    PUCHAR password, ULONG password_size,
    PUCHAR nonce, ULONG nonce_size,
    PUCHAR tag, ULONG tag_size,
    PUCHAR salt, ULONG salt_size,
    PUCHAR additional_data, ULONG additional_data_size
);

DecryptionResult decrypt(
    const ByteBuffer& ciphertext,
    string_view password,
    const ByteBuffer& nonce,
    const ByteBuffer& tag,
    const ByteBuffer& salt,
    const ByteBuffer& additional_data);

DecryptionResult decrypt(
    const Encryption& enc_res,
    string_view password);

bool writeToFile(const string& filename, const Encryption& data);

} // AES256_GCM namespace


} // WAPP namespace

#endif // WAPP_H
