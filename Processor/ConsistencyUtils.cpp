#ifndef CONSISTENCY_UTILS_CPP_
#define CONSISTENCY_UTILS_CPP_

#include "Processor/ConsistencyUtils.h"
#include "Math/gfp.hpp"
#include <algorithm>  // for remove_if, all_of
#include <cctype>     // for isspace, isxdigit 
#include <cstdlib>    // for strtol
#include <string>


// TODO: sample random scalar 
// TODO: secret-share new value through protocol

void convert_value(blst_fr *to, const gfp_<0, 4> *from) {
    blst_fr_from_uint64(to, from->as_bigint().data);
}

void convert_value(gfp_<0, 4> *to, const blst_fr *from) {
    uint64_t vals[4] = {0};
    blst_uint64_from_fr(vals, from);
    bigint b(vals, 4);
    *to = gfp_<0, 4>(b);
}

void convert_value(gfp_<0, 4> *to, const blst_fp *from) {
    uint64_t vals[6] = {0};
    blst_uint64_from_fp(vals, from);
    // TODO: is this correct?
    bigint b(vals, 6);
    *to = gfp_<0, 4>(b);
}

/*
void convert_value(gfp_<0, 4> *to, const blst_fp2 *from) {
    uint64_t vals[6] = {0};
    blst_uint64_from_fp2(vals, from);
    // TODO: is this correct?
    bigint b(vals, 6);
    *to = gfp_<0, 4>(b);
}
*/

void convert_value(g1_t *to, const fr_t *from) {
    g1_mul(to, blst_p1_generator(), from);
}

void convert_value(blst_scalar *to, const gfp_<0, 4> *from) {
    blst_scalar_from_uint64(to, from->as_bigint().data);
}

/**
 * Reads a single hex string from an input file stream and stores it in an octetStream.
 * 
 * @param input_file The input file stream to read from
 * @param os The octetStream to store the read data
 * @return true if the reading was successful, false otherwise
 */
bool read_single_hex_string(ifstream &input_file, octetStream &os)
{

    string line;
    if (!getline(input_file, line))
        return false;
    
    // Remove whitespace using a lambda function as the predicate
    line.erase(std::remove_if(line.begin(), line.end(), 
               [](unsigned char c) { return std::isspace(c); }), 
               line.end());
    
    // Check if the string has valid hex characters
    if (line.empty() || !std::all_of(line.begin(), line.end(), 
                                    [](unsigned char c) { return std::isxdigit(c); }))
        return false;
    
    // Ensure even length (each byte needs two hex characters)
    if (line.length() % 2 != 0)
        return false;

    // Calculate the number of bytes
    size_t num_bytes = line.length() / 2;
    
    // Resize the octetStream to accommodate the bytes
    os.resize(num_bytes);
    
    // Convert hex string to bytes
    // TODO: optimize this
    for (size_t i = 0; i < num_bytes; i++)
    {
        string byte_str = line.substr(i * 2, 2);
        octet byte_val = static_cast<octet>(std::stoul(byte_str.c_str(), nullptr, 16));
        // os.data[i] = byte_val;
        os.append(&byte_val,1);

    }
    
    // Set the length of the octetStream
    // os.len = num_bytes;
    // Reset read pointer
    // os.ptr = 0;
    
    return true;
}

// TODO: leave here? or in PCS file?
// input is a vector of scalar shares
// TODO: is this again lincomb?
// p0 + p1 x + p2 x^2 + p3 x^3 + p4 x^4 + ...
// TODO: first compute powers of beta, then do lincomb fast. or do it all in for loop. which one is faster
//




std::pair<std::vector<fr_t>, fr_t> polynomial_division_X_minus_c(const std::vector<fr_t>& poly, fr_t c) {
    // Handle edge cases
    if (poly.empty()) {
        return {std::vector<fr_t>(), FR_ZERO};
    }
    
    // If c is zero, division by X is just a shift
    if (fr_equal(&c, &FR_ZERO)) {
        // Check if X divides the polynomial (the constant term must be zero)
        if (!fr_equal(&poly[0], &FR_ZERO)) {
            throw std::invalid_argument("Polynomial not divisible by X");
        }
        
        std::vector<fr_t> quotient(poly.size() - 1);
        for (size_t i = 0; i < quotient.size(); ++i) {
            quotient[i] = poly[i + 1];
        }
        return {quotient, FR_ZERO};
    }
    
    // The degree is one less than the number of coefficients
    size_t n = poly.size();
    
    // If polynomial is just a constant, quotient is 0 and remainder is the constant
    if (n == 1) {
        return {std::vector<fr_t>(), poly[0]};
    }
    
    // Initialize the quotient polynomial (degree is one less than input)
    std::vector<fr_t> quotient(n - 1);
    
    // Use synthetic division (with modular arithmetic assumed inside fr_t operators)
    quotient[n - 2] = poly[n - 1];
    for (long i = n - 3; i >= 0; --i) {
        // quotient[i] = quotient[i + 1] * c + poly[i + 1];
        fr_t tmp;
        blst_fr_mul(&tmp, &quotient[i+1], &c);
        blst_fr_add(&quotient[i], &poly[i+1], &tmp);
        // The fr_t type should handle modular arithmetic internally
    }
    
    // The remainder
    // fr_t remainder = poly[0] + quotient[0] * c;
    fr_t tmp, remainder;
    blst_fr_mul(&tmp, &quotient[0], &c);
    blst_fr_add(&remainder, &poly[0], &tmp);
    
    return {quotient, remainder};
}

void g2_sub(g2_t *out, const g2_t *a, const g2_t *b) {
    g2_t bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
}

void g2_mul(g2_t *out, const g2_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    // BITS_PER_FIELD_ELEMENT = 255
    blst_p2_mult(out, a, s.b, 255);
}

void bytes_from_g2(blst_byte *out, const g2_t *in) {
    blst_p2_compress(out, in);
    // void blst_p2_compress(byte out[96], const blst_p2 *in);
}


/**
 * Convert untrusted bytes into a trusted and validated KZGCommitment.
 *
 * @param[out]  out The output commitment
 * @param[in]   b   The commitment bytes
 */
C_KZG_RET bytes_to_kzg_commitment(g2_t *out, const blst_byte *b) {
    blst_p2_affine p2_affine;

    /* Convert the bytes to a p2 point */
    /* The uncompress routine checks that the point is on the curve */
    if (blst_p2_uncompress(&p2_affine, b) != BLST_SUCCESS) return C_KZG_BADARGS;
    blst_p2_from_affine(out, &p2_affine);

    /* The point at infinity is accepted! */
    if (blst_p2_is_inf(out)) return C_KZG_OK;
    /* The point must be on the right subgroup */
    if (!blst_p2_in_g2(out)) return C_KZG_BADARGS;

    return C_KZG_OK;
}

std::vector<gfp_<0, 4>> read_clear_input(std::ifstream &infile, size_t n) {
    // std::string filename = "myfile"; // Path to the file
    // std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "ERROR: opening file!" << std::endl;
        return {};
    }

    std::vector<gfp_<0, 4>> input;
    input.reserve(n); 

    int x;
    for (size_t i = 0; i < n; i++) {
        if (!(infile >> x)) { 
            std::cerr << "ERROR: Failed to read integer at index " << i << std::endl;
            return {}; 
        }
        input.emplace_back(x);
    }
    return input;
}

#endif
