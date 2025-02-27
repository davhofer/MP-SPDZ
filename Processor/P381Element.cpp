/*
 * P381Element.cpp
 *
 */
#ifndef P381ELEMENT_CPP_
#define P381ELEMENT_CPP_

// TODO: remodel as P381Element

#include "Processor/P381Element.h"

// #include "Math/gfp.hpp"
#include <iostream>
#include <iomanip>
// #include <cstdint>


// EC_GROUP* P381Element::curve;
//
void P381Element::init(bool init_field)
{
    // TODO: need to init field if the curve scalar field is different to the MPC scalar field!

    if (init_field) {
        bigint mod(BLS12_381_Fr_modulus, 4);
        Scalar::init_field(mod, false);
        // TODO: required?
        // free(mod);
    }
    /*
    curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    assert(curve != 0);
    if (init_field) {
        auto modulus = EC_GROUP_get0_order(curve);
        auto mod = BN_bn2dec(modulus);
        Scalar::init_field(mod, false);
        free(mod);
    }
    */
}

void P381Element::finish()
{
    // TODO: required?
    // EC_GROUP_free(curve);
}

P381Element::P381Element()
{
    /*
    point = EC_POINT_new(curve);
    assert(point != 0);
    assert(EC_POINT_set_to_infinity(curve, point) != 0);
    */
    point = G1_IDENTITY;
}

P381Element::~P381Element()
{
    // EC_POINT_free(point);
}

void P381Element::set_point(g1_t p) {
    point = p;
}

// TODO: how to mark function as const
g1_t P381Element::get_point() const {
    return point;
}

P381Element::P381Element(const Point& other) :
        P381Element()
{
    point = other;
}

P381Element::P381Element(const Scalar& other) :
        P381Element()
{
    // other.as_bigint().data[i]
    fr_t s;
    convert_value(&s, &other);
    g1_mul(&point, blst_p1_generator(), &s);
    
    // TODO: checks/assertions? -> at least for testing
    
    /*
    BIGNUM* exp = BN_new();
    BN_dec2bn(&exp, bigint(other).get_str().c_str());
    assert(EC_POINT_mul(curve, point, exp, 0, 0, 0) != 0);
    BN_free(exp);
    */
}

P381Element::P381Element(word other) :
        P381Element()
{
    // TODO: is this correct?
    // word is a 64bit unsigned int
    uint64_t vals[4] = {other, 0, 0, 0};
    fr_t s;
    blst_fr_from_uint64(&s, vals);
    g1_mul(&point, blst_p1_generator(), &s);

    /*
    BIGNUM* exp = BN_new();
    BN_dec2bn(&exp, to_string(other).c_str());
    assert(EC_POINT_mul(curve, point, exp, 0, 0, 0) != 0);
    BN_free(exp);
    */
}

P381Element& P381Element::operator =(const P381Element& other)
{
    /*
    assert(EC_POINT_copy(point, other.point) != 0);
    */

    point = other.point;
    return *this;

}

void P381Element::check()
{
    assert(blst_p1_on_curve(&point) && blst_p1_in_g1(&point));
}

// TODO: test
P381Element::Scalar P381Element::x() const
{
    // typedef struct { blst_fp x, y, z; } blst_p1;
    blst_fp x_fp = point.x;
    Scalar res;
    convert_value(&res, &x_fp);
    return res;
    /*
    BIGNUM* x = BN_new();
#if OPENSSL_VERSION_MAJOR >= 3
    assert(EC_POINT_get_affine_coordinates(curve, point, x, 0, 0) != 0);
#else
    assert(EC_POINT_get_affine_coordinates_GFp(curve, point, x, 0, 0) != 0);
#endif
    char* xx = BN_bn2dec(x);
    Scalar res((bigint(xx)));
    OPENSSL_free(xx);
    BN_free(x);
    return res;
    */
}

P381Element P381Element::operator +(const P381Element& other) const
{
    P381Element res;
    blst_p1_add_or_double(&res.point, &point, &other.point);
    // assert(EC_POINT_add(curve, res.point, point, other.point, 0) != 0);
    return res;
}

P381Element P381Element::operator -(const P381Element& other) const
{
    P381Element res;
    g1_sub(&res.point, &point, &other.point);
    return res;
    /*
    P381Element tmp = other;
    assert(EC_POINT_invert(curve, tmp.point, 0) != 0);
    return *this + tmp;
    */
}

P381Element P381Element::operator *(const Scalar& other) const
{
    P381Element res;
    fr_t fr;
    convert_value(&fr, &other);
    g1_mul(&res.point, &point, &fr);
    /*
    BIGNUM* exp = BN_new();
    BN_dec2bn(&exp, bigint(other).get_str().c_str());
    assert(EC_POINT_mul(curve, res.point, 0, point, exp, 0) != 0);
    BN_free(exp);
    */
    return res;
}

bool P381Element::operator ==(const P381Element& other) const
{
    return blst_p1_is_equal(&point, &other.point);
    /*
    int cmp = EC_POINT_cmp(curve, point, other.point, 0);
    assert(cmp == 0 or cmp == 1);
    return not cmp;
    */
}

P381Element operator*(const P381Element::Scalar& x, const P381Element& y)
{
    return y * x;
}

P381Element::P381Element(const P381Element& other) :
        P381Element()
{
    *this = other;
}

P381Element& P381Element::operator +=(const P381Element& other)
{
    *this = *this + other;
    return *this;
}

P381Element& P381Element::operator /=(const Scalar& other)
{
    *this = *this * other.invert();
    return *this;
}

bool P381Element::operator !=(const P381Element& other) const
{
    return not (*this == other);
}

// typedef unsigned char octet;
// octet is basically a byte
/* 
void blst_p1_serialize(byte out[96], const blst_p1 *in);
void blst_p1_compress(byte out[48], const blst_p1 *in);
BLST_ERROR blst_p1_uncompress(blst_p1_affine *out, const byte in[48]);
BLST_ERROR blst_p1_deserialize(blst_p1_affine *out, const byte in[96]);

void blst_p1_from_affine(blst_p1 *out, const blst_p1_affine *in);
*/


void P381Element::pack(octetStream& os, int) const
{
    // void blst_p1_compress(byte out[48], const blst_p1 *in);
    // don't need to store length since we know length...
    Bytes48 buffer;
    bytes_from_g1(&buffer, &point);
    os.append(buffer.bytes, 48);
    /*
    octet* buffer;
    size_t length = EC_POINT_point2buf(curve, point,
            POINT_CONVERSION_COMPRESSED, &buffer, 0);
//    std::cout << "Length " << length << std::endl;
    assert(length != 0);
    os.store_int(length, 8);
    os.append(buffer, length);
    free(buffer);
    */
}

void P381Element::unpack(octetStream& os, int)
{
    Bytes48 buffer;
    os.consume(buffer.bytes, 48);
    C_KZG_RET ret = bytes_to_kzg_commitment(&point, &buffer); 
    assert(ret == 0);
    /*
    size_t length = os.get_int(8);
    assert(
            EC_POINT_oct2point(curve, point, os.consume(length), length, 0)
                    != 0);
    */
}

void P381Element::randomize(PRNG& G, int n)
{
    (void) n;
    P381Element::Scalar newscalar;
    newscalar.randomize(G, n);
    point = P381Element(newscalar).point;
}

ostream& operator <<(ostream& s, const P381Element& x)
{
    // TODO: convert point to compressed bytes, print out bytes as hex
    Bytes48 bytes;
    bytes_from_g1(&bytes, &x.point);

    s << std::hex << std::setfill('0'); // Set hex mode and zero-padding
    for (size_t i = 0; i < 48; ++i) {
        s << std::setw(2) << static_cast<int>(bytes.bytes[i]); // Print each byte as a 2-digit hex
    }
    s << std::dec; // Reset to decimal mode if needed
    return s;

    /*
    char* hex = EC_POINT_point2hex(x.curve, x.point,
            POINT_CONVERSION_COMPRESSED, 0);
    s << hex;
    OPENSSL_free(hex);
    return s;
    */
}

void P381Element::input(istream& s,bool human)
{
    P381Element::Scalar newscalar;
    newscalar.input(s,human);
    point = P381Element(newscalar).point;
}

//octetStream P381Element::hash(size_t n_bytes) const
//{
//    octetStream os;
//    pack(os);
//    auto res = os.hash();
//    assert(n_bytes >= res.get_length());
//    res.resize_precise(n_bytes);
//    return res;
//}

#endif
