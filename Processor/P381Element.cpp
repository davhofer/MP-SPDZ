/*
 * P381Element.cpp
 *
 */
#ifndef P381ELEMENT_CPP_
#define P381ELEMENT_CPP_

#include "Processor/P381Element.h"

#include <iostream>
#include <iomanip>


void P381Element::init(bool init_field)
{

    if (init_field) {
        bigint mod(BLS12_381_Fr_modulus, 4);
        Scalar::init_field(mod, false);
    }
}

void P381Element::finish()
{
}

P381Element::P381Element()
{
    point = G1_IDENTITY;
}

P381Element::~P381Element()
{
}

void P381Element::set_point(g1_t p) {
    point = p;
}

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
    fr_t s;
    convert_value(&s, &other);
    g1_mul(&point, blst_p1_generator(), &s);
}

P381Element::P381Element(word other) :
        P381Element()
{
    uint64_t vals[4] = {other, 0, 0, 0};
    fr_t s;
    blst_fr_from_uint64(&s, vals);
    g1_mul(&point, blst_p1_generator(), &s);
}

P381Element& P381Element::operator =(const P381Element& other)
{
    point = other.point;
    return *this;

}

void P381Element::check()
{
    assert(blst_p1_on_curve(&point) && blst_p1_in_g1(&point));
}

P381Element::Scalar P381Element::x() const
{
    blst_fp x_fp = point.x;
    Scalar res;
    convert_value(&res, &x_fp);
    return res;
}

P381Element P381Element::operator +(const P381Element& other) const
{
    P381Element res;
    blst_p1_add_or_double(&res.point, &point, &other.point);
    return res;
}

P381Element P381Element::operator -(const P381Element& other) const
{
    P381Element res;
    g1_sub(&res.point, &point, &other.point);
    return res;
}

P381Element P381Element::operator *(const Scalar& other) const
{
    P381Element res;
    fr_t fr;
    convert_value(&fr, &other);
    g1_mul(&res.point, &point, &fr);
    return res;
}

P381Element P381Element::operator *(const int other) const
{
    P381Element res;
    Scalar s(other);
    fr_t fr;
    convert_value(&fr, &s);
    g1_mul(&res.point, &point, &fr);
    return res;
}

bool P381Element::operator ==(const P381Element& other) const
{
    return blst_p1_is_equal(&point, &other.point);
}

#ifndef PROTOCOLS_MALICIOUSSHAMIRSHARE_H_
P381Element operator*(const P381Element::Scalar& x, const P381Element& y)
{
    return y * x;
}
#endif 

P381Element operator*(const int x, const P381Element& y)
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


void P381Element::pack(octetStream& os, int) const
{
    Bytes48 buffer;
    bytes_from_g1(&buffer, &point);
    os.append(buffer.bytes, 48);
}

void P381Element::unpack(octetStream& os, int)
{
    Bytes48 buffer;
    os.consume(buffer.bytes, 48);
    C_KZG_RET ret = bytes_to_kzg_commitment(&point, &buffer); 
    assert(ret == 0);
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
    Bytes48 bytes;
    bytes_from_g1(&bytes, &x.point);

    s << std::hex << std::setfill('0'); // Set hex mode and zero-padding
    for (size_t i = 0; i < 48; ++i) {
        s << std::setw(2) << static_cast<int>(bytes.bytes[i]); // Print each byte as a 2-digit hex
    }
    s << std::dec; // Reset to decimal mode if needed
    return s;
}

void P381Element::input(istream& s,bool human)
{
    P381Element::Scalar newscalar;
    newscalar.input(s,human);
    point = P381Element(newscalar).point;
}

void P381ElementG2::init(bool init_field)
{
    // need to init field if the curve scalar field is different to the MPC scalar field
    if (init_field) {
        bigint mod(BLS12_381_Fr_modulus, 4);
        Scalar::init_field(mod, false);
    }
}

void P381ElementG2::finish()
{
}

P381ElementG2::P381ElementG2()
{
}

P381ElementG2::~P381ElementG2()
{
}

void P381ElementG2::set_point(g2_t p) {
    point = p;
}

g2_t P381ElementG2::get_point() const {
    return point;
}

P381ElementG2::P381ElementG2(const Point& other) :
        P381ElementG2()
{
    point = other;
}

P381ElementG2::P381ElementG2(const Scalar& other) :
        P381ElementG2()
{
    fr_t s;
    convert_value(&s, &other);
    g2_mul(&point, blst_p2_generator(), &s);
}

P381ElementG2::P381ElementG2(word other) :
        P381ElementG2()
{
    uint64_t vals[4] = {other, 0, 0, 0};
    fr_t s;
    blst_fr_from_uint64(&s, vals);
    g2_mul(&point, blst_p2_generator(), &s);
}

P381ElementG2& P381ElementG2::operator =(const P381ElementG2& other)
{
    point = other.point;
    return *this;

}

void P381ElementG2::check()
{
    assert(blst_p2_on_curve(&point) && blst_p2_in_g2(&point));
}

P381ElementG2 P381ElementG2::operator +(const P381ElementG2& other) const
{
    P381ElementG2 res;
    blst_p2_add_or_double(&res.point, &point, &other.point);
    return res;
}

P381ElementG2 P381ElementG2::operator -(const P381ElementG2& other) const
{
    P381ElementG2 res;
    g2_sub(&res.point, &point, &other.point);
    return res;
}

P381ElementG2 P381ElementG2::operator *(const Scalar& other) const
{
    P381ElementG2 res;
    fr_t fr;
    convert_value(&fr, &other);
    g2_mul(&res.point, &point, &fr);
    return res;
}

P381ElementG2 P381ElementG2::operator *(const int other) const
{
    P381ElementG2 res;
    Scalar s(other);
    fr_t fr;
    convert_value(&fr, &s);
    g2_mul(&res.point, &point, &fr);
    return res;
}

bool P381ElementG2::operator ==(const P381ElementG2& other) const
{
    return blst_p2_is_equal(&point, &other.point);
}

#ifndef PROTOCOLS_MALICIOUSSHAMIRSHARE_H_
P381ElementG2 operator*(const P381ElementG2::Scalar& x, const P381ElementG2& y)
{
    return y * x;
}
#endif 

P381ElementG2 operator*(const int x, const P381ElementG2& y)
{
    return y * x;
}

P381ElementG2::P381ElementG2(const P381ElementG2& other) :
        P381ElementG2()
{
    *this = other;
}

P381ElementG2& P381ElementG2::operator +=(const P381ElementG2& other)
{
    *this = *this + other;
    return *this;
}

P381ElementG2& P381ElementG2::operator /=(const Scalar& other)
{
    *this = *this * other.invert();
    return *this;
}

bool P381ElementG2::operator !=(const P381ElementG2& other) const
{
    return not (*this == other);
}

void P381ElementG2::pack(octetStream& os, int) const
{
    blst_byte buffer[96];
    bytes_from_g2(buffer, &point);
    os.append(buffer, 96);
}

void P381ElementG2::unpack(octetStream& os, int)
{
    blst_byte buffer[96];
    os.consume(buffer, 96);
    C_KZG_RET ret = bytes_to_kzg_commitment(&point, buffer); 
    assert(ret == 0);
}

void P381ElementG2::randomize(PRNG& G, int n)
{
    (void) n;
    P381ElementG2::Scalar newscalar;
    newscalar.randomize(G, n);
    point = P381ElementG2(newscalar).point;
}

ostream& operator <<(ostream& s, const P381ElementG2& x)
{
    blst_byte bytes[96];
    bytes_from_g2(bytes, &x.point);

    s << std::hex << std::setfill('0'); // Set hex mode and zero-padding
    for (size_t i = 0; i < 96; ++i) {
        s << std::setw(2) << static_cast<int>(bytes[i]); // Print each byte as a 2-digit hex
    }
    s << std::dec; // Reset to decimal mode if needed
    return s;
}

void P381ElementG2::input(istream& s,bool human)
{
    P381ElementG2::Scalar newscalar;
    newscalar.input(s,human);
    point = P381ElementG2(newscalar).point;
}

#endif
