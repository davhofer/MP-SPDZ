/*
 * P381Element.h
 *
 */

#ifndef P381ELEMENT_H_
#define P381ELEMENT_H_

#include "Math/gfp.h"
#include "Processor/ConsistencyUtils.h"

// modulus (dec): 52435875175126190479447740508185965837690552500527637822603658699938581184513
// modulus (hex): 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
const uint64_t BLS12_381_Fr_modulus[4] = {
        0xFFFFFFFF00000001ULL, 
        0x53BDA402FFFE5BFEULL,
        0x3339D80809A1D805ULL,
        0x73EDA753299D7D48ULL
};

class P381Element : public ValueInterface
{
public:
    typedef gfp_<0, 4> Scalar;
    typedef g1_t Point;
    typedef fr_t Field;

private:
    g1_t point;

public:
    typedef P381Element next;
    typedef void Square;

    static const true_type invertible;

    static int size() { return 0; }
    static int length() { return 256; }
    static string type_string() { return "P381"; }

    static void init(bool init_field = false);
    static void finish();

    P381Element();
    P381Element(const P381Element& other);
    P381Element(const Scalar& other);
    P381Element(const Point& other);
    P381Element(word other);
    ~P381Element();

    P381Element& operator=(const P381Element& other);

    void check();

    void set_point(g1_t p);
    g1_t get_point() const;

    Scalar x() const;
    void randomize(PRNG& G, int n = -1);
    void input(istream& s, bool human);
    static string type_short() { return "ec"; }
    static DataFieldType field_type() { return DATA_INT; }

    P381Element operator+(const P381Element& other) const;
    P381Element operator-(const P381Element& other) const;
    P381Element operator*(const Scalar& other) const;
    P381Element operator*(const int other) const;

    P381Element& operator+=(const P381Element& other);
    P381Element& operator/=(const Scalar& other);

    bool operator==(const P381Element& other) const;
    bool operator!=(const P381Element& other) const;

    void pack(octetStream& os, int = -1) const;
    void unpack(octetStream& os, int = -1);

    friend ostream& operator<<(ostream& s, const P381Element& x);

    // Custom functions for compatibility with libff
    static P381Element zero() {
        return P381Element();
    }
    static const int num_limbs = Scalar::N_LIMBS;
    P381Element dbl() {
        return *this + *this;
    }
    P381Element mixed_add(const P381Element &other) {
        return *this + other;
    }

};


#ifndef PROTOCOLS_MALICIOUSSHAMIRSHARE_H_
P381Element operator*(const P381Element::Scalar& x, const P381Element& y);
#endif

P381Element operator*(const int x, const P381Element& y);

// G2 for signature
class P381ElementG2 : public ValueInterface
{
public:
    typedef gfp_<0, 4> Scalar;
    typedef g2_t Point;
    typedef fr_t Field;

private:
    g2_t point;

public:
    typedef P381ElementG2 next;
    typedef void Square;

    static const true_type invertible;

    static int size() { return 0; }
    static int length() { return 256; }
    static string type_string() { return "P381G2"; }

    static void init(bool init_field = false);
    static void finish();

    P381ElementG2();
    P381ElementG2(const P381ElementG2& other);
    P381ElementG2(const Scalar& other);
    P381ElementG2(const Point& other);
    P381ElementG2(word other);
    ~P381ElementG2();

    P381ElementG2& operator=(const P381ElementG2& other);

    void check();

    void set_point(g2_t p);
    g2_t get_point() const;

    void randomize(PRNG& G, int n = -1);
    void input(istream& s, bool human);
    static string type_short() { return "ec"; }
    static DataFieldType field_type() { return DATA_INT; }

    P381ElementG2 operator+(const P381ElementG2& other) const;
    P381ElementG2 operator-(const P381ElementG2& other) const;
    P381ElementG2 operator*(const Scalar& other) const;
    P381ElementG2 operator*(const int other) const;

    P381ElementG2& operator+=(const P381ElementG2& other);
    P381ElementG2& operator/=(const Scalar& other);

    bool operator==(const P381ElementG2& other) const;
    bool operator!=(const P381ElementG2& other) const;

    void pack(octetStream& os, int = -1) const;
    void unpack(octetStream& os, int = -1);

    friend ostream& operator<<(ostream& s, const P381ElementG2& x);


    // Custom functions for compatibility with libff
    static P381ElementG2 zero() {
        return P381ElementG2();
    }
    static const int num_limbs = Scalar::N_LIMBS;
    P381ElementG2 dbl() {
        // this should be implemented in openssl?
        return *this + *this;
    }
    P381ElementG2 mixed_add(const P381ElementG2 &other) {
        return *this + other;
    }

    // End of custom functions
};


#ifndef PROTOCOLS_MALICIOUSSHAMIRSHARE_H_
P381ElementG2 operator*(const P381ElementG2::Scalar& x, const P381ElementG2& y);
#endif

P381ElementG2 operator*(const int x, const P381ElementG2& y);

#endif /* P381ELEMENT_H_ */
