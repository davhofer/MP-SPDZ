#ifndef COMMITMENT_SCHEME_H_
#define COMMITMENT_SCHEME_H_

#include "Processor/P381Element.h"

// what interface does each commitment scheme need to provide? basically, wrap the calls to the underlying library? or directly implement the commitment scheme, e.g. for pedersen
// provide a CurvePoint type
/*

vector<T> shares 
convert shares 
vector<Share<CurveScalar>> poly 


commitment scheme needs a vector of elements in its native scalar field 
the conversion from shares to scalar field elements depends on the secret share scheme 

Share type 
MPC value type 
Curve scalar type

convert share of MPC value to (native) Curve scalar 
- extract val from share => share dependent
- convert val to curve scalar => share independent


=> function to extract values from shares, this should probably be done in CC.commit function, depending on share type
=> function to convert different MP-SPDZ values to different curve field values, this should be a generic utility function that uses templating and overloading for all supported types

=> the various commitment schemes will then take

perform commitment on curve scalar
get Curve wrapper type

vector<T> shares

vector<CurveField>


*/

class KZGCommitmentScheme {
public:
    KZGSettings settings;
    typedef P381Element CurvePoint;

    ~KZGCommitmentScheme() {
        free_trusted_setup(&settings);
    }

    void setup();

    // TODO: commit to shares or values?
    P381Element commit(const std::vector<typename P381Element::Field> &poly);

    P381Element prove(typename P381Element::Point commitment, std::vector<typename P381Element::Field> &input_poly, typename P381Element::Field z, typename P381Element::Field y);

    bool verify(typename P381Element::Point c, typename P381Element::Field beta, typename P381Element::Field rho, typename P381Element::Point pi);
};


#endif
