#ifndef COMMITMENT_SCHEME_H_
#define COMMITMENT_SCHEME_H_

#include "Processor/P381Element.h"

class KZGCommitmentScheme {
public:
    typedef P381Element CurvePoint;

    ~KZGCommitmentScheme() {
    }

    std::vector<typename P381Element::Point> alpha_g1_points;
    g2_t alpha_g2;

    void setup(size_t d, PRNG &shared_prng);

    P381Element commit(const std::vector<typename P381Element::Scalar> &poly);

    P381Element prove(typename P381Element::Point commitment, std::vector<typename P381Element::Field> &input_poly, typename P381Element::Field z, typename P381Element::Field y);

    bool verify(typename P381Element::Point c, typename P381Element::Field beta, typename P381Element::Field rho, typename P381Element::Point pi);
};

class PedVecCommitmentScheme {
public:
    typedef P381Element CurvePoint;

    size_t n;
    std::vector<typename P381Element::Point> bases;

    void setup(size_t d, PRNG &shared_prng);

    P381Element commit(const std::vector<typename P381Element::Scalar> &poly);
};


#endif
