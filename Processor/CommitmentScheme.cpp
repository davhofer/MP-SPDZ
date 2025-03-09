#ifndef COMMITMENT_SCHEME_CPP_
#define COMMITMENT_SCHEME_CPP_

#include "Processor/CommitmentScheme.h"
#include <libff/algebra/scalar_multiplication/multiexp.hpp>



void KZGCommitmentScheme::setup(size_t d, PRNG &shared_prng) {
    (void) shared_prng;




    const char *file_path = "deps/c-kzg/src/trusted_setup.txt"; 
    FILE *file = fopen(file_path, "rb");  

    if (!file) {
        perror("Error opening file");
        return;  // Exit with an error code
    }

    uint64_t precompute = 8;

    KZGSettings settings;
    C_KZG_RET result = load_trusted_setup_file(&settings, file, precompute);
    assert(result == C_KZG_OK);
    fclose(file);  // Close the file after use

    alpha_g1_points = std::vector<typename P381Element::Point>(d);
    for(size_t i=0;i<d;i++) {
        alpha_g1_points[i] = settings.g1_values_monomial[i % 4096];
    }
    alpha_g2 = settings.g2_values_monomial[1];

    free_trusted_setup(&settings);

}


P381Element KZGCommitmentScheme::commit(const std::vector<typename P381Element::Scalar> &poly) {



    assert(poly.size() <= alpha_g1_points.size());

    std::vector<typename P381Element::Field> coeffs(poly.size());


    for (unsigned long i = 0; i < poly.size(); i++) 
        convert_value(&coeffs[i], &poly[i]);


    CurvePoint::Point out;
    C_KZG_RET ret = g1_lincomb_fast(&out, alpha_g1_points.data(), coeffs.data(), coeffs.size());
    assert(ret == C_KZG_OK);
    return P381Element(out);
}


P381Element KZGCommitmentScheme::prove(typename P381Element::Point commitment, std::vector<typename P381Element::Field> &input_poly, typename P381Element::Field z, typename P381Element::Field y) {
    (void) commitment;

    // compute poly(X) - poly(z)
    // note that y = poly(z) 
    fr_t tmp;
    blst_fr_sub(&tmp, &input_poly[0], &y);


    input_poly[0] = tmp;
    
    /*
    std::vector<fr_t> divisor(2);
    divisor[1] = FR_ONE;
    blst_fr_sub(&divisor[0], &FR_ZERO, &z);
    */


    std::pair<std::vector<fr_t>, fr_t> res = polynomial_division_X_minus_c(input_poly, z);


    // check remainder == 0
    /*
     * TODO: uncomment, benchmarking
    if (!fr_equal(&res.second, &FR_ZERO)) {
        std::cout << "\nERROR: poly. division: remainder not zero!\n\n";
        return P381Element();
    }
    */
    

    g1_t pi;
    C_KZG_RET ret = g1_lincomb_fast(&pi, alpha_g1_points.data(), res.first.data(), res.first.size());
    assert(ret == C_KZG_OK);
    P381Element proof(pi);
    return proof;

}



bool KZGCommitmentScheme::verify(typename P381Element::Point c, typename P381Element::Field beta, typename P381Element::Field rho, typename P381Element::Point pi) {

    // check if:
    // e(pi, alpha*h2 - beta * h2) = e(c - rho*h1, h2)
    g1_t rhs_g1, tmp1;
    g2_t lhs_g2, tmp2;

    // compute beta * h2
    g2_mul(&tmp2, blst_p2_generator(), &beta);
    // compute alpha * h2 - beta * h2
    g2_sub(&lhs_g2, &alpha_g2, &tmp2);

    // compute rho * h1
    g1_mul(&tmp1, blst_p1_generator(), &rho);
    // compute c - rho * h1
    g1_sub(&rhs_g1, &c, &tmp1);

    return pairings_verify(&pi, &lhs_g2, &rhs_g1, blst_p2_generator());
}

void PedVecCommitmentScheme::setup(size_t d, PRNG &shared_prng) {
    (void) shared_prng;

    n = d;

    bases.clear();
    bases.reserve(d);


    typename P381Element::Scalar x(3);
    P381Element current(x);
    for (size_t i=0;i<n;i++) {
        // p.randomize(shared_prng, 1);
        bases.push_back(current.get_point());
        current = current * x;
    }


}

    // TODO: commit to shares or values?
P381Element PedVecCommitmentScheme::commit(const std::vector<typename P381Element::Scalar> &poly) {
    assert(poly.size() <= n);

    std::vector<typename P381Element::Field> coeffs(poly.size());

    for (unsigned long i = 0; i < poly.size(); i++) 
        convert_value(&coeffs[i], &poly[i]);

    CurvePoint::Point out;
    C_KZG_RET ret = g1_lincomb_fast(&out, bases.data(), coeffs.data(), coeffs.size());
    assert(ret == C_KZG_OK);
    return P381Element(out);

}


#endif
