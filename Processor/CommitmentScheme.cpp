#ifndef COMMITMENT_SCHEME_CPP_
#define COMMITMENT_SCHEME_CPP_

#include "Processor/CommitmentScheme.h"



void KZGCommitmentScheme::setup() {
    const char *file_path = "deps/c-kzg/src/trusted_setup.txt"; 
    FILE *file = fopen(file_path, "rb");  

    if (!file) {
        perror("Error opening file");
        return;  // Exit with an error code
    }

    uint64_t precompute = 9;

    C_KZG_RET result = load_trusted_setup_file(&settings, file, precompute);

    assert(result == C_KZG_OK);
    fclose(file);  // Close the file after use
}


P381Element KZGCommitmentScheme::commit(const std::vector<typename P381Element::Field> &poly) {
    CurvePoint::Point out;
    C_KZG_RET ret = g1_lincomb_fast(&out, settings.g1_values_monomial, poly.data(), poly.size());
    assert(ret == C_KZG_OK);
    return P381Element(out);
}

/*
// Test cases
void test_polynomial_division() {
    fr_t a, b, c, d, e;
    blst_fr_from_uint64(&a, 4);
    blst_fr_from_uint64(&b, 3);
    blst_fr_from_uint64(&c, 2);
    blst_fr_from_uint64(&d, 1);
    blst_fr_from_uint64(&e, 1);
    
    std::vector<fr_t> dividend = {a, b, c};
    std::vector<fr_t> divisor = {d, e};
    
    auto [quotient, remainder] = polynomial_division(dividend, divisor);
    
    std::cout << "Quotient size: " << quotient.size() << "\n";
    std::cout << "Remainder size: " << remainder.size() << "\n";
}
*/

P381Element KZGCommitmentScheme::prove(typename P381Element::Point commitment, std::vector<typename P381Element::Field> &input_poly, typename P381Element::Field z, typename P381Element::Field y) {
    (void) commitment;

    std::cout << "\nCommitmentScheme.prove\n";
    std::cout << "poly:\n";
    for(size_t i =0;i<input_poly.size();i++) {
        print_fr(&input_poly[i]);
    }
    std::cout << std::endl;
    std::cout << "beta: ";
    print_fr(&z);
    std::cout << "rho: ";
    print_fr(&y);

    // compute poly(X) - poly(z)
    // note that y = poly(z) 
    fr_t tmp;
    blst_fr_sub(&tmp, &input_poly[0], &y);
    input_poly[0] = tmp;
    
    std::vector<fr_t> divisor(2);
    divisor[1] = FR_ONE;
    blst_fr_sub(&divisor[0], &FR_ZERO, &z);

    std::pair<std::vector<fr_t>, fr_t> res = polynomial_division_X_minus_c(input_poly, z);




    // check remainder == 0
    if (!fr_equal(&res.second, &FR_ZERO)) {
        std::cout << "poly. division: remainder not zero!\n";
        return P381Element();
    }
    
    /*
    std::cout << "Quotient:\n";
    for(size_t i =0;i<res.first.size();i++) {
        print_fr(&res.first[i]);
    }

    std::cout << "remainder :\n";
    print_fr(&remainder);
    std::cout << std::endl;
    */

    g1_t pi;
    g1_lincomb_fast(&pi, settings.g1_values_monomial, res.first.data(), res.first.size());
    return P381Element(pi);


    /*
    std::cout << "testing poly div...\n";
    std::vector<typename P381Element::Field> p1, p2, p3;

    fr_t two, three, minus_one, minus_three, minus_two;
    blst_fr_sub(&minus_one, &FR_ZERO, &FR_ONE);
    blst_fr_add(&two, &FR_ONE, &FR_ONE);
    blst_fr_sub(&minus_two, &minus_one, &FR_ONE);
    blst_fr_add(&three, &FR_ONE, &two);
    blst_fr_sub(&minus_three, &FR_ZERO, &three);

    p1.push_back(FR_ONE);
    p1.push_back(minus_two);
    p1.push_back(minus_two);
    p1.push_back(minus_three);

    fr_t c1 = three;

    p2.push_back(three);
    p2.push_back(two);
    p2.push_back(FR_ONE);
    p2.push_back(two);

    fr_t c2 = minus_one;

    p3.push_back(two);
    p3.push_back(minus_one);
    p3.push_back(minus_one);
    p3.push_back(FR_ZERO);

    fr_t c3 = FR_ONE;

    std::cout << "fr minux one:\n";
    print_fr(&minus_one);

    std::pair<std::vector<fr_t>, fr_t> res1 = polynomial_division_X_minus_c(p1, c1);
    for(size_t i =0;i<res1.first.size();i++) {
        print_fr(&res1.first[i]);
    }
    std::cout << "remainder 1:\n";
    print_fr(&res1.second);

    std::cout << std::endl;
    std::cout << std::endl;
    std::pair<std::vector<fr_t>, fr_t> res2 = polynomial_division_X_minus_c(p2, c2);
    for(size_t i =0;i<res2.first.size();i++) {
        print_fr(&res2.first[i]);
    }
    std::cout << "remainder 2:\n";
    print_fr(&res2.second);
    std::cout << std::endl;

    std::pair<std::vector<fr_t>, fr_t> res3 = polynomial_division_X_minus_c(p3, c3);
    for(size_t i =0;i<res3.first.size();i++) {
        print_fr(&res3.first[i]);
    }
    std::cout << "remainder 3:\n";
    print_fr(&res3.second);
    std::cout << std::endl;

    std::vector<typename P381Element::Field> lagrange_poly(input_poly.size()), final_poly;
    C_KZG_RET fftret = fr_fft(lagrange_poly.data(), input_poly.data(), input_poly.size(), &settings);
    std::cout << "fft ret val: " << fftret << std::endl;

    final_poly = input_poly;


    // TODO: check if it works with "polynomial in evaluation form", or do we need to change smth?
    // TODO: is this correct?
    std::cout << "y:\n";
    print_fr(&y);

    Bytes48 proof_bytes;
    fr_t y_out;

    C_KZG_RET ret = compute_kzg_proof_wrapper(&proof_bytes, &y_out, final_poly.data(), final_poly.size(), &z, &settings);

    assert(ret == C_KZG_OK);

    std::cout << "y_out:\n";
    print_fr(&y_out);

    typename P381Element::Scalar y_out_gfp;
    convert_value(&y_out_gfp, &y_out);
    std::cout << "y_out_gfp:\n" << y_out_gfp << std::endl;



    // assert(fr_equal(&y_out, &y));
    bool equal = fr_equal(&y_out, &y);
    std::cout << ": " << equal << std::endl;

    g1_t proof;
    bytes_to_kzg_proof(&proof, &proof_bytes);
    return P381Element(proof);
    // return P381Element();

    */
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

bool KZGCommitmentScheme::verify(typename P381Element::Point c, typename P381Element::Field beta, typename P381Element::Field rho, typename P381Element::Point pi) {

    std::cout << "\nKZG::verify\n";
    std::cout << "c:\n";
    print_g1(&c);
    std::cout << "beta:\n";
    print_fr(&beta);
    std::cout << "rho:\n";
    print_fr(&rho);
    std::cout << "pi:\n";
    print_g1(&pi);

    // check if:
    // e(pi, alpha*h2 - beta * h2) = e(c - rho*h1, h2)
    g1_t rhs_g1, tmp1;
    g2_t lhs_g2, tmp2;

    // compute beta * h2
    g2_mul(&tmp2, blst_p2_generator(), &beta);
    // compute alpha * h2 - beta * h2
    g2_sub(&lhs_g2, &settings.g2_values_monomial[1], &tmp2);

    // compute rho * h1
    g1_mul(&tmp1, blst_p1_generator(), &rho);
    // compute c - rho * h1
    g1_sub(&rhs_g1, &c, &tmp1);

    return pairings_verify(&pi, &lhs_g2, &rhs_g1, blst_p2_generator());
}

#endif
