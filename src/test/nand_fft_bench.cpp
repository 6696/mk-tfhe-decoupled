#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <sys/time.h>
#include "tfhe.h"
#include "polynomials.h"
#include "lwesamples.h"
#include "lwekey.h"
#include "lweparams.h"
#include "tlwe.h"
#include "tgsw.h"



#include "mkTFHEparams.h"
#include "mkTFHEkeys.h"
#include "mkTFHEkeygen.h"
#include "mkTFHEsamples.h"
#include "mkTFHEfunctions.h"





 

using namespace std;



// **********************************************************************************
// ********************************* MAIN *******************************************
// **********************************************************************************


void dieDramatically(string message) {
    cerr << message << endl;
    abort();
} 


        

int32_t main(int32_t argc, char **argv) {

    // generate params 
    static const int32_t k = 1;
    static const double ks_stdev = 3.05e-5;// 2.44e-5; //standard deviation
    static const double bk_stdev = 3.72e-9; // 3.29e-10; //standard deviation
    static const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space
    static const int32_t n = 560; //500;            // LWE modulus
    static const int32_t n_extract = 1024;    // LWE extract modulus (used in bootstrapping)
    static const int32_t hLWE = 0;         // HW secret key LWE --> not used
    static const double stdevLWE = 0.012467;      // LWE ciphertexts standard deviation
    static const int32_t Bksbit = 2;       // Base bit key switching
    static const int32_t dks = 8;          // dimension key switching
    static const double stdevKS = ks_stdev; // 2.44e-5;       // KS key standard deviation
    static const int32_t N = 1024;            // RLWE,RGSW modulus
    static const int32_t hRLWE = 0;        // HW secret key RLWE,RGSW --> not used
    static const double stdevRLWEkey = bk_stdev; // 3.29e-10; // 0; // 0.012467;  // RLWE key standard deviation
    static const double stdevRLWE = bk_stdev; // 3.29e-10; // 0; // 0.012467;     // RLWE ciphertexts standard deviation
    static const double stdevRGSW = bk_stdev; // 3.29e-10;     // RGSW ciphertexts standard deviation 
    static const int32_t Bgbit = 8;        // Base bit gadget
    static const int32_t dg = 4;           // dimension gadget
    static const double stdevBK = bk_stdev; // 3.29e-10;       // BK standard deviation
//    int32_t parties = 0;      // number of parties

    // new parameters 
    // 2 parties, B=2^9, d=3 -> works
    // 4 parties, B=2^8, d=4 -> works
    // 8 parties, B=2^6, d=5 -> works 

    for(int32_t parties = 2; parties < 100; parties++) {
        // params
        LweParams *extractedLWEparams = new_LweParams(n_extract, ks_stdev, max_stdev);
        LweParams *LWEparams = new_LweParams(n, ks_stdev, max_stdev);
        TLweParams *RLWEparams = new_TLweParams(N, k, bk_stdev, max_stdev);
        MKTFHEParams *MKparams = new_MKTFHEParams(n, n_extract, hLWE, stdevLWE, Bksbit, dks, stdevKS, N,
                                                  hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit, dg, stdevBK,
                                                  parties);

        // LWE key
        MKLweKey *MKlwekey = new_MKLweKey(LWEparams, MKparams);
        MKLweKeyGen(MKlwekey);

        // RLWE key
        MKRLweKey *MKrlwekey = new_MKRLweKey(RLWEparams, MKparams);
        MKRLweKeyGen(MKrlwekey);

        // LWE key extracted
        MKLweKey *MKextractedlwekey = new_MKLweKey(extractedLWEparams, MKparams);
        MKtLweExtractKey(MKextractedlwekey, MKrlwekey);

        // bootstrapping + key switching keys
        MKLweBootstrappingKey_v2 *MKlweBK = new_MKLweBootstrappingKey_v2(LWEparams, RLWEparams, MKparams);
        MKlweCreateBootstrappingKey_v2(MKlweBK, MKlwekey, MKrlwekey, MKextractedlwekey,
                                       extractedLWEparams, LWEparams, RLWEparams, MKparams);

        // bootstrapping FFT + key switching keys
        MKLweBootstrappingKeyFFT_v2 *MKlweBK_FFT = new_MKLweBootstrappingKeyFFT_v2(MKlweBK, LWEparams, RLWEparams,
                                                                                   MKparams);

        // use current time as seed for the random generator
        srand(time(0));

        int32_t mess1 = rand() % 2;
        int32_t mess2 = rand() % 2;
        int32_t out = 1 - (mess1 * mess2);
        // generate 2 samples in input
        MKLweSample *test_in1 = new_MKLweSample(LWEparams, MKparams);
        MKLweSample *test_in2 = new_MKLweSample(LWEparams, MKparams);
        MKbootsSymEncrypt(test_in1, mess1, MKlwekey);
        MKbootsSymEncrypt(test_in2, mess2, MKlwekey);
        // generate output sample
        MKLweSample *test_out_v2m2 = new_MKLweSample(LWEparams, MKparams);

        // evaluate MK bootstrapped NAND
        clock_t begin_NAND_v2m2 = clock();
        MKbootsNAND_FFT_v2m2(test_out_v2m2, test_in1, test_in2, MKlweBK_FFT, LWEparams, extractedLWEparams,
                             RLWEparams, MKparams, MKrlwekey);
        clock_t end_NAND_v2m2 = clock();
        double time_NAND_v2m2 = ((double) end_NAND_v2m2 - begin_NAND_v2m2) / CLOCKS_PER_SEC;
        cout << time_NAND_v2m2 << endl;

        // verify NAND
        int32_t outNAND_v2m2 = MKbootsSymDecrypt(test_out_v2m2, MKlwekey);
        if (outNAND_v2m2 != out) {
            cout << "ERROR!!! " << parties;
//                return 1;
        }



        // delete samples
        delete_MKLweSample(test_out_v2m2);
        delete_MKLweSample(test_in2);
        delete_MKLweSample(test_in1);

        // delete keys
        delete_MKLweBootstrappingKeyFFT_v2(MKlweBK_FFT);
        delete_MKLweBootstrappingKey_v2(MKlweBK);
        delete_MKLweKey(MKextractedlwekey);
        delete_MKRLweKey(MKrlwekey);
        delete_MKLweKey(MKlwekey);
        // delete params
        delete_MKTFHEParams(MKparams);
        delete_TLweParams(RLWEparams);
        delete_LweParams(LWEparams);
        delete_LweParams(extractedLWEparams);
    }


    return 0;
}
