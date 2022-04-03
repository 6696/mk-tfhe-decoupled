#include <iostream>
#include <cstdlib>
#include "polynomials.h"
#include "lweparams.h"
#include "tlwe.h"
#include <tuple>

#include "mkTFHEparams.h"
#include "mkTFHEkeys.h"
#include "mkTFHEkeygen.h"
#include "mkTFHEsamples.h"
#include "mkTFHEfunctions.h"



using namespace std;

// **********************************************************************************
// **************************** STATIC PARAMETERS ***********************************
// **********************************************************************************

// generate params
static const int32_t k = 1;
static const double ks_stdev = 3.05e-5;// 2.44e-5; //standard deviation
static const double bk_stdev = 3.72e-9; // 3.29e-10; //standard deviation
static const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space
static const int32_t n = 560; //500;            // LWE modulus
static const int32_t n_extract = 1024;    // LWE extract modulus (used in bootstrapping)
//    static const int32_t hLWE = 0;         // HW secret key LWE --> not used
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
static const int32_t parties = 4;      // number of parties

// new parameters
// 2 parties, B=2^9, d=3 -> works
// 4 parties, B=2^8, d=4 -> works
// 8 parties, B=2^6, d=5 -> works

/// global vars

// **********************************************************************************
// ********************************* GATES ******************************************
// **********************************************************************************

void NAND(MKLweSample *result, MKLweSample *ca, MKLweSample *cb,
          tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
          MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    MKbootsNAND_FFT_v2m2(result, ca, cb, BK_FFT,
                         get<0>(params), get<1>(params),
                         get<2>(params), get<3>(params), PK);
    cout << 1 << flush;
}

void NOT(MKLweSample *result, MKLweSample *ca,
         tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
         MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    NAND(result, ca, ca, params, BK_FFT, PK);
}

void AND(MKLweSample *result, MKLweSample *ca, MKLweSample *cb,
         tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
         MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    NAND(result, ca, cb, params, BK_FFT, PK);
    NOT(result, result, params, BK_FFT, PK);
}

void OR(MKLweSample *result, MKLweSample *ca, MKLweSample *cb,
         tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
         MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    MKLweSample *tmp_a = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *tmp_b = new_MKLweSample(get<0>(params), get<3>(params));

    NOT(tmp_a, ca, params, BK_FFT, PK);
    NOT(tmp_b, cb, params, BK_FFT, PK);
    NAND(result, tmp_a, tmp_b, params, BK_FFT, PK);
}

void XOR(MKLweSample *result, MKLweSample *ca, MKLweSample *cb,
         tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
         MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    MKLweSample *tmp = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *tmp_a = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *tmp_b = new_MKLweSample(get<0>(params), get<3>(params));

    NAND(tmp, ca, cb, params, BK_FFT, PK);

    NAND(tmp_a, tmp, ca, params, BK_FFT, PK);
    NAND(tmp_b, tmp, cb, params, BK_FFT, PK);

    NAND(result, tmp_a, tmp_b, params, BK_FFT, PK);
}

void FIVE_BIT_AND(MKLweSample *result, MKLweSample *ca, MKLweSample *cb,
                  MKLweSample *cc, MKLweSample *cd, MKLweSample *ce,
                  tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
                  MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    AND(result, ca, cb, params, BK_FFT, PK);
    AND(result, result, cc, params, BK_FFT, PK);
    AND(result, result, cd, params, BK_FFT, PK);
    AND(result, result, ce, params, BK_FFT, PK);
}

void FOUR_BIT_AND(MKLweSample *result, MKLweSample *ca, MKLweSample *cb, MKLweSample *cc, MKLweSample *cd,
                  tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
                  MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    AND(result, ca, cb, params, BK_FFT, PK);
    AND(result, result, cc, params, BK_FFT, PK);
    AND(result, result, cd, params, BK_FFT, PK);
}

void FOUR_BIT_OR(MKLweSample *result, MKLweSample *ca, MKLweSample *cb, MKLweSample *cc, MKLweSample *cd,
                  tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
                  MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    OR(result, ca, cb, params, BK_FFT, PK);
    OR(result, result, cc, params, BK_FFT, PK);
    OR(result, result, cd, params, BK_FFT, PK);
}

void THREE_BIT_AND(MKLweSample *result, MKLweSample *ca, MKLweSample *cb, MKLweSample *cc,
                  tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
                  MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    AND(result, ca, cb, params, BK_FFT, PK);
    AND(result, result, cc, params, BK_FFT, PK);
}

// compares a > b, where a0 ist LSB
void FOUR_BIT_A_GT_B(MKLweSample *result,
                         MKLweSample *a0, MKLweSample *a1, MKLweSample *a2, MKLweSample *a3,
                         MKLweSample *b0, MKLweSample *b1, MKLweSample *b2, MKLweSample *b3,
                 tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params,
                 MKLweBootstrappingKeyFFT_v2* BK_FFT, MKRLweKey* PK){
    // define vars
    MKLweSample *not_b0 = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *not_b1 = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *not_b2 = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *not_b3 = new_MKLweSample(get<0>(params), get<3>(params));

    MKLweSample *tmp0 = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *tmp1 = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *tmp2 = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *tmp3 = new_MKLweSample(get<0>(params), get<3>(params));

    MKLweSample *t0 = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *t1 = new_MKLweSample(get<0>(params), get<3>(params));
    MKLweSample *t2 = new_MKLweSample(get<0>(params), get<3>(params));

    // init NOT
    NOT(not_b0, b0, params, BK_FFT, PK);
    NOT(not_b1, b1, params, BK_FFT, PK);
    NOT(not_b2, b2, params, BK_FFT, PK);
    NOT(not_b3, b3, params, BK_FFT, PK);

    // perform xor
    XOR(t0, b3, a3, params, BK_FFT, PK);
    XOR(t1, b2, a2, params, BK_FFT, PK);
    XOR(t2, b1, a1, params, BK_FFT, PK);

    AND(tmp3, a3, not_b3, params, BK_FFT, PK);

    THREE_BIT_AND(tmp2, a2, t0, not_b2, params, BK_FFT, PK);

    FOUR_BIT_AND(tmp1, not_b1, a1, t1, t0, params, BK_FFT, PK);

    FIVE_BIT_AND(tmp0, not_b0, a0, t2, t1, t0, params, BK_FFT, PK);

    FOUR_BIT_OR(result, tmp0, tmp1, tmp2, tmp3, params, BK_FFT, PK);
}

// **********************************************************************************
// ********************************* MAIN *******************************************
// **********************************************************************************


void dieDramatically(string message) {
    cerr << message << endl;
    abort();
}

static void deserialize_sample(vector<MKLweSample *> *vector, string path, int32_t b,
                               tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params)
{
    fstream infile = fstream(path, ios::in | ios::binary);
    for (int i = 0; i < b; i++) {
        MKLweSample *sample = new_MKLweSample(get<0>(params), get<3>(params));
        sample->deserialize(&infile);
        vector->push_back(sample);
    }
}

static void compute(string path, int32_t b)
{
    // Key generation
    cout << "Starting BIT DECRYPTION" << endl;

    LweParams *extractedLWEparams = new_LweParams(n_extract, ks_stdev, max_stdev);
    MKTFHEParams *MKparams = new_MKTFHEParams(n, n_extract, 0, stdevLWE, Bksbit, dks, stdevKS, N,
                                              hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit, dg, stdevBK, parties);
    LweParams *LWEparams = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *RLWEparams = new_TLweParams(N, k, bk_stdev, max_stdev);

    tuple<LweParams*, LweParams*, TLweParams*, MKTFHEParams*> params (LWEparams, extractedLWEparams, RLWEparams, MKparams);

    vector<MKLweSample *> sampleVector1;
    vector<MKLweSample *> sampleVector2;
    vector<MKLweSample *> sampleVector3;
    vector<MKLweSample *> sampleVector4;
    deserialize_sample(&sampleVector1, path + "/client1/sampleSeq1.binary", b, params);
    deserialize_sample(&sampleVector2, path + "/client2/sampleSeq2.binary", b, params);
    deserialize_sample(&sampleVector3, path + "/client3/sampleSeq3.binary", b, params);
    deserialize_sample(&sampleVector4, path + "/client4/sampleSeq4.binary", b, params);

    // KSK + BSK
    vector<MKLweBootstrappingKey_v2 *> bkVector;
    for (int i = 1; i <= 4; i++) {
        MKLweBootstrappingKey_v2 * bk = new_MKLweBootstrappingKey_v2(LWEparams, RLWEparams, MKparams);
        bk->deserialize(path + "/client" + to_string(i) + "/keys/KSKBSK.binary");
        bkVector.push_back(bk);
    }

    // PK
    vector<MKRLweKey *> pkVector;
    for (int i = 1; i <= 4; i++) {
        MKRLweKey* pk = new_MKRLweKey(RLWEparams, MKparams);
        pk->deserialize(path + "/client" + to_string(i) + "/keys/Public.binary");
        pkVector.push_back(pk);
    }

    MKLweBootstrappingKey_v2* BK = new_MKLweBootstrappingKey_v2Merged(bkVector, MKparams, LWEparams, RLWEparams);
    MKLweBootstrappingKeyFFT_v2* BK_FFT = new_MKLweBootstrappingKeyFFT_v2(BK, LWEparams, RLWEparams, MKparams);

    MKRLweKey* PK = MKRLweKeyMerge(pkVector, RLWEparams, MKparams);

    // init out bits
    vector<MKLweSample *> outVector;
    for (int i = 0; i < b; i++) {
        MKLweSample *out = new_MKLweSample(LWEparams, MKparams);
        outVector.push_back(out);
    }

    FOUR_BIT_OR(outVector[0], sampleVector1[0], sampleVector2[0], sampleVector3[0], sampleVector4[0], params, BK_FFT, PK);
    FOUR_BIT_OR(outVector[1], sampleVector1[1], sampleVector2[1], sampleVector3[1], sampleVector4[1], params, BK_FFT, PK);
    FOUR_BIT_OR(outVector[2], sampleVector1[2], sampleVector2[2], sampleVector3[2], sampleVector4[2], params, BK_FFT, PK);
    FOUR_BIT_OR(outVector[3], sampleVector1[3], sampleVector2[3], sampleVector3[3], sampleVector4[3], params, BK_FFT, PK);


//    for (int i = 0; i < b; i++) {
//        FOUR_BIT_AND(outVector[i],sampleVector1[i], sampleVector2[i],
//                     sampleVector3[i], sampleVector4[i],
//                     params, BK_FFT, PK);
//        AND(outVector[i],sampleVector1[i], sampleVector2[i], params, BK_FFT, PK);
//    }

    {
        fstream outfile = fstream(path + "/sampleResult.binary", ios::out | ios::binary);
        for (int i = 0; i < b; i++) {
            outVector[i]->serialize(&outfile);
        }
    }

    cout << "Next decryption: DONE!" << endl;

    // delete params
    delete_MKTFHEParams(MKparams);
    delete_TLweParams(RLWEparams);
    delete_LweParams(LWEparams);
}

static void show_usage(string name)
{
    cerr << "Usage: " << name << " OPTION\n"
    << "Options:\n"
    << "\tc \tPerform calculations on ciphertext" << endl
    << endl;
}

int32_t main(int argc, char* argv[]) {
    if (argc < 2) {
        show_usage(argv[0]);
        return 1;
    }
    vector <string> sources;
    string destination;

    switch (*argv[1])
    {
        default: {
            printf("Unknown option -%c\n\n", (*argv)[1]);
            break;
        }
        case 'c': {
            compute(argv[2], 6);
            break;
        }
    }


    return 0;
}
