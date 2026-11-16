#include <gtest/gtest.h>

#include <cbmpc/internal/core/convert.h>
#include <cbmpc/internal/core/log.h>
#include <cbmpc/internal/crypto/base_ecc.h>
#include <cbmpc/internal/crypto/commitment.h>
#include <cbmpc/internal/protocol/ecdsa_2p.h>
#include <cbmpc/internal/protocol/int_commitment.h>
#include <cbmpc/internal/protocol/sid.h>
#include <cbmpc/internal/protocol/util.h>
#include <cbmpc/internal/zk/zk_ec.h>

#include "utils/local_network/mpc_tester.h"

namespace {

using namespace coinbase;
using namespace coinbase::mpc;
using namespace coinbase::mpc::ecdsa2pc;
using namespace coinbase::testutils;

// Presigning: presign_batch between the two parties, then presign_complete_p2 and presign_finish_p1, each
// run by one party alone. Index 0 is party 1 (it holds the Paillier key and outputs the signature), index 1
// is party 2.
class ECDSA2PCPresign : public Network2PC {
 protected:
  void keygen(std::vector<ecdsa2pc::key_t>& keys) {
    keys.resize(2);
    mpc_runner->run_2pc([&keys](job_2p_t& job) {
      ASSERT_EQ(ecdsa2pc::dkg(job, crypto::curve_secp256k1, keys[job.get_party_idx()]), SUCCESS);
    });
  }

  void presign(const std::vector<ecdsa2pc::key_t>& keys, int n, std::vector<presig_t>& presigs) {
    presigs.resize(2);
    mpc_runner->run_2pc([&](job_2p_t& job) {
      const int i = job.get_party_idx();
      buf_t sid;
      ASSERT_EQ(presign_batch(job, sid, keys[i], n, presigs[i]), SUCCESS);
    });
    ASSERT_EQ(presigs[0].R.size(), size_t(n));
    ASSERT_EQ(presigs[1].R.size(), size_t(n));
  }

  static void expect_valid(const ecdsa2pc::key_t& key, mem_t msg, const buf_t& sig) {
    ASSERT_FALSE(sig.empty());
    crypto::ecc_pub_key_t pub(key.Q);
    EXPECT_EQ(pub.verify(msg, sig), SUCCESS);
  }

  // Message 4 for one slot, built as presign_complete_p2 builds it but with the mask rho given by the
  // caller, who may pass a negative one. The ciphertext and the proof are real: the proof is the same
  // computation as zk_ecdsa_sign_2pc_integer_commit_t::prove, which cannot be called here only because it
  // commits to rho with a plain modular power and so takes no negative rho.
  static void message4_with_rho(const ecdsa2pc::key_t& key, const presig_t& presig, int index, mem_t msg,
                                const bn_t& rho, buf_t& msg4) {
    const ecurve_t curve = key.curve;
    const auto& G = curve.generator();
    const mod_t& q = curve.order();
    const mod_t& N = key.paillier.get_N();
    const bn_t m = curve_msg_to_bn(msg, curve);
    const bn_t& k2 = presig.k[index];
    const ecc_point_t& R2 = presig.R2[index];
    const bn_t r = presig.R[index].get_x() % q;
    const ecc_point_t Q2 = key.x_share * G;
    const uint64_t aux = uint64_t(index);

    bn_t rc;
    ASSERT_EQ(key.paillier.rand_N_star(rc, /*resample_until_coprime=*/false), SUCCESS);

    bn_t w1, w2;
    MODULO(q) {
      w1 = k2.inv();
      w2 = w1 * key.x_share;
    }
    const bn_t& w3 = rho;

    // The plaintext P2 adds to r·k2⁻¹·(x1 + q·2^stat). Negative when rho is negative enough; Paillier takes
    // it modulo N, and it is far smaller than N in absolute value.
    bn_t plain = w1 * m + w2 * r + w3 * q;
    if (plain.sign() < 0) plain = N.value() + plain;
    ASSERT_TRUE(plain.sign() >= 0 && plain < N.value());

    crypto::paillier_t::rerand_scope_t paillier_rerand(crypto::paillier_t::rerand_e::off);
    crypto::paillier_t::elem_t c_key = key.paillier.elem(key.c_key) + (q << SEC_P_STAT);
    crypto::paillier_t::elem_t c = (c_key * (w1 * r)) + key.paillier.enc(plain, rc);

    const crypto::unknown_order_pedersen_params_t& params = crypto::unknown_order_pedersen_params_t::get();
    const mod_t& N_ped = params.N;
    const bn_t& g = params.g;
    const bn_t& h = params.h;

    zk_ecdsa_sign_2pc_integer_commit_t zk;
    crypto::paillier_t::elem_t c_key_tag = r * c_key;

    bn_t r1_w = bn_t::rand(N_ped << SEC_P_STAT);
    bn_t r2_w = bn_t::rand(N_ped << SEC_P_STAT);
    bn_t r3_w = bn_t::rand(N_ped << SEC_P_STAT);
    // g^rho for a negative rho is (g⁻¹)^|rho|. The absolute value is taken outside the modulus scope.
    const bool w3_negative = w3.sign() < 0;
    const bn_t w3_abs = w3_negative ? bn_t(0) - w3 : w3;
    MODULO(N_ped) {
      zk.W1 = g.pow(w1) * h.pow(r1_w);
      zk.W2 = g.pow(w2) * h.pow(r2_w);
      zk.W3 = (w3_negative ? g.inv() : g).pow(w3_abs) * h.pow(r3_w);
    }

    bn_t w1_tag = bn_t::rand(q << (SEC_P_STAT + SEC_P_COM));
    bn_t w2_tag = bn_t::rand(q << (SEC_P_STAT + SEC_P_COM));
    bn_t w3_tag = bn_t::rand((q * q) << (3 * SEC_P_STAT + SEC_P_COM));
    bn_t r1_w_tag = bn_t::rand(N_ped << (2 * SEC_P_STAT + SEC_P_COM));
    bn_t r2_w_tag = bn_t::rand(N_ped << (2 * SEC_P_STAT + SEC_P_COM));
    bn_t r3_w_tag = bn_t::rand(N_ped << (2 * SEC_P_STAT + SEC_P_COM));
    MODULO(N_ped) {
      zk.W1_tag = g.pow(w1_tag) * h.pow(r1_w_tag);
      zk.W2_tag = g.pow(w2_tag) * h.pow(r2_w_tag);
      zk.W3_tag = g.pow(w3_tag) * h.pow(r3_w_tag);
    }
    zk.G_tag = w1_tag * R2;
    zk.Q2_tag = w2_tag * R2;

    bn_t r_enc;
    ASSERT_EQ(key.paillier.rand_N_star(r_enc, /*resample_until_coprime=*/false), SUCCESS);
    crypto::paillier_t::elem_t C_enc_tag =
        key.paillier.enc(w1_tag * m + w2_tag * r + w3_tag * q, r_enc) + (w1_tag * c_key_tag);
    zk.C_enc_tag = C_enc_tag.to_bn();

    buf_t e_buf = crypto::ro::hash_string(N, c_key, c, Q2, R2, m, r, zk.W1, zk.W2, zk.W3, zk.W1_tag, zk.W2_tag,
                                          zk.W3_tag, zk.G_tag, zk.Q2_tag, C_enc_tag, presig.sid, aux)
                      .bitlen(SEC_P_COM);
    zk.e = bn_t::from_bin(e_buf);

    zk.w1_tag_tag = w1_tag + zk.e * w1;
    zk.w2_tag_tag = w2_tag + zk.e * w2;
    zk.w3_tag_tag = w3_tag + zk.e * w3;
    zk.r1_w_tag_tag = r1_w_tag + zk.e * r1_w;
    zk.r2_w_tag_tag = r2_w_tag + zk.e * r2_w;
    zk.r3_w_tag_tag = r3_w_tag + zk.e * r3_w;
    MODULO(N) { zk.r_enc_tag_tag = r_enc * rc.pow(zk.e); }

    msg4 = coinbase::ser(c.to_bn(), zk);
  }

  // What message 4 decrypts to before P2's mask is added: k2⁻¹·m + (k2⁻¹·x2 mod q)·r + k2⁻¹·r·(x1 + q·2^stat),
  // as an integer. Only a test that holds both shares can compute it; it is what places a plaintext just
  // below or just above zero.
  static bn_t unmasked_plaintext(const std::vector<ecdsa2pc::key_t>& keys, const std::vector<presig_t>& presigs,
                                 int index, mem_t msg) {
    const ecurve_t curve = keys[1].curve;
    const mod_t& q = curve.order();
    const bn_t m = curve_msg_to_bn(msg, curve);
    const bn_t r = presigs[1].R[index].get_x() % q;
    bn_t w1, w2;
    MODULO(q) {
      w1 = presigs[1].k[index].inv();
      w2 = w1 * keys[1].x_share;
    }
    return w1 * m + w2 * r + (w1 * r) * (keys[0].x_share + (q << SEC_P_STAT));
  }

  static bn_t decrypt_message4(const ecdsa2pc::key_t& p1_key, mem_t msg4) {
    bn_t c;
    zk_ecdsa_sign_2pc_integer_commit_t zk;
    EXPECT_EQ(coinbase::deser(msg4, c, zk), SUCCESS);
    crypto::vartime_scope_t vartime_scope;
    return p1_key.paillier.decrypt(c);
  }
};

TEST_F(ECDSA2PCPresign, PresignCompleteFinish) {
  std::vector<ecdsa2pc::key_t> keys;
  std::vector<presig_t> presigs;
  keygen(keys);
  presign(keys, 3, presigs);

  for (int i = 0; i < 3; i++) {
    buf_t msg = crypto::gen_random(32);
    buf_t msg4, sig;
    ASSERT_EQ(presign_complete_p2(keys[1], presigs[1], i, msg, msg4), SUCCESS);
    ASSERT_EQ(presign_finish_p1(keys[0], presigs[0], i, msg, msg4, sig), SUCCESS);
    expect_valid(keys[0], msg, sig);
  }
}

// The proof on message 4 bounds the size of the plaintext, not its sign. A plaintext a little below zero
// and one a little above it must both finish with a valid signature: the two differ by one multiple of q,
// and which side of zero a given mask lands on depends on party 1's share.
TEST_F(ECDSA2PCPresign, FinishGivesAValidSignatureForAPlaintextOnEitherSideOfZero) {
  std::vector<ecdsa2pc::key_t> keys;
  std::vector<presig_t> presigs;
  keygen(keys);
  presign(keys, 2, presigs);
  const mod_t& q = keys[0].curve.order();
  const bn_t N_half = (keys[0].paillier.get_N().value() + 1) >> 1;

  {  // slot 0: just below zero
    buf_t msg = crypto::gen_random(32);
    const bn_t T = unmasked_plaintext(keys, presigs, 0, msg);
    const bn_t rho = (T / q.value() + 1).neg();
    ASSERT_TRUE((T + rho * q.value()).sign() < 0);

    buf_t msg4, sig;
    message4_with_rho(keys[1], presigs[1], 0, msg, rho, msg4);
    ASSERT_FALSE(msg4.empty());
    EXPECT_TRUE(decrypt_message4(keys[0], msg4) >= N_half);
    EXPECT_EQ(presign_finish_p1(keys[0], presigs[0], 0, msg, msg4, sig), SUCCESS);
    expect_valid(keys[0], msg, sig);
  }
  {  // slot 1: just above zero
    buf_t msg = crypto::gen_random(32);
    const bn_t T = unmasked_plaintext(keys, presigs, 1, msg);
    const bn_t rho = (T / q.value()).neg();
    ASSERT_TRUE((T + rho * q.value()).sign() >= 0);

    buf_t msg4, sig;
    message4_with_rho(keys[1], presigs[1], 1, msg, rho, msg4);
    ASSERT_FALSE(msg4.empty());
    EXPECT_TRUE(decrypt_message4(keys[0], msg4) < N_half);
    EXPECT_EQ(presign_finish_p1(keys[0], presigs[0], 1, msg, msg4, sig), SUCCESS);
    expect_valid(keys[0], msg, sig);
  }
}

// A mask outside what the proof allows is refused by the proof, whatever the plaintext.
TEST_F(ECDSA2PCPresign, FinishRefusesAMaskOutsideTheProofsRange) {
  std::vector<ecdsa2pc::key_t> keys;
  std::vector<presig_t> presigs;
  keygen(keys);
  presign(keys, 1, presigs);
  const mod_t& q = keys[0].curve.order();

  buf_t msg = crypto::gen_random(32);
  const bn_t rho = ((q.value() * q.value()) << (3 * SEC_P_STAT + SEC_P_COM + 2)).neg();
  buf_t msg4;
  message4_with_rho(keys[1], presigs[1], 0, msg, rho, msg4);
  ASSERT_FALSE(msg4.empty());

  buf_t sig(1);
  dylog_disable_scope_t no_log_err;
  EXPECT_NE(presign_finish_p1(keys[0], presigs[0], 0, msg, msg4, sig), SUCCESS);
  EXPECT_TRUE(sig.empty());
}

// The helper with an honest mask is accepted like presign_complete_p2's own message: it builds the proof
// the verifier expects, so the tests above fail for the reason they name and not for a malformed proof.
TEST_F(ECDSA2PCPresign, HelperMessageWithAnHonestMaskIsAccepted) {
  std::vector<ecdsa2pc::key_t> keys;
  std::vector<presig_t> presigs;
  keygen(keys);
  presign(keys, 1, presigs);
  const mod_t& q = keys[0].curve.order();

  buf_t msg = crypto::gen_random(32);
  buf_t msg4, sig;
  message4_with_rho(keys[1], presigs[1], 0, msg, bn_t::rand((q.value() * q.value()) << (SEC_P_STAT * 2)), msg4);
  ASSERT_EQ(presign_finish_p1(keys[0], presigs[0], 0, msg, msg4, sig), SUCCESS);
  expect_valid(keys[0], msg, sig);
}

// A finish that fails leaves nothing in the signature output, at whichever step it fails.
TEST_F(ECDSA2PCPresign, FailedFinishLeavesNoSignature) {
  std::vector<ecdsa2pc::key_t> keys;
  std::vector<presig_t> presigs;
  keygen(keys);
  presign(keys, 2, presigs);
  dylog_disable_scope_t no_log_err;

  {  // slot 0: the proof holds and the signature does not verify (party 1's own nonce is wrong)
    buf_t msg = crypto::gen_random(32);
    buf_t msg4;
    ASSERT_EQ(presign_complete_p2(keys[1], presigs[1], 0, msg, msg4), SUCCESS);
    presig_t wrong = presigs[0];
    MODULO(keys[0].curve.order()) { wrong.k[0] += 1; }
    buf_t sig(1);
    EXPECT_NE(presign_finish_p1(keys[0], wrong, 0, msg, msg4, sig), SUCCESS);
    EXPECT_TRUE(sig.empty());
  }
  {  // slot 1: the proof is for another message
    buf_t msg = crypto::gen_random(32);
    buf_t other = crypto::gen_random(32);
    buf_t msg4;
    ASSERT_EQ(presign_complete_p2(keys[1], presigs[1], 1, msg, msg4), SUCCESS);
    buf_t sig(1);
    EXPECT_NE(presign_finish_p1(keys[0], presigs[0], 1, other, msg4, sig), SUCCESS);
    EXPECT_TRUE(sig.empty());
  }
  {  // complete called with party 1's key: no message 4
    buf_t msg = crypto::gen_random(32);
    buf_t msg4(1);
    EXPECT_NE(presign_complete_p2(keys[0], presigs[0], 0, msg, msg4), SUCCESS);
    EXPECT_TRUE(msg4.empty());
  }
}

// A proof that fails at its Pedersen checks, which run under a modulus, must not leave that modulus set on
// the thread: the next signature on the same thread is computed as usual.
TEST_F(ECDSA2PCPresign, FailedProofLeavesNoModulusOnTheThread) {
  std::vector<ecdsa2pc::key_t> keys;
  std::vector<presig_t> presigs;
  keygen(keys);
  presign(keys, 2, presigs);

  {
    buf_t msg = crypto::gen_random(32);
    buf_t msg4;
    ASSERT_EQ(presign_complete_p2(keys[1], presigs[1], 0, msg, msg4), SUCCESS);

    // Change one response of the proof: every range and curve check still holds, the first Pedersen
    // equation does not.
    bn_t c;
    zk_ecdsa_sign_2pc_integer_commit_t zk;
    ASSERT_EQ(coinbase::deser(msg4, c, zk), SUCCESS);
    zk.r1_w_tag_tag += 1;
    buf_t tampered = coinbase::ser(c, zk);

    buf_t sig;
    dylog_disable_scope_t no_log_err;
    ASSERT_TRUE(crypto::thread_local_storage_mod() == nullptr);
    EXPECT_NE(presign_finish_p1(keys[0], presigs[0], 0, msg, tampered, sig), SUCCESS);
    EXPECT_TRUE(crypto::thread_local_storage_mod() == nullptr);
  }
  {
    buf_t msg = crypto::gen_random(32);
    buf_t msg4, sig;
    ASSERT_EQ(presign_complete_p2(keys[1], presigs[1], 1, msg, msg4), SUCCESS);
    ASSERT_EQ(presign_finish_p1(keys[0], presigs[0], 1, msg, msg4, sig), SUCCESS);
    expect_valid(keys[0], msg, sig);
  }
}

// Party 1 refuses nonce points from party 2 that are not on the key's curve, even with a proof that is
// valid on the curve they are on.
TEST_F(ECDSA2PCPresign, PresignRefusesPartyTwosPointsOnAnotherCurve) {
  std::vector<ecdsa2pc::key_t> keys;
  keygen(keys);
  const ecurve_t other = crypto::curve_p256;

  error_t p1_rv = UNINITIALIZED_ERROR;
  presig_t p1_presig;
  mpc_runner->run_2pc([&](job_2p_t& job) {
    if (job.is_p1()) {
      buf_t sid;
      dylog_disable_scope_t no_log_err;
      p1_rv = presign_batch(job, sid, keys[0], 1, p1_presig);
      return;
    }
    // Party 2, not following the protocol: its point and its proof are on another curve.
    buf_t sid, com_msg;
    ASSERT_EQ(generate_sid_fixed_2p(job, party_t::p2, sid), SUCCESS);
    ASSERT_EQ(job.p1_to_p2(com_msg), SUCCESS);
    std::vector<bn_t> k2 = {other.get_random_value()};
    std::vector<ecc_point_t> R2 = {k2[0] * other.generator()};
    zk::uc_batch_dl_t pi_2;
    pi_2.prove(R2, k2, sid, 2);
    ASSERT_EQ(job.p2_to_p1(R2, pi_2), SUCCESS);
  });

  EXPECT_NE(p1_rv, SUCCESS);
  EXPECT_TRUE(p1_presig.R.empty());
}

// A point that names no curve at all is refused as well, and party 1 comes back with an error.
TEST_F(ECDSA2PCPresign, PresignRefusesPartyTwosPointWithNoCurve) {
  std::vector<ecdsa2pc::key_t> keys;
  keygen(keys);
  const ecurve_t curve = crypto::curve_secp256k1;

  error_t p1_rv = UNINITIALIZED_ERROR;
  presig_t p1_presig;
  mpc_runner->run_2pc([&](job_2p_t& job) {
    if (job.is_p1()) {
      buf_t sid;
      dylog_disable_scope_t no_log_err;
      p1_rv = presign_batch(job, sid, keys[0], 1, p1_presig);
      return;
    }
    buf_t sid, com_msg;
    ASSERT_EQ(generate_sid_fixed_2p(job, party_t::p2, sid), SUCCESS);
    ASSERT_EQ(job.p1_to_p2(com_msg), SUCCESS);
    // The proof is for a real point; the point sent in its place names no curve.
    std::vector<bn_t> k2 = {curve.get_random_value()};
    std::vector<ecc_point_t> proved = {k2[0] * curve.generator()};
    zk::uc_batch_dl_t pi_2;
    pi_2.prove(proved, k2, sid, 2);
    std::vector<ecc_point_t> R2 = {ecc_point_t()};
    ASSERT_FALSE(R2[0].get_curve().valid());
    ASSERT_EQ(job.p2_to_p1(R2, pi_2), SUCCESS);
  });

  EXPECT_NE(p1_rv, SUCCESS);
  EXPECT_TRUE(p1_presig.R.empty());
}

// Party 2 refuses nonce points from party 1 that are not on the key's curve.
TEST_F(ECDSA2PCPresign, PresignRefusesPartyOnesPointsOnAnotherCurve) {
  std::vector<ecdsa2pc::key_t> keys;
  keygen(keys);
  const ecurve_t other = crypto::curve_p256;

  error_t p2_rv = UNINITIALIZED_ERROR;
  presig_t p2_presig;
  mpc_runner->run_2pc([&](job_2p_t& job) {
    if (job.is_p2()) {
      buf_t sid;
      dylog_disable_scope_t no_log_err;
      p2_rv = presign_batch(job, sid, keys[1], 1, p2_presig);
      return;
    }
    // Party 1, not following the protocol: its point, its proof and its commitment are on another curve.
    buf_t sid;
    ASSERT_EQ(generate_sid_fixed_2p(job, party_t::p2, sid), SUCCESS);
    std::vector<bn_t> k1 = {other.get_random_value()};
    std::vector<ecc_point_t> R1 = {k1[0] * other.generator()};
    zk::uc_batch_dl_t pi_1, pi_2;
    pi_1.prove(R1, k1, sid, 1);
    coinbase::crypto::commitment_t com(sid, job.get_pid(party_t::p1));
    com.gen(R1, pi_1);
    ASSERT_EQ(job.p1_to_p2(com.msg), SUCCESS);
    std::vector<ecc_point_t> R2;
    ASSERT_EQ(job.p2_to_p1(R2, pi_2), SUCCESS);
    ASSERT_EQ(job.p1_to_p2(com.rand, R1, pi_1), SUCCESS);
  });

  EXPECT_NE(p2_rv, SUCCESS);
  EXPECT_TRUE(p2_presig.R.empty());
}

// Party 2 refuses a point from party 1 that names no curve at all, and comes back with an error.
TEST_F(ECDSA2PCPresign, PresignRefusesPartyOnesPointWithNoCurve) {
  std::vector<ecdsa2pc::key_t> keys;
  keygen(keys);
  const ecurve_t curve = crypto::curve_secp256k1;

  error_t p2_rv = UNINITIALIZED_ERROR;
  presig_t p2_presig;
  mpc_runner->run_2pc([&](job_2p_t& job) {
    if (job.is_p2()) {
      buf_t sid;
      dylog_disable_scope_t no_log_err;
      p2_rv = presign_batch(job, sid, keys[1], 1, p2_presig);
      return;
    }
    // Party 1, not following the protocol: the proof and the commitment are for a real point; the point sent
    // in its place names no curve. A point with no curve cannot be committed to (hashing it needs its curve),
    // so the commitment covers the real point.
    buf_t sid;
    ASSERT_EQ(generate_sid_fixed_2p(job, party_t::p2, sid), SUCCESS);
    std::vector<bn_t> k1 = {curve.get_random_value()};
    std::vector<ecc_point_t> proved = {k1[0] * curve.generator()};
    zk::uc_batch_dl_t pi_1, pi_2;
    pi_1.prove(proved, k1, sid, 1);
    coinbase::crypto::commitment_t com(sid, job.get_pid(party_t::p1));
    com.gen(proved, pi_1);
    ASSERT_EQ(job.p1_to_p2(com.msg), SUCCESS);
    std::vector<ecc_point_t> R2;
    ASSERT_EQ(job.p2_to_p1(R2, pi_2), SUCCESS);
    std::vector<ecc_point_t> R1 = {ecc_point_t()};
    ASSERT_FALSE(R1[0].get_curve().valid());
    ASSERT_EQ(job.p1_to_p2(com.rand, R1, pi_1), SUCCESS);
  });

  EXPECT_NE(p2_rv, SUCCESS);
  EXPECT_TRUE(p2_presig.R.empty());
}

}  // namespace
