#pragma once

#include <stdint.h>

#include <cbmpc/internal/crypto/base.h>
#include <cbmpc/internal/protocol/mpc_job.h>
#include <cbmpc/internal/zk/zk_ec.h>
#include <cbmpc/internal/zk/zk_paillier.h>

namespace coinbase::mpc::ecdsa2pc {

struct key_t {
  party_t role;
  ecurve_t curve;
  ecc_point_t Q;
  bn_t x_share;
  bn_t c_key;
  crypto::paillier_t paillier;
};

/**
 * @specs:
 * - ecdsa-2pc-spec | ECDSA-2PC-Optimized-KeyGen-2P
 */
error_t dkg(job_2p_t& job, ecurve_t curve, key_t& key);

/**
 * @specs:
 * - ecdsa-2pc-spec | ECDSA-2PC-Optimized-Refresh-2P
 */
error_t refresh(job_2p_t& job, const key_t& key, key_t& new_key);

/**
 * @specs:
 * - ecdsa-2pc-spec | ECDSA-2PC-Sign-2P
 *
 * @notes:
 * - The input message must be the hash of the actual message.
 * - This is the variant that contains `ZK-Two-Party-ECDSA-Sign-Integer-Commit`
 */
error_t sign(job_2p_t& job, buf_t& sid, const key_t& key, const mem_t msg, buf_t& sig);
error_t sign_batch(job_2p_t& job, buf_t& sid, const key_t& key, const std::vector<mem_t>& msgs,
                   std::vector<buf_t>& sigs);

/**
 * @specs:
 * - ecdsa-2pc-spec | ECDSA-2PC-Sign-2P
 *
 * @notes:
 * - The input message must be the hash of the actual message.
 * - Message 4 is taken from section 9 so that it is compatible with normal sign.
 */
error_t sign_with_global_abort(job_2p_t& job, buf_t& sid, const key_t& key, const mem_t msg, buf_t& sig);
error_t sign_with_global_abort_batch(job_2p_t& job, buf_t& sid, const key_t& key, const std::vector<mem_t>& msgs,
                                     std::vector<buf_t>& sigs);

/**
 * @specs:
 * - ecdsa-2pc-spec | ECDSA-2PC-Optimized-KeyGen-2P
 *
 * @notes:
 * - We don't have a specific api for this in the spec, rather the steps are described in the optimized keygen api.
 */
struct paillier_gen_interactive_t {
  paillier_gen_interactive_t(const crypto::mpc_pid_t& pid) : range(pid), equal(pid) {}

  zk::pdl_t pdl;
  zk::paillier_pedersen_equal_interactive_t equal;
  zk::range_pedersen_interactive_t range;
  zk::valid_paillier_interactive_t valid;

  zk::valid_paillier_interactive_t::challenge_msg_t valid_m1;
  zk::valid_paillier_interactive_t::prover_msg_t valid_m2;
  bn_t N;
  bn_t c_key, r_key, rho, Com;

  AUTO(msg1, std::tie(N, c_key, Com, equal.msg1, range.msg1));
  AUTO(msg2, std::tie(equal.challenge, range.challenge, valid_m1));
  AUTO(msg3, std::tie(pdl, equal.msg2, range.msg2, valid_m2));

  void step1_p1_to_p2(crypto::paillier_t& paillier, const bn_t& x1, const mod_t& q, bn_t& c_key);
  void step2_p2_to_p1();
  void step3_p1_to_p2(const crypto::paillier_t& paillier, const bn_t& x1, const ecc_point_t& Q1,
                      const crypto::mpc_pid_t& prover_pid, mem_t sid);
  error_t step4_p2_output(crypto::paillier_t& paillier, const ecc_point_t& Q1, const bn_t& c_key,
                          const crypto::mpc_pid_t& prover_pid, mem_t sid);
};

struct zk_ecdsa_sign_2pc_integer_commit_t {
  bn_t W1, W2, W3, W1_tag, W2_tag, W3_tag;
  ecc_point_t G_tag, Q2_tag;
  bn_t C_enc_tag, e, w1_tag_tag, w2_tag_tag, w3_tag_tag, r1_w_tag_tag, r2_w_tag_tag, r3_w_tag_tag, r_enc_tag_tag;

  void convert(coinbase::converter_t& c) {
    c.convert(W1, W2, W3, W1_tag, W2_tag, W3_tag, G_tag, Q2_tag, C_enc_tag, e, w1_tag_tag, w2_tag_tag, w3_tag_tag,
              r1_w_tag_tag, r2_w_tag_tag, r3_w_tag_tag, r_enc_tag_tag);
  }

  /**
   * @specs:
   * - ecdsa-2pc-spec | Prove-ZK-Two-Party-ECDSA-Sign-Integer-Commit-1P
   *
   * @notes:
   * - The integer commitment is implemented inline
   */
  error_t prove(const crypto::paillier_t& paillier, const crypto::paillier_t::elem_t& ckey,
                const crypto::paillier_t::elem_t& c, const ecc_point_t& Q2, const ecc_point_t& R2, const bn_t& m_tag,
                const bn_t& r, const bn_t& k2, const bn_t& x2, const bn_t& rho, const bn_t& rc, mem_t sid,
                uint64_t aux);

  /**
   * @specs:
   * - ecdsa-2pc-spec | Verify-ZK-Two-Party-ECDSA-Sign-Integer-Commit-1P
   */
  error_t verify(const ecurve_t curve, const crypto::paillier_t& paillier, const crypto::paillier_t::elem_t& ckey,
                 const crypto::paillier_t::elem_t& c, const ecc_point_t& Q2, const ecc_point_t& R2, const bn_t& m_tag,
                 const bn_t& r, mem_t sid, uint64_t aux) const;
};


/**
 * Presigning: messages 1 to 3 of ECDSA-2PC-Sign-2P run ahead of the message
 * for a batch of n nonces, so that when a message comes P2 produces message 4
 * alone and P1 verifies and finishes alone. The message enters the protocol
 * only at message 4, and the commitment of message 1 covers R1 and its proof,
 * as in the spec. One slot signs one message: the caller must discard a slot
 * after its first use, whatever the outcome, since a nonce used twice reveals
 * the key.
 */
struct presig_t {
  party_t role;
  buf_t sid;
  std::vector<bn_t> k;          // this party's nonces: k1 on P1, k2 on P2
  std::vector<ecc_point_t> R;   // the joint nonce points, k1·R2 = k2·R1
  std::vector<ecc_point_t> R2;  // P2's nonce points, part of the statement P2 proves
};

constexpr int MAX_PRESIGN_BATCH = 4096;

error_t presign_batch(job_2p_t& job, buf_t& sid, const key_t& key, int n, presig_t& out);
error_t presign_complete_p2(const key_t& key, const presig_t& presig, int index, mem_t msg, buf_t& msg4);
error_t presign_finish_p1(const key_t& key, const presig_t& presig, int index, mem_t msg, mem_t msg4, buf_t& sig);

}  // namespace coinbase::mpc::ecdsa2pc
