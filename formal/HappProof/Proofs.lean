import HappProof.Protocol

namespace HappProof

theorem checkpoint_satisfies_refl (c : Checkpoint) : c.satisfies c := by
  cases c <;> simp [Checkpoint.satisfies, Checkpoint.satisfiesB]

theorem usedJti_markJti (st : State) (jti x : TokenId) :
    (st.markJti jti).usedJti x = (st.usedJti x || (x == jti)) := by
  simp [State.markJti]

theorem usedJti_markJti_self (st : State) (jti : TokenId) :
    (st.markJti jti).usedJti jti = true := by
  simp [usedJti_markJti]

theorem usedChallenge_markChallenge (st : State) (cid x : ChallengeId) :
    (st.markChallenge cid).usedChallenge x = (st.usedChallenge x || (x == cid)) := by
  simp [State.markChallenge]

theorem usedChallenge_markChallenge_self (st : State) (cid : ChallengeId) :
    (st.markChallenge cid).usedChallenge cid = true := by
  simp [usedChallenge_markChallenge]

theorem verify_rejects_route_mismatch
    (cfg : Config) (st : State) (route : RouteId) (cred : Credential)
    (hroute : (st.routeBinding route != some cred.session) = true) :
    verifyAndConsume cfg st route cred = .error .routeIsolationViolation := by
  simp [verifyAndConsume, hroute]

theorem verify_rejects_used_jti
    (cfg : Config) (st : State) (route : RouteId) (cred : Credential) (sess : Session)
    (hroute : st.routeBinding route = some cred.session)
    (hsess : st.sessions cred.session = some sess)
    (haud : sess.aud = cred.aud)
    (hcap : sess.cap = cred.cap)
    (hused : st.usedJti cred.jti = true) :
    verifyAndConsume cfg st route cred = .error .replayJti := by
  simp [verifyAndConsume, hroute, hsess, haud, hcap, hused]

theorem verify_rejects_checkpoint_pairing
    (cfg : Config) (st : State) (route : RouteId) (cred : Credential) (sess : Session)
    (hroute : st.routeBinding route = some cred.session)
    (hsess : st.sessions cred.session = some sess)
    (haud : sess.aud = cred.aud)
    (hcap : sess.cap = cred.cap)
    (hfresh : st.usedJti cred.jti = false)
    (hweak : cred.checkpoint.satisfiesB (cfg.requiredCheckpoint cred.cap) = false) :
    verifyAndConsume cfg st route cred = .error .checkpointTooWeak := by
  simp [verifyAndConsume, hroute, hsess, haud, hcap, hfresh, hweak]

theorem verify_rejects_used_challenge
    (cfg : Config) (st : State) (route : RouteId) (cred : Credential) (sess : Session) (cid : ChallengeId)
    (hroute : st.routeBinding route = some cred.session)
    (hsess : st.sessions cred.session = some sess)
    (haud : sess.aud = cred.aud)
    (hcap : sess.cap = cred.cap)
    (hfresh : st.usedJti cred.jti = false)
    (hpair : cred.checkpoint.satisfiesB (cfg.requiredCheckpoint cred.cap) = true)
    (hreq : cfg.challengeRequired cred.cap = true)
    (hcid : cred.challengeId = some cid)
    (hused : st.usedChallenge cid = true) :
    verifyAndConsume cfg st route cred = .error .challengeAlreadyUsed := by
  simp [verifyAndConsume, hroute, hsess, haud, hcap, hfresh, hpair, hreq, hcid, hused]

theorem verify_nonchallenge_path_marks_jti
    (cfg : Config) (st : State) (route : RouteId) (cred : Credential) (sess : Session)
    (hroute : st.routeBinding route = some cred.session)
    (hsess : st.sessions cred.session = some sess)
    (haud : sess.aud = cred.aud)
    (hcap : sess.cap = cred.cap)
    (hfresh : st.usedJti cred.jti = false)
    (hpair : cred.checkpoint.satisfiesB (cfg.requiredCheckpoint cred.cap) = true)
    (hreqFalse : cfg.challengeRequired cred.cap = false) :
    verifyAndConsume cfg st route cred = .ok (st.markJti cred.jti)
      ∧ (st.markJti cred.jti).usedJti cred.jti = true := by
  constructor
  · simp [verifyAndConsume, hroute, hsess, haud, hcap, hfresh, hpair, hreqFalse]
  · simp [State.markJti]

theorem verify_challenge_path_is_atomic
    (cfg : Config) (st : State) (route : RouteId) (cred : Credential) (sess : Session)
    (cid : ChallengeId) (chal : Challenge)
    (hroute : st.routeBinding route = some cred.session)
    (hsess : st.sessions cred.session = some sess)
    (haud : sess.aud = cred.aud)
    (hcap : sess.cap = cred.cap)
    (hfresh : st.usedJti cred.jti = false)
    (hpair : cred.checkpoint.satisfiesB (cfg.requiredCheckpoint cred.cap) = true)
    (hreq : cfg.challengeRequired cred.cap = true)
    (hcid : cred.challengeId = some cid)
    (hchalUnused : st.usedChallenge cid = false)
    (hchal : st.outstandingChallenge cid = some chal)
    (hctx : chal.aud = cred.aud ∧ chal.cap = cred.cap ∧ chal.session = cred.session) :
    verifyAndConsume cfg st route cred = .ok ((st.markJti cred.jti).markChallenge cid)
      ∧ ((st.markJti cred.jti).markChallenge cid).usedJti cred.jti = true
      ∧ ((st.markJti cred.jti).markChallenge cid).usedChallenge cid = true := by
  rcases hctx with ⟨hcaud, hccap, hcsess⟩
  have hctxBool :
      (chal.aud != cred.aud || chal.cap != cred.cap || chal.session != cred.session) = false := by
    simp [hcaud, hccap, hcsess]
  constructor
  · simp [verifyAndConsume, hroute, hsess, haud, hcap, hfresh, hpair, hreq, hcid, hchalUnused, hchal, hctxBool]
  constructor
  · simp [State.markJti, State.markChallenge]
  · simp [State.markJti, State.markChallenge]

end HappProof
