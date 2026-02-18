import HappProof.Protocol

namespace HappProof
namespace E2E

abbrev Audience := HappProof.Audience
abbrev Capability := HappProof.Capability
abbrev TokenId := HappProof.TokenId
abbrev ChallengeId := HappProof.ChallengeId
abbrev SessionId := HappProof.SessionId
abbrev RouteId := HappProof.RouteId
abbrev Checkpoint := HappProof.Checkpoint

inductive SessionStatus where
  | pending
  | approved
  | denied
deriving Repr, DecidableEq

structure Session where
  aud : Audience
  cap : Capability
  status : SessionStatus
  pohpVerified : Bool
  identityRequired : Bool
  identityDone : Bool
  challengeId : Option ChallengeId
deriving Repr, DecidableEq

structure Challenge where
  aud : Audience
  cap : Capability
  session : SessionId
deriving Repr, DecidableEq

structure Credential where
  jti : TokenId
  aud : Audience
  cap : Capability
  session : SessionId
  challengeId : Option ChallengeId
  checkpoint : Checkpoint
deriving Repr, DecidableEq

structure Config where
  requiredCheckpoint : Capability -> Checkpoint
  challengeRequired : Capability -> Bool

structure State where
  sessions : SessionId -> Option Session
  routeBinding : RouteId -> Option SessionId
  outstandingChallenge : ChallengeId -> Option Challenge
  usedJti : TokenId -> Bool
  usedChallenge : ChallengeId -> Bool

namespace State

def empty : State where
  sessions := fun _ => none
  routeBinding := fun _ => none
  outstandingChallenge := fun _ => none
  usedJti := fun _ => false
  usedChallenge := fun _ => false

def setSession (st : State) (sid : SessionId) (sess : Option Session) : State :=
  { st with sessions := fun x => if x = sid then sess else st.sessions x }

def setRouteBinding (st : State) (route : RouteId) (sid : Option SessionId) : State :=
  { st with routeBinding := fun x => if x = route then sid else st.routeBinding x }

def setOutstanding (st : State) (cid : ChallengeId) (chal : Option Challenge) : State :=
  { st with outstandingChallenge := fun x => if x = cid then chal else st.outstandingChallenge x }

def markUsedJti (st : State) (jti : TokenId) : State :=
  { st with usedJti := fun x => st.usedJti x || (x == jti) }

def markUsedChallenge (st : State) (cid : ChallengeId) : State :=
  { st with usedChallenge := fun x => st.usedChallenge x || (x == cid) }

end State

def routeInv (st : State) : Prop :=
  forall route sid, st.routeBinding route = some sid -> Exists fun s => st.sessions sid = some s

def Session.safeApproved (s : Session) : Prop :=
  s.status = .approved ->
    (s.pohpVerified = true /\ (s.identityRequired = false \/ s.identityDone = true))

def approvedInv (st : State) : Prop :=
  forall sid s, st.sessions sid = some s -> s.safeApproved

def Invariant (st : State) : Prop :=
  routeInv st /\ approvedInv st

theorem routeInv_empty : routeInv State.empty := by
  intro route sid h
  simp [State.empty] at h

theorem approvedInv_empty : approvedInv State.empty := by
  intro sid s h
  simp [State.empty] at h

theorem invariant_empty : Invariant State.empty := by
  exact And.intro routeInv_empty approvedInv_empty

theorem routeInv_setSession_some
    (st : State) (hInv : routeInv st) (sid : SessionId) (s : Session) :
    routeInv (State.setSession st sid (some s)) := by
  intro route sid' hBind
  by_cases hEq : sid' = sid
  · subst hEq
    exact Exists.intro s (by simp [State.setSession])
  · rcases hInv route sid' (by simpa [State.setSession, hEq] using hBind) with ⟨s0, hs0⟩
    exact Exists.intro s0 (by simp [State.setSession, hEq, hs0])

theorem routeInv_setRouteBinding_some
    (st : State) (hInv : routeInv st) (route : RouteId) (sid : SessionId)
    (hSess : Exists fun s => st.sessions sid = some s) :
    routeInv (State.setRouteBinding st route (some sid)) := by
  intro route' sid' hBind
  by_cases hEq : route' = route
  · subst hEq
    have hSidEq : sid = sid' := by
      simpa [State.setRouteBinding] using hBind
    have hSidEq' : sid' = sid := hSidEq.symm
    subst hSidEq'
    exact hSess
  · rcases hInv route' sid' (by simpa [State.setRouteBinding, hEq] using hBind) with ⟨s, hs⟩
    exact Exists.intro s hs

theorem approvedInv_setSession_some
    (st : State) (hInv : approvedInv st) (sid : SessionId) (sNew : Session)
    (hSafe : sNew.safeApproved) :
    approvedInv (State.setSession st sid (some sNew)) := by
  intro sid' s' hSess
  by_cases hEq : sid' = sid
  · subst hEq
    simp [State.setSession] at hSess
    cases hSess
    exact hSafe
  · have hOld : st.sessions sid' = some s' := by
      simpa [State.setSession, hEq] using hSess
    exact hInv sid' s' hOld

theorem approvedInv_preserved_setRouteBinding
    (st : State) (hInv : approvedInv st) (route : RouteId) (sid : Option SessionId) :
    approvedInv (State.setRouteBinding st route sid) := by
  intro sid' s hSess
  exact hInv sid' s hSess

theorem approvedInv_preserved_setOutstanding
    (st : State) (hInv : approvedInv st) (cid : ChallengeId) (chal : Option Challenge) :
    approvedInv (State.setOutstanding st cid chal) := by
  intro sid' s hSess
  exact hInv sid' s hSess

theorem approvedInv_preserved_markUsedJti
    (st : State) (hInv : approvedInv st) (jti : TokenId) :
    approvedInv (State.markUsedJti st jti) := by
  intro sid' s hSess
  exact hInv sid' s hSess

theorem approvedInv_preserved_markUsedChallenge
    (st : State) (hInv : approvedInv st) (cid : ChallengeId) :
    approvedInv (State.markUsedChallenge st cid) := by
  intro sid' s hSess
  exact hInv sid' s hSess

theorem identityGate_false_of_or (s : Session)
    (h : s.identityRequired = false \/ s.identityDone = true) :
    (s.identityRequired && (s.identityDone != true)) = false := by
  cases h with
  | inl hReq =>
      simp [hReq]
  | inr hDone =>
      simp [hDone]

inductive IssueError where
  | missingSession
  | notApproved
  | missingPoHP
  | missingIdentity
  | missingChallengeBinding
deriving Repr, DecidableEq

def issueCredential
    (cfg : Config) (st : State) (sid : SessionId) (jti : TokenId) (checkpoint : Checkpoint) :
    Except IssueError Credential :=
  match st.sessions sid with
  | none => .error .missingSession
  | some s =>
    if s.status != .approved then
      .error .notApproved
    else if s.pohpVerified != true then
      .error .missingPoHP
    else if s.identityRequired && (s.identityDone != true) then
      .error .missingIdentity
    else if cfg.challengeRequired s.cap then
      match s.challengeId with
      | none => .error .missingChallengeBinding
      | some cid =>
        .ok {
          jti := jti
          aud := s.aud
          cap := s.cap
          session := sid
          challengeId := some cid
          checkpoint := checkpoint
        }
    else
      .ok {
        jti := jti
        aud := s.aud
        cap := s.cap
        session := sid
        challengeId := none
        checkpoint := checkpoint
      }

theorem issueCredential_success_nonchallenge
    (cfg : Config) (st : State) (sid : SessionId) (s : Session)
    (jti : TokenId) (checkpoint : Checkpoint)
    (hSess : st.sessions sid = some s)
    (hApproved : s.status = .approved)
    (hPoHP : s.pohpVerified = true)
    (hIdentity : s.identityRequired = false \/ s.identityDone = true)
    (hNoChallenge : cfg.challengeRequired s.cap = false) :
    issueCredential cfg st sid jti checkpoint = .ok {
      jti := jti
      aud := s.aud
      cap := s.cap
      session := sid
      challengeId := none
      checkpoint := checkpoint
    } := by
  cases hReq : s.identityRequired <;> cases hDone : s.identityDone <;>
    simp [issueCredential, hSess, hApproved, hPoHP, hNoChallenge, hReq, hDone] at hIdentity ⊢

theorem issueCredential_success_challenge
    (cfg : Config) (st : State) (sid : SessionId) (s : Session)
    (cid : ChallengeId) (jti : TokenId) (checkpoint : Checkpoint)
    (hSess : st.sessions sid = some s)
    (hApproved : s.status = .approved)
    (hPoHP : s.pohpVerified = true)
    (hIdentity : s.identityRequired = false \/ s.identityDone = true)
    (hRequireChallenge : cfg.challengeRequired s.cap = true)
    (hCid : s.challengeId = some cid) :
    issueCredential cfg st sid jti checkpoint = .ok {
      jti := jti
      aud := s.aud
      cap := s.cap
      session := sid
      challengeId := some cid
      checkpoint := checkpoint
    } := by
  cases hReq : s.identityRequired <;> cases hDone : s.identityDone <;>
    simp [issueCredential, hSess, hApproved, hPoHP, hRequireChallenge, hCid, hReq, hDone] at hIdentity ⊢

inductive Action where
  | createSession (sid : SessionId) (route : RouteId) (aud : Audience) (cap : Capability)
      (identityRequired : Bool)
  | markPoHP (sid : SessionId)
  | markIdentity (sid : SessionId)
  | approve (sid : SessionId)
  | deny (sid : SessionId)
  | issueChallenge (sid : SessionId) (cid : ChallengeId)
  | execute (route : RouteId) (cred : Credential)
deriving Repr

inductive Step (cfg : Config) : Action -> State -> State -> Prop where
  | createSession
      (sid : SessionId) (route : RouteId) (aud : Audience) (cap : Capability)
      (identityRequired : Bool)
      (hSidFresh : st.sessions sid = none)
      (hRouteFresh : st.routeBinding route = none) :
      Step cfg
        (.createSession sid route aud cap identityRequired)
        st
        (State.setRouteBinding
          (State.setSession st sid (some {
            aud := aud
            cap := cap
            status := .pending
            pohpVerified := false
            identityRequired := identityRequired
            identityDone := false
            challengeId := none
          }))
          route (some sid))

  | markPoHP
      (sid : SessionId) (s : Session)
      (hSess : st.sessions sid = some s) :
      Step cfg (.markPoHP sid) st
        (State.setSession st sid (some { s with pohpVerified := true }))

  | markIdentity
      (sid : SessionId) (s : Session)
      (hSess : st.sessions sid = some s) :
      Step cfg (.markIdentity sid) st
        (State.setSession st sid (some { s with identityDone := true }))

  | approve
      (sid : SessionId) (s : Session)
      (hSess : st.sessions sid = some s)
      (hPoHP : s.pohpVerified = true)
      (hIdentity : s.identityRequired = false \/ s.identityDone = true) :
      Step cfg (.approve sid) st
        (State.setSession st sid (some { s with status := .approved }))

  | deny
      (sid : SessionId) (s : Session)
      (hSess : st.sessions sid = some s) :
      Step cfg (.deny sid) st
        (State.setSession st sid (some { s with status := .denied }))

  | issueChallenge
      (sid : SessionId) (cid : ChallengeId) (s : Session)
      (hSess : st.sessions sid = some s)
      (hNoSessionChallenge : s.challengeId = none)
      (hCidFresh : st.outstandingChallenge cid = none)
      (hCidUnused : st.usedChallenge cid = false) :
      Step cfg (.issueChallenge sid cid) st
        (State.setOutstanding
          (State.setSession st sid (some { s with challengeId := some cid }))
          cid
          (some { aud := s.aud, cap := s.cap, session := sid }))

  | executeNoChallenge
      (route : RouteId) (cred : Credential) (s : Session)
      (hRoute : st.routeBinding route = some cred.session)
      (hSess : st.sessions cred.session = some s)
      (hApproved : s.status = .approved)
      (hAud : s.aud = cred.aud)
      (hCap : s.cap = cred.cap)
      (hFreshJti : st.usedJti cred.jti = false)
      (hPair : cred.checkpoint.satisfiesB (cfg.requiredCheckpoint cred.cap) = true)
      (hNoChallengePolicy : cfg.challengeRequired cred.cap = false) :
      Step cfg (.execute route cred) st (State.markUsedJti st cred.jti)

  | executeWithChallenge
      (route : RouteId) (cred : Credential) (cid : ChallengeId) (s : Session) (ch : Challenge)
      (hRoute : st.routeBinding route = some cred.session)
      (hSess : st.sessions cred.session = some s)
      (hApproved : s.status = .approved)
      (hAud : s.aud = cred.aud)
      (hCap : s.cap = cred.cap)
      (hFreshJti : st.usedJti cred.jti = false)
      (hPair : cred.checkpoint.satisfiesB (cfg.requiredCheckpoint cred.cap) = true)
      (hChallengePolicy : cfg.challengeRequired cred.cap = true)
      (hSessionCid : s.challengeId = some cid)
      (hCredCid : cred.challengeId = some cid)
      (hFreshCid : st.usedChallenge cid = false)
      (hOutstanding : st.outstandingChallenge cid = some ch)
      (hChAud : ch.aud = cred.aud)
      (hChCap : ch.cap = cred.cap)
      (hChSession : ch.session = cred.session) :
      Step cfg (.execute route cred) st
        (State.setSession
          (State.setOutstanding
            (State.markUsedChallenge (State.markUsedJti st cred.jti) cid)
            cid none)
          cred.session
          (some { s with challengeId := none }))

theorem step_preserves_invariant
    (cfg : Config) (act : Action) (st st' : State)
    (hInv : Invariant st)
    (hStep : Step cfg act st st') :
    Invariant st' := by
  rcases hInv with ⟨hRouteInv, hApprovedInv⟩
  cases hStep with
  | createSession sid route aud cap identityRequired hSidFresh hRouteFresh =>
      let sNew : Session := {
        aud := aud
        cap := cap
        status := .pending
        pohpVerified := false
        identityRequired := identityRequired
        identityDone := false
        challengeId := none
      }
      constructor
      · have hR1 : routeInv (State.setSession st sid (some sNew)) :=
          routeInv_setSession_some st hRouteInv sid sNew
        apply routeInv_setRouteBinding_some (State.setSession st sid (some sNew)) hR1 route sid
        exact Exists.intro sNew (by simp [State.setSession])
      · have hSafe : Session.safeApproved sNew := by
          intro hA
          cases hA
        have hA1 : approvedInv (State.setSession st sid (some sNew)) :=
          approvedInv_setSession_some st hApprovedInv sid sNew hSafe
        exact approvedInv_preserved_setRouteBinding (State.setSession st sid (some sNew)) hA1 route (some sid)

  | markPoHP sid s hSess =>
      constructor
      · exact routeInv_setSession_some st hRouteInv sid { s with pohpVerified := true }
      · apply approvedInv_setSession_some st hApprovedInv sid { s with pohpVerified := true }
        intro hA
        have hOld := hApprovedInv sid s hSess (by simpa using hA)
        exact And.intro rfl hOld.2

  | markIdentity sid s hSess =>
      constructor
      · exact routeInv_setSession_some st hRouteInv sid { s with identityDone := true }
      · apply approvedInv_setSession_some st hApprovedInv sid { s with identityDone := true }
        intro hA
        have hOld := hApprovedInv sid s hSess (by simpa using hA)
        exact And.intro hOld.1 (Or.inr rfl)

  | approve sid s hSess hPoHP hIdentity =>
      constructor
      · exact routeInv_setSession_some st hRouteInv sid { s with status := .approved }
      · apply approvedInv_setSession_some st hApprovedInv sid { s with status := .approved }
        intro _hA
        exact And.intro hPoHP hIdentity

  | deny sid s hSess =>
      constructor
      · exact routeInv_setSession_some st hRouteInv sid { s with status := .denied }
      · apply approvedInv_setSession_some st hApprovedInv sid { s with status := .denied }
        intro hA
        cases hA

  | issueChallenge sid cid s hSess hNoSessionChallenge hCidFresh hCidUnused =>
      constructor
      · have hR1 : routeInv (State.setSession st sid (some { s with challengeId := some cid })) :=
          routeInv_setSession_some st hRouteInv sid { s with challengeId := some cid }
        intro route sid' hBind
        exact hR1 route sid' hBind
      · have hA1 : approvedInv (State.setSession st sid (some { s with challengeId := some cid })) :=
          approvedInv_setSession_some st hApprovedInv sid { s with challengeId := some cid }
            (by
              intro hA
              exact hApprovedInv sid s hSess (by simpa using hA))
        exact approvedInv_preserved_setOutstanding
          (State.setSession st sid (some { s with challengeId := some cid }))
          hA1 cid (some { aud := s.aud, cap := s.cap, session := sid })

  | executeNoChallenge route cred s hRoute hSess hApproved hAud hCap hFreshJti hPair hNoChallengePolicy =>
      constructor
      · intro route' sid' hBind
        exact hRouteInv route' sid' hBind
      · exact approvedInv_preserved_markUsedJti st hApprovedInv cred.jti

  | executeWithChallenge route cred cid s ch hRoute hSess hApproved hAud hCap hFreshJti hPair
      hChallengePolicy hSessionCid hCredCid hFreshCid hOutstanding hChAud hChCap hChSession =>
      constructor
      · have hR0 : routeInv (State.markUsedJti st cred.jti) := by
          intro route' sid' hBind; exact hRouteInv route' sid' hBind
        have hR1 : routeInv (State.markUsedChallenge (State.markUsedJti st cred.jti) cid) := by
          intro route' sid' hBind; exact hR0 route' sid' hBind
        have hR2 : routeInv (State.setOutstanding (State.markUsedChallenge (State.markUsedJti st cred.jti) cid) cid none) := by
          intro route' sid' hBind; exact hR1 route' sid' hBind
        exact routeInv_setSession_some
          (State.setOutstanding (State.markUsedChallenge (State.markUsedJti st cred.jti) cid) cid none)
          hR2 cred.session { s with challengeId := none }
      · have hA0 : approvedInv (State.markUsedJti st cred.jti) :=
          approvedInv_preserved_markUsedJti st hApprovedInv cred.jti
        have hA1 : approvedInv (State.markUsedChallenge (State.markUsedJti st cred.jti) cid) :=
          approvedInv_preserved_markUsedChallenge (State.markUsedJti st cred.jti) hA0 cid
        have hA2 : approvedInv (State.setOutstanding (State.markUsedChallenge (State.markUsedJti st cred.jti) cid) cid none) :=
          approvedInv_preserved_setOutstanding
            (State.markUsedChallenge (State.markUsedJti st cred.jti) cid) hA1 cid none
        apply approvedInv_setSession_some
          (State.setOutstanding (State.markUsedChallenge (State.markUsedJti st cred.jti) cid) cid none)
          hA2 cred.session { s with challengeId := none }
        intro hA
        exact hApprovedInv cred.session s hSess (by simpa using hA)

theorem executeWithChallenge_atomic_consumption
    (st : State) (cred : Credential) (cid : ChallengeId) (s : Session) :
    let st' :=
      State.setSession
        (State.setOutstanding
          (State.markUsedChallenge (State.markUsedJti st cred.jti) cid)
          cid none)
        cred.session
        (some { s with challengeId := none })
    st'.usedJti cred.jti = true /\
    st'.usedChallenge cid = true /\
    st'.outstandingChallenge cid = none /\
    st'.sessions cred.session = some { s with challengeId := none } := by
  simp [State.markUsedJti, State.markUsedChallenge, State.setOutstanding, State.setSession]

end E2E
end HappProof
