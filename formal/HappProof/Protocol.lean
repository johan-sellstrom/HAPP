namespace HappProof

abbrev Audience := String
abbrev Capability := String
abbrev TokenId := String
abbrev ChallengeId := String
abbrev SessionId := Nat
abbrev RouteId := String

inductive Checkpoint where
  | none
  | pohp
  | pohpAndIdentity
deriving Repr, DecidableEq

def Checkpoint.satisfiesB : Checkpoint → Checkpoint → Bool
  | _, .none => true
  | .pohpAndIdentity, .pohp => true
  | got, need => got == need

def Checkpoint.satisfies (got need : Checkpoint) : Prop :=
  got.satisfiesB need = true

structure Session where
  aud : Audience
  cap : Capability
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
  requiredCheckpoint : Capability → Checkpoint
  challengeRequired : Capability → Bool

structure State where
  sessions : SessionId → Option Session
  routeBinding : RouteId → Option SessionId
  outstandingChallenge : ChallengeId → Option Challenge
  usedJti : TokenId → Bool
  usedChallenge : ChallengeId → Bool

namespace State

def empty : State where
  sessions := fun _ => none
  routeBinding := fun _ => none
  outstandingChallenge := fun _ => none
  usedJti := fun _ => false
  usedChallenge := fun _ => false

def upsertSession (st : State) (sid : SessionId) (sess : Session) : State :=
  { st with
    sessions := fun x => if x = sid then some sess else st.sessions x }

def bindRoute (st : State) (route : RouteId) (sid : SessionId) : State :=
  { st with
    routeBinding := fun x => if x = route then some sid else st.routeBinding x }

def issueChallenge (st : State) (cid : ChallengeId) (chal : Challenge) : State :=
  { st with
    outstandingChallenge := fun x => if x = cid then some chal else st.outstandingChallenge x }

def markJti (st : State) (jti : TokenId) : State :=
  { st with usedJti := fun x => st.usedJti x || (x == jti) }

def markChallenge (st : State) (cid : ChallengeId) : State :=
  { st with
    usedChallenge := fun x => st.usedChallenge x || (x == cid)
    outstandingChallenge := fun x => if x = cid then none else st.outstandingChallenge x }

end State

inductive VerifyError where
  | routeIsolationViolation
  | missingSession
  | audienceMismatch
  | capabilityMismatch
  | replayJti
  | checkpointTooWeak
  | missingChallenge
  | challengeAlreadyUsed
  | unknownChallenge
  | challengeContextMismatch
deriving Repr, DecidableEq

def verifyAndConsume (cfg : Config) (st : State) (route : RouteId) (cred : Credential) :
    Except VerifyError State :=
  if st.routeBinding route != some cred.session then
    .error .routeIsolationViolation
  else
    match st.sessions cred.session with
    | none => .error .missingSession
    | some sess =>
      if sess.aud != cred.aud then
        .error .audienceMismatch
      else if sess.cap != cred.cap then
        .error .capabilityMismatch
      else if st.usedJti cred.jti then
        .error .replayJti
      else if !(cred.checkpoint.satisfiesB (cfg.requiredCheckpoint cred.cap)) then
        .error .checkpointTooWeak
      else if cfg.challengeRequired cred.cap then
        match cred.challengeId with
        | none => .error .missingChallenge
        | some cid =>
          if st.usedChallenge cid then
            .error .challengeAlreadyUsed
          else
            match st.outstandingChallenge cid with
            | none => .error .unknownChallenge
            | some chal =>
              if chal.aud != cred.aud || chal.cap != cred.cap || chal.session != cred.session then
                .error .challengeContextMismatch
              else
                .ok ((st.markJti cred.jti).markChallenge cid)
      else
        .ok (st.markJti cred.jti)

end HappProof
