//! Profile policy seam - which MLS "external operations" a build is allowed to construct or accept.
//!
//! Sibling seam to [`crate::suite_policy`]: the single surface every call site asks *"is this
//! operation allowed for the profile I'm building/running as?"*, so the answer lives in one place
//! instead of scattered inline checks. Free functions over an explicit enum, not a `dyn Profile`
//! object graph - this crate keeps policy seams small and closed-form (see `suite_policy`'s own
//! header for the same discipline).
//!
//! ## The two operation classes this seam routes, and why they're split
//! RFC 9420 defines two different "external operation" mechanisms, with materially different risk
//! shapes:
//!
//! - **External commits** (`MlsGroup::join_by_external_commit`, driven by a `GroupInfo`'s
//!   `ExternalPub` extension, RFC 9420 §12.4.3.1) let a non-member unilaterally join and rewrite
//!   group state. The External-Operations `TreeKEM` analysis (ETK, eprint 2025/229) shows this
//!   materially changes the standard's security model: an attacker who compromises a party's
//!   long-term secret can, at any time, resync/replace that party's representation in the group.
//!   `Profile::Haven` refuses this **permanently, in every lane** - see [`allows_external_commit`].
//! - **External proposals** (`Sender::External`, validated against a group's
//!   `ExternalSendersExtension`, RFC 9420 §12.1.4.1/§12.1.7) are cryptographically inert on their
//!   own: openmls will not act on one until an existing member explicitly commits it. This is a
//!   materially smaller risk surface. `Profile::Haven` still refuses it in the native chat lane
//!   (which never populates `ExternalSendersExtension` at all - the protection is structural, not
//!   merely a policy choice), but a cross-provider ("mimi") lane MAY, in a future narrow and
//!   explicit-inclusion-only form, accept one class of it - see [`allows_external_proposal`].
//!
//! `Profile::Spec` is the unrestricted profile: a full-fidelity implementation (e.g. a public
//! reference daemon) that supports what RFC 9420 defines, for interop-testing and
//! standards-conformance purposes. It is never the profile Haven's own product builds with.
//!
//! This seam is **orthogonal to, and composes after, the ciphersuite accept-gate**
//! (`suite_policy::gate_inbound_mls_suite`): an inbound object is suite-gated first
//! (unconditional, every object), then profile-gated for whether its *operation type* is allowed
//! at all. Neither seam supersedes the other.
//!
//! Today (this seam's first landing) nothing in this crate constructs or accepts either mechanism -
//! `Profile::Haven`'s answers describe a posture already true by the absence of call sites, not a
//! new restriction. The seam exists so that posture is a named, citable, testable fact instead of
//! an emergent one, and so a future narrow mimi-lane acceptance path (external proposals only, see
//! above) has a designed home to land in rather than a scattered ad hoc check.

/// Which posture a build/consumer follows for MLS external operations.
///
/// `Haven` is Haven's own product build, in both the native chat lane and the mimi
/// (cross-provider) lane. `Spec` is an unrestricted, full-fidelity posture - e.g. a public
/// reference implementation exercising what RFC 9420 actually defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Full RFC 9420 fidelity - external commits and external proposals both permitted.
    Spec,
    /// Haven's product posture - external commits permanently refused in both lanes; external
    /// proposals refused in the native lane, narrowly designed (not yet implemented) in the mimi
    /// lane.
    Haven,
}

/// Which lane a call site is operating in, for the decisions where the two lanes diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Haven-to-Haven chat. Never carries an `ExternalSendersExtension`.
    Native,
    /// Cross-provider (MIMI) federation. May, under a future narrow allowlist, carry one.
    Mimi,
}

/// The result of asking whether a profile+lane may accept an external proposal, and under what
/// constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalProposalPolicy {
    /// No external proposal of any kind is ever accepted.
    Denied,
    /// A narrow allowlist MAY be accepted: pre-configured single sender, `Remove`-type only,
    /// explicit-inclusion-only (never relying on openmls's default sweep-pending-into-next-commit
    /// behavior). **Implemented, not merely designed** - see
    /// [`crate::mimi::mimi_accept_external_remove_proposal`] below for the enforcing function and
    /// its negative tests; not yet wired to any live caller.
    /// A future landing must not widen past this without a new, separately security-reviewed
    /// decision.
    AllowlistedRemoveOnly,
    /// Full RFC 9420 fidelity - any external proposal type openmls exposes may be constructed or
    /// accepted. Only ever returned for [`Profile::Spec`].
    FullyPermitted,
}

/// May this profile ever construct or accept an external **commit**
/// (`join_by_external_commit` / a `GroupInfo`'s `ExternalPub` used to enable a join)?
///
/// Always `false` for [`Profile::Haven`], in both lanes, permanently - this is the ETK surface
/// closure described in the module doc. There is no lane parameter because this answer does not
/// vary by lane: the native chat lane needs no external commit (members join via Welcome only),
/// and the mimi lane's cross-provider join uses the add-driven §5.2 KeyPackage+Welcome flow
/// instead of the §5.6 GroupInfo-join MIMI also defines.
#[must_use]
pub const fn allows_external_commit(profile: Profile) -> bool {
    matches!(profile, Profile::Spec)
}

/// May this profile accept an external **proposal** (`Sender::External`, validated against a
/// group's pre-configured `ExternalSendersExtension`), and under what constraint?
///
/// Native lane: always [`ExternalProposalPolicy::Denied`] for [`Profile::Haven`] - the native lane
/// never populates `ExternalSendersExtension` at all, so this is a structural guarantee, not just
/// a policy one; openmls itself refuses any `Sender::External` proposal when the extension is
/// absent. Mimi lane: [`Profile::Haven`] returns [`ExternalProposalPolicy::AllowlistedRemoveOnly`] -
/// the narrowest opening with a named use case (hub-side moderation/retraction) - and this
/// policy is **implemented**, not merely designed: [`crate::mimi::mimi_accept_external_remove_proposal`]
/// is the one function every acceptance decision goes through. It commits a pending external
/// proposal only if the sender is the group's one allowlisted entry AND the proposal's type is
/// `Remove`, using explicit single-proposal inclusion rather than openmls's default
/// sweep-all-pending-into-commit behavior - so no other pending proposal rides along uninvited.
/// The matching group-creation path that populates `ExternalSendersExtension` with exactly the
/// hub's one credential is [`crate::mimi::mimi_create_group_with_external_senders`]. Both are
/// negative-tested (a non-allowlisted sender, and a non-`Remove` proposal type, are each proven
/// refused). **Not yet wired to a live caller**: the group-creation entry point in production
/// use today does not yet populate the extension or invoke the acceptance function - supplying
/// a real hub credential and wiring the call is separate, later work.
#[must_use]
pub const fn allows_external_proposal(profile: Profile, lane: Lane) -> ExternalProposalPolicy {
    match (profile, lane) {
        (Profile::Spec, _) => ExternalProposalPolicy::FullyPermitted,
        (Profile::Haven, Lane::Native) => ExternalProposalPolicy::Denied,
        (Profile::Haven, Lane::Mimi) => ExternalProposalPolicy::AllowlistedRemoveOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- external commit: Haven refuses always, both lanes conceptually (no lane param exists
    //     because the answer never varies) ---
    #[test]
    fn haven_never_allows_external_commit() {
        assert!(!allows_external_commit(Profile::Haven));
    }

    #[test]
    fn spec_allows_external_commit() {
        assert!(allows_external_commit(Profile::Spec));
    }

    // --- external proposal: native lane is a hard denial for Haven ---
    #[test]
    fn haven_native_lane_denies_external_proposal() {
        assert_eq!(
            allows_external_proposal(Profile::Haven, Lane::Native),
            ExternalProposalPolicy::Denied
        );
    }

    // --- external proposal: mimi lane gets the narrow designed allowlist, never full fidelity ---
    #[test]
    fn haven_mimi_lane_gets_remove_only_allowlist() {
        assert_eq!(
            allows_external_proposal(Profile::Haven, Lane::Mimi),
            ExternalProposalPolicy::AllowlistedRemoveOnly
        );
    }

    // --- Spec is unrestricted in both lanes ---
    #[test]
    fn spec_is_fully_permitted_in_both_lanes() {
        assert_eq!(
            allows_external_proposal(Profile::Spec, Lane::Native),
            ExternalProposalPolicy::FullyPermitted
        );
        assert_eq!(
            allows_external_proposal(Profile::Spec, Lane::Mimi),
            ExternalProposalPolicy::FullyPermitted
        );
    }

    // --- regression pin: Haven's mimi-lane answer must never silently widen past Remove-only
    //     without a deliberate code change to this match arm (and the security review that
    //     implies). ---
    #[test]
    fn haven_mimi_lane_is_never_fully_permitted() {
        assert_ne!(
            allows_external_proposal(Profile::Haven, Lane::Mimi),
            ExternalProposalPolicy::FullyPermitted
        );
    }
}
